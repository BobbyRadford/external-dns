/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"

	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/source"

	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/api/cis/cisv1"
	"github.com/IBM-Cloud/bluemix-go/crn"
	"github.com/IBM-Cloud/bluemix-go/session"
)

const (
	// cisCreate is a ChangeAction enum value
	cisCreate = "CREATE"
	// cisDelete is a ChangeAction enum value
	cisDelete = "DELETE"
	// cisUpdate is a ChangeAction enum value
	cisUpdate = "UPDATE"
	// defaultCISRecordTTL 1 = automatic
	defaultCISRecordTTL = 1
)

var cisTypeNotSupported = map[string]bool{
	"LOC": true,
	"MX":  true,
	"NS":  true,
	"SPF": true,
	"TXT": true,
	"SRV": true,
}

// ibmDNS is the subset of the IBM CIS API that we actually use. Add methods as required. Signatures must match exactly.
type ibmDNS interface {
	ListZones(cisID string) ([]cisv1.Zone, error)
	DNSRecords(cisID string, zoneID string) ([]cisv1.DnsRecord, error)
	CreateDNSRecord(cisID string, zoneID string, record cisv1.DnsBody) (*cisv1.DnsRecord, error)
	DeleteDNSRecord(cisID string, zoneID string, recordID string) error
	ListGlbs(cisID string, zoneID string, glbBody cisv1.GlbBody) ([]cisv1.Glb, error)
	CreateGLB(cisID string, zoneID string, glbBody cisv1.GlbBody) (*cisv1.Glb, error)
}

type ibmZoneService struct {
	service cisv1.CisServiceAPI
}

func (z *ibmZoneService) ListZones(cisID string) ([]cisv1.Zone, error) {
	return z.service.Zones().ListZones(cisID)
}

func (z *ibmZoneService) DNSRecords(cisID string, zoneID string) ([]cisv1.DnsRecord, error) {
	return z.service.Dns().ListDns(cisID, zoneID)
}

func (z *ibmZoneService) CreateDNSRecord(cisID string, zoneID string, record cisv1.DnsBody) (*cisv1.DnsRecord, error) {
	return z.service.Dns().CreateDns(cisID, zoneID, record)
}

func (z *ibmZoneService) DeleteDNSRecord(cisID string, zoneID string, recordID string) error {
	return z.service.Dns().DeleteDns(cisID, zoneID, recordID)
}

func (z *ibmZoneService) CreateGLB(cisID string, zoneID string, glbBody cisv1.GlbBody) (*cisv1.Glb, error) {
	return z.service.Glbs().CreateGlb(cisID, zoneID, glbBody)
}

func (z *ibmZoneService) ListGlbs(cisID string, zoneID string, glbBody cisv1.GlbBody) ([]cisv1.Glb, error) {
	return z.service.Glbs().ListGlbs(cisID, zoneID)
}

// IBMProvider is an implementation of Provider for IBM Cloud Internet Services DNS.
type IBMProvider struct {
	Client           ibmDNS
	CRN              string
	domainFilter     DomainFilter
	zoneIDFilter     ZoneIDFilter
	proxiedByDefault bool
	DryRun           bool
}

type ibmChange struct {
	Action            string
	ResourceRecordSet []cisv1.DnsRecord
}

// IBMProviderConfig ...
type IBMProviderConfig struct {
	CRN              string
	DomainFilter     DomainFilter
	ZoneIDFilter     ZoneIDFilter
	ProxiedByDefault bool
	DryRun           bool
}

// NewIBMProvider ...
func NewIBMProvider(config IBMProviderConfig) (*IBMProvider, error) {
	// initialize via chosen auth method and returns new API object
	var (
		client cisv1.CisServiceAPI
		err    error
	)

	_, err = crn.Parse(config.CRN)

	// Authenticate with IBM Cloud.
	apikey := os.Getenv("IBM_CIS_API_KEY")
	ibmCloudSession, err := session.New(&bluemix.Config{
		BluemixAPIKey: apikey,
		HTTPClient:    &http.Client{},
	})

	if err != nil {
		return nil, err
	}

	client, err = cisv1.New(ibmCloudSession)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IBM CIS provider: %v", err)
	}

	provider := &IBMProvider{
		Client: &ibmZoneService{
			service: client,
		},
		CRN:              config.CRN,
		domainFilter:     config.DomainFilter,
		zoneIDFilter:     config.ZoneIDFilter,
		proxiedByDefault: config.ProxiedByDefault,
		DryRun:           config.DryRun,
	}
	return provider, nil
}

// Zones returns the list of hosted zones.
func (p *IBMProvider) Zones(ctx context.Context) ([]cisv1.Zone, error) {
	result := []cisv1.Zone{}

	zonesResponse, err := p.Client.ListZones(p.CRN)
	if err != nil {
		return nil, err
	}

	for _, zone := range zonesResponse {
		if !p.domainFilter.Match(zone.Name) {
			continue
		}

		if !p.zoneIDFilter.Match(zone.Id) {
			continue
		}
		result = append(result, zone)
	}
	return result, nil
}

// Records returns the list of records.
func (p *IBMProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	zones, err := p.Zones(ctx)
	if err != nil {
		return nil, err
	}

	endpoints := []*endpoint.Endpoint{}
	for _, zone := range zones {
		records, err := p.Client.DNSRecords(p.CRN, zone.Id)
		if err != nil {
			return nil, err
		}

		endpoints = append(endpoints, groupByNameAndTypeIBM(records)...)
	}

	return endpoints, nil
}

// ApplyChanges applies a given set of changes in a given zone.
func (p *IBMProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	proxiedByDefault := p.proxiedByDefault

	combinedChanges := make([]*ibmChange, 0, len(changes.Create)+len(changes.UpdateNew)+len(changes.Delete))

	combinedChanges = append(combinedChanges, newIBMChanges(cloudFlareCreate, changes.Create, proxiedByDefault)...)
	combinedChanges = append(combinedChanges, newIBMChanges(cloudFlareUpdate, changes.UpdateNew, proxiedByDefault)...)
	combinedChanges = append(combinedChanges, newIBMChanges(cloudFlareDelete, changes.Delete, proxiedByDefault)...)

	return p.submitChanges(ctx, combinedChanges)
}

// submitChanges takes a zone and a collection of Changes and sends them as a single transaction.
func (p *IBMProvider) submitChanges(ctx context.Context, changes []*ibmChange) error {
	// return early if there is nothing to change
	if len(changes) == 0 {
		return nil
	}

	cfg := ctx.Value(string("config"))
	if cfg != nil {
		log.Debug("Found config! bobby remove this")
	}

	zones, err := p.Zones(ctx)
	if err != nil {
		return err
	}
	// separate into per-zone change sets to be passed to the API.
	changesByZone := p.changesByZone(zones, changes)

	for zoneID, changes := range changesByZone {
		records, err := p.Client.DNSRecords(p.CRN, zoneID)
		if err != nil {
			return fmt.Errorf("could not fetch records from zone, %v", err)
		}
		for _, change := range changes {
			logFields := log.Fields{
				"record":  change.ResourceRecordSet[0].Name,
				"type":    change.ResourceRecordSet[0].DnsType,
				"ttl":     change.ResourceRecordSet[0].Ttl,
				"targets": len(change.ResourceRecordSet),
				"action":  change.Action,
				"zone":    zoneID,
			}

			log.WithFields(logFields).Info("Changing record.")

			if p.DryRun {
				continue
			}

			recordIDs := p.getRecordIDs(records, change.ResourceRecordSet[0])

			// to simplify bookkeeping for multiple records, an update is executed as delete+create
			if change.Action == cisDelete || change.Action == cisUpdate {
				for _, recordID := range recordIDs {
					err := p.Client.DeleteDNSRecord(p.CRN, zoneID, recordID)
					if err != nil {
						log.WithFields(logFields).Errorf("failed to delete record: %v", err)
					}
				}
			}

			if change.Action == cisCreate || change.Action == cisUpdate {
				for _, record := range change.ResourceRecordSet {
					dnsBody := cisv1.DnsBody{
						Name:     record.Name,
						DnsType:  record.DnsType,
						Content:  record.Content,
						Priority: record.Priority,
						Data:     record.Data,
					}
					_, err := p.Client.CreateDNSRecord(p.CRN, zoneID, dnsBody)
					if err != nil {
						log.WithFields(logFields).Errorf("failed to create record: %v", err)
					}
				}
			}
		}
	}
	return nil
}

// changesByZone separates a multi-zone change into a single change per zone.
func (p *IBMProvider) changesByZone(zones []cisv1.Zone, changeSet []*ibmChange) map[string][]*ibmChange {
	changes := make(map[string][]*ibmChange)
	zoneNameIDMapper := zoneIDName{}

	for _, z := range zones {
		zoneNameIDMapper.Add(z.Id, z.Name)
		changes[z.Id] = []*ibmChange{}
	}

	for _, c := range changeSet {
		zoneID, _ := zoneNameIDMapper.FindZone(c.ResourceRecordSet[0].Name)
		if zoneID == "" {
			log.Debugf("Skipping record %s because no hosted zone matching record DNS Name was detected", c.ResourceRecordSet[0].Name)
			continue
		}
		changes[zoneID] = append(changes[zoneID], c)
	}

	return changes
}

func (p *IBMProvider) getRecordIDs(records []cisv1.DnsRecord, record cisv1.DnsRecord) []string {
	recordIDs := make([]string, 0)
	for _, zoneRecord := range records {
		if zoneRecord.Name == record.Name && zoneRecord.DnsType == record.DnsType {
			recordIDs = append(recordIDs, zoneRecord.Id)
		}
	}
	sort.Strings(recordIDs)
	return recordIDs
}

// newIBMChanges returns a collection of Changes based on the given records and action.
func newIBMChanges(action string, endpoints []*endpoint.Endpoint, proxiedByDefault bool) []*ibmChange {
	changes := make([]*ibmChange, 0, len(endpoints))

	for _, endpoint := range endpoints {
		changes = append(changes, newIBMChange(action, endpoint, proxiedByDefault))
	}

	return changes
}

func newIBMChange(action string, endpoint *endpoint.Endpoint, proxiedByDefault bool) *ibmChange {
	ttl := defaultCISRecordTTL
	proxied := shouldBeProxied(endpoint, proxiedByDefault)

	if endpoint.RecordTTL.IsConfigured() {
		ttl = int(endpoint.RecordTTL)
	}

	resourceRecordSet := make([]cisv1.DnsRecord, len(endpoint.Targets))

	for i := range endpoint.Targets {
		resourceRecordSet[i] = cisv1.DnsRecord{
			Name:    endpoint.DNSName,
			Ttl:     ttl,
			Proxied: proxied,
			DnsType: endpoint.RecordType,
			Content: endpoint.Targets[i],
		}
	}

	return &ibmChange{
		Action:            action,
		ResourceRecordSet: resourceRecordSet,
	}
}

func groupByNameAndTypeIBM(records []cisv1.DnsRecord) []*endpoint.Endpoint {
	endpoints := []*endpoint.Endpoint{}

	// group supported records by name and type
	groups := map[string][]cisv1.DnsRecord{}

	for _, r := range records {
		if !supportedRecordType(r.DnsType) {
			continue
		}

		groupBy := r.Name + r.DnsType
		if _, ok := groups[groupBy]; !ok {
			groups[groupBy] = []cisv1.DnsRecord{}
		}

		groups[groupBy] = append(groups[groupBy], r)
	}

	// create single endpoint with all the targets for each name/type
	for _, records := range groups {
		targets := make([]string, len(records))
		for i, record := range records {
			targets[i] = record.Content
		}
		endpoints = append(endpoints,
			endpoint.NewEndpointWithTTL(
				records[0].Name,
				records[0].DnsType,
				endpoint.TTL(records[0].Ttl),
				targets...).
				WithProviderSpecific(source.IBMCISProxiedKey, strconv.FormatBool(records[0].Proxied)))
	}

	return endpoints
}
