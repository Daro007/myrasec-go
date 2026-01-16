package myrasec

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	RecordTypeA     = "A"
	RecordTypeAAAA  = "AAAA"
	RecordTypeCNAME = "CNAME"
)

func (rec DNSRecord) CanBeProtected() bool {
	return rec.RecordType == RecordTypeA ||
		rec.RecordType == RecordTypeAAAA ||
		rec.RecordType == RecordTypeCNAME
}

func (api *API) GetDNSRecord(domainName string, recordID int) (*DNSRecord, error) {
	if api == nil {
		return nil, fmt.Errorf("API client is nil")
	}

	url := fmt.Sprintf("%s/domains/%s/dns/%d", api.baseURL, domainName, recordID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+api.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := api.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var record DNSRecord
	if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &record, nil
}
