package client

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/hm-edu/harica/models"
)

const (
	CMv1AdminEnterprisesPath = "/cm/v1/admin/enterprises"
	CMv1BulkCreateSmimePath  = "/cm/v1/bulk/create/smime"

	headerAPIKey = "X-API-Key"
)

type CMv1Enterprise struct {
	OrganizationID string
	EnterpriseID   string
	Name           string
}

// ListCMv1Enterprises returns enterprise/org information visible to the API key.
// The HARICA docs describe this endpoint as returning JSON.
func ListCMv1Enterprises(baseURL, apiKey string, debug bool) ([]CMv1Enterprise, []byte, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, nil, errors.New("api key is required")
	}

	r := resty.New()
	resp, err := r.R().
		SetDebug(debug).
		SetHeader(headerAPIKey, apiKey).
		Get(baseURL + CMv1AdminEnterprisesPath)
	if err != nil {
		return nil, nil, err
	}
	if resp == nil {
		return nil, nil, errors.New("enterprises response is nil")
	}
	body := resp.Body()
	if resp.IsError() {
		return nil, body, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: body}
	}
	if !strings.Contains(strings.ToLower(resp.Header().Get("Content-Type")), ApplicationJson) {
		return nil, body, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type"), Body: body}
	}

	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, body, fmt.Errorf("failed to parse enterprises response json: %w", err)
	}
	items, ok := decoded.([]any)
	if !ok {
		return nil, body, errors.New("unexpected enterprises response: expected json array")
	}

	result := make([]CMv1Enterprise, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		var orgID string
		if v, ok := m["organizationId"]; ok {
			if s, ok := v.(string); ok {
				orgID = strings.TrimSpace(s)
			}
		}
		var enterpriseID string
		if v, ok := m["id"]; ok {
			if s, ok := v.(string); ok {
				enterpriseID = strings.TrimSpace(s)
			}
		}
		var name string
		if v, ok := m["name"]; ok {
			if s, ok := v.(string); ok {
				name = strings.TrimSpace(s)
			}
		}
		if name == "" {
			if v, ok := m["enterpriseName"]; ok {
				if s, ok := v.(string); ok {
					name = strings.TrimSpace(s)
				}
			}
		}

		if orgID == "" && enterpriseID == "" && name == "" {
			continue
		}
		result = append(result, CMv1Enterprise{OrganizationID: orgID, EnterpriseID: enterpriseID, Name: name})
	}

	return result, body, nil
}

// CreateCMv1SmimeBulkZip issues S/MIME certificates using the API-key bulk endpoint and returns the raw ZIP response bytes.
// On failure, it returns an error that includes the raw response body where possible.
func CreateCMv1SmimeBulkZip(baseURL, apiKey, organizationID string, request models.SmimeBulkRequest, debug bool) ([]byte, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("api key is required")
	}
	if strings.TrimSpace(organizationID) == "" {
		return nil, errors.New("organization id is required")
	}

	b := new(bytes.Buffer)
	w := csv.NewWriter(b)
	if err := w.Write([]string{
		"FriendlyName",
		"Email",
		"Email2",
		"Email3",
		"GivenName",
		"Surname",
		"PickupPassword",
		"CertType",
		"CSR",
	}); err != nil {
		return nil, err
	}

	if request.CertType != "email_only" && request.CertType != "natural_legal_lcp" {
		return nil, errors.New("invalid certificate type")
	}

	if err := w.Write([]string{
		request.FriendlyName,
		request.Email,
		request.Email2,
		request.Email3,
		request.GivenName,
		request.Surname,
		request.PickupPassword,
		request.CertType,
		request.CSR,
	}); err != nil {
		return nil, err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}

	r := resty.New()
	resp, err := r.R().
		SetDebug(debug).
		SetHeader(headerAPIKey, apiKey).
		SetMultipartFormData(map[string]string{
			"Value": organizationID,
		}).
		SetMultipartField("File", "bulk.csv", "text/csv", bytes.NewReader(b.Bytes())).
		Post(baseURL + CMv1BulkCreateSmimePath)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("bulk smime response is nil")
	}
	body := resp.Body()
	if resp.IsError() {
		return nil, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: body}
	}
	// Docs state: ZIP on success, JSON on error.
	if strings.Contains(strings.ToLower(resp.Header().Get("Content-Type")), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type"), Body: body}
	}
	return body, nil
}
