package client

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/hm-edu/harica/models"
	"go.mozilla.org/pkcs7"
)

func scanDERCertificates(data []byte) []*x509.Certificate {
	// Heuristic extractor: scan for DER SEQUENCE headers that decode as X.509 certificates.
	// This is intentionally tolerant and is used as a fallback for PKCS#7 bundles that
	// may use BER/indefinite-length encodings that Go PKCS#7 parsers reject.
	certs := make([]*x509.Certificate, 0, 4)
	seen := make(map[string]struct{})

	for i := 0; i+4 < len(data); i++ {
		if data[i] != 0x30 { // SEQUENCE
			continue
		}
		// Parse DER length
		b1 := data[i+1]
		var headerLen int
		var contentLen int
		switch {
		case b1 < 0x80:
			headerLen = 2
			contentLen = int(b1)
		case b1 == 0x80:
			// Indefinite length (BER) - skip; certificates themselves should be DER.
			continue
		default:
			n := int(b1 & 0x7f)
			if n < 1 || n > 4 {
				continue
			}
			if i+2+n > len(data) {
				continue
			}
			headerLen = 2 + n
			l := 0
			for j := 0; j < n; j++ {
				l = (l << 8) | int(data[i+2+j])
			}
			contentLen = l
		}
		if contentLen <= 0 {
			continue
		}
		total := headerLen + contentLen
		if i+total > len(data) {
			continue
		}

		candidate := data[i : i+total]
		cert, err := x509.ParseCertificate(candidate)
		if err != nil {
			continue
		}
		key := string(cert.Raw)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		certs = append(certs, cert)
		i += total - 1
	}

	return certs
}

const (
	CMv1AdminEnterprisesPath = "/cm/v1/admin/enterprises"
	CMv1BulkCreateSmimePath  = "/cm/v1/bulk/create/smime"

	headerAPIKey = "X-API-Key"
)

type CMv1Enterprise struct {
	OrganizationID string
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
			} else {
				continue
			}
		}

		result = append(result, CMv1Enterprise{OrganizationID: orgID})
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

// ExtractFirstCertificatePEMFromZip tries to locate the first leaf certificate in the ZIP
// response and returns it as PEM.
//
// The HARICA bulk S/MIME endpoint returns a ZIP on success. For single-user requests
// we use this helper to keep stdout output compatible with legacy flows.
func ExtractFirstCertificatePEMFromZip(zipBytes []byte) (string, error) {
	if len(zipBytes) == 0 {
		return "", errors.New("zip is empty")
	}

	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return "", err
	}

	var lastX509Err error
	var lastPKCS7Err error

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(rc, 25<<20))
		_ = rc.Close()
		if readErr != nil {
			continue
		}

		text := strings.TrimSpace(string(data))
		if strings.Contains(text, "-----BEGIN CERTIFICATE-----") {
			if !strings.HasSuffix(text, "\n") {
				text += "\n"
			}
			return text, nil
		}

		if cert, err := x509.ParseCertificate(data); err == nil {
			block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
			return string(pem.EncodeToMemory(block)), nil
		} else {
			lastX509Err = err
		}

		// HARICA bulk S/MIME ZIPs may contain a PKCS#7 (.p7b) bundle.
		// Try to parse it and return the first non-CA certificate.
		if p7, err := pkcs7.Parse(data); err == nil {
			certs := p7.Certificates
			if len(certs) == 0 {
				continue
			}
			chosen := certs[0]
			for _, c := range certs {
				if c != nil && !c.IsCA {
					chosen = c
					break
				}
			}
			if chosen != nil {
				block := &pem.Block{Type: "CERTIFICATE", Bytes: chosen.Raw}
				return string(pem.EncodeToMemory(block)), nil
			}
		} else {
			lastPKCS7Err = err

			// Fallback: scan for embedded DER certificates within the PKCS#7 blob.
			if scanned := scanDERCertificates(data); len(scanned) > 0 {
				chosen := scanned[0]
				for _, c := range scanned {
					if c != nil && !c.IsCA {
						chosen = c
						break
					}
				}
				if chosen != nil {
					block := &pem.Block{Type: "CERTIFICATE", Bytes: chosen.Raw}
					return string(pem.EncodeToMemory(block)), nil
				}
			}
		}
	}

	if lastPKCS7Err != nil {
		return "", fmt.Errorf("no certificate found in zip (last pkcs7 parse error: %w)", lastPKCS7Err)
	}
	if lastX509Err != nil {
		return "", fmt.Errorf("no certificate found in zip (last x509 parse error: %w)", lastX509Err)
	}
	return "", errors.New("no certificate found in zip")
}
