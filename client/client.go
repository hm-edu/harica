package client

import (
	"bytes"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hm-edu/harica/models"
	"github.com/pquerna/otp/totp"
)

const (
	BaseURLProduction = "https://cm.harica.gr"
	BaseURLStaging    = "https://cm-stg.harica.gr"
	BaseURLDevel      = "https://cm-dev.harica.gr"

	LoginPath     = "/api/User/Login"
	LoginPathTotp = "/api/User/Login2FA"

	CreatePrevalidaitonPath  = "/api/OrganizationAdmin/CreatePrevalidatedValidation"
	GetOrganizationsPath     = "/api/OrganizationAdmin/GetOrganizations"
	GetOrganizationsBulkPath = "/api/OrganizationAdmin/GetOrganizationsBulk"

	CreateBulkCertificatesSMIMEPath  = "/api/OrganizationAdmin/CreateBulkCertificatesSMIME"
	GetBulkCertificateEntriesPath    = "/api/OrganizationAdmin/GetBulkCertificateEntries"
	GetBulkCertificatesOfAnEntryPath = "/api/OrganizationAdmin/GetBulkCertificatesOfAnEntry"
	RevokeBulkCertificatePath        = "/api/OrganizationAdmin/RevokeBulkCertificate"

	UpdateReviewsPath             = "/api/OrganizationValidatorSSL/UpdateReviews"
	GetReviewableTransactionsPath = "/api/OrganizationValidatorSSL/GetSSLReviewableTransactions"
	RevokeCertificatePath         = "/api/OrganizationValidatorSSL/RevokeCertificate"

	GetCertificatePath    = "/api/Certificate/GetCertificate"
	RevocationReasonsPath = "/api/Certificate/GetRevocationReasons"

	DomainValidationsPath         = "/api/ServerCertificate/GetDomainValidations"
	CheckMatchingOrganizationPath = "/api/ServerCertificate/CheckMachingOrganization"
	CheckDomainNamesPath          = "/api/ServerCertificate/CheckDomainNames"
	RequestServerCertificatePath  = "/api/ServerCertificate/RequestServerCertificate"
	GetMyTransactionsPath         = "/api/ServerCertificate/GetMyTransactions"

	ApplicationJson = "application/json"
	DnsValidation   = "3.2.2.4.7"
)

type Client struct {
	baseURL               string
	client                *resty.Client
	currentToken          string
	debug                 bool
	user                  string
	password              string
	totp                  string
	retryEnabled          bool
	retry                 int
	requestTimeoutEnabled bool
	requestTimeout        time.Duration
	refreshInterval       time.Duration
	loginLock             sync.RWMutex
	bulkLock              sync.RWMutex
}

type Domain struct {
	Domain string `json:"domain"`
}

type Option func(*Client)

type UnexpectedResponseContentTypeError struct {
	ContentType string
	Body        []byte
}

func (e *UnexpectedResponseContentTypeError) Error() string {
	return fmt.Sprintf("unexpected response content type: %s (find request body in this errors `body` field)", e.ContentType)
}

type UnexpectedResponseCodeError struct {
	Code int
	Body []byte
}

func (e *UnexpectedResponseCodeError) Error() string {
	return fmt.Sprintf("unexpected response status code %d: %s", e.Code, e.Body)
}

func NewClient(user, password, totpSeed string, options ...Option) (*Client, error) {
	c := Client{
		baseURL: BaseURLProduction, // default to production environment
	}
	for _, option := range options {
		option(&c)
	}
	err := c.prepareClient(user, password, totpSeed, false)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func WithProductionEnvironment() Option {
	return func(c *Client) {
		c.baseURL = BaseURLProduction
	}
}

func WithStagingEnvironment() Option {
	return func(c *Client) {
		c.baseURL = BaseURLStaging
	}
}

func WithDevelEnvironment() Option {
	return func(c *Client) {
		c.baseURL = BaseURLDevel
	}
}

func WithDebug(debug bool) Option {
	return func(c *Client) {
		c.debug = debug
	}
}

// WithEnvironment returns the appropriate environment option based on the environment string
func WithEnvironment(env string) Option {
	switch env {
	case "staging":
		return WithStagingEnvironment()
	case "devel":
		return WithDevelEnvironment()
	default:
		return WithProductionEnvironment()
	}
}

func WithRefreshInterval(interval time.Duration) Option {
	return func(c *Client) {
		c.refreshInterval = interval
	}
}

func WithRetry(retry int) Option {
	return func(c *Client) {
		c.retryEnabled = true
		c.retry = retry
	}
}

func WithRequestTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.requestTimeoutEnabled = true
		c.requestTimeout = timeout
	}
}

func ParseCSR(csr []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csr)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("failed to decode PEM block containing CSR")
	}
	csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %v", err)
	}

	if err := csrParsed.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature is invalid: %v", err)
	}

	return csrParsed, nil
}

func (c *Client) SessionRefresh(force bool) error {
	return c.prepareClient(c.user, c.password, c.totp, force)
}

func (c *Client) prepareClient(user, password, totpSeed string, force bool) error {
	c.loginLock.Lock()
	defer c.loginLock.Unlock()
	renew := false
	slog.Info("Preparing client")
	if c.currentToken != "" {
		slog.Info("Token exists, checking expiration")
		// Check JWT
		token, _, err := jwt.NewParser().ParseUnverified(c.currentToken, jwt.MapClaims{})
		if err != nil {
			return err
		}
		exp, err := token.Claims.GetExpirationTime()
		if err != nil {
			return err
		}
		slog.Info("Token expires", slog.Time("exp", exp.Time))
		if exp.Before(time.Now()) || exp.Before(time.Now().Add(c.refreshInterval)) {
			renew = true
			slog.Info("Token expired or will expire soon, renewing")
		}
	}
	c.user = user
	c.password = password
	c.totp = totpSeed
	if c.client == nil || c.currentToken == "" || renew || force {
		if totpSeed != "" {
			return c.loginTotp(user, password, totpSeed)
		} else {
			return c.login(user, password)
		}
	}
	return nil
}

func (c *Client) loginTotp(user, password, totpSeed string) error {
	r := resty.New()
	verificationToken, err := getVerificationToken(r, c.baseURL)
	if err != nil {
		return err
	}
	otp, err := totp.GenerateCode(totpSeed, time.Now())
	if err != nil {
		return err
	}
	resp, err := r.
		R().SetHeaderVerbatim("RequestVerificationToken", verificationToken).
		SetHeader("Content-Type", ApplicationJson).
		SetBody(map[string]string{"email": user, "password": password, "token": otp}).
		Post(c.baseURL + LoginPathTotp)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("2FA Login response is nil")
	}
	if resp.IsError() {
		return &UnexpectedResponseCodeError{Code: resp.StatusCode()}
	}
	tokenResp := strings.Trim(resp.String(), "\"")
	_, _, err = jwt.NewParser().ParseUnverified(tokenResp, jwt.MapClaims{})
	if err != nil {
		return err
	}
	c.currentToken = tokenResp
	r = r.SetHeaders(map[string]string{"Authorization": c.currentToken})
	token, err := getVerificationToken(r, c.baseURL)
	if err != nil {
		return err
	}
	r = r.SetHeaderVerbatim("RequestVerificationToken", token).SetDebug(c.debug)
	c.client = r
	slog.Info("Logged in with TOTP", slog.String("user", user))
	javaWebToken, _, err := jwt.NewParser().ParseUnverified(c.currentToken, jwt.MapClaims{})
	if err != nil {
		return err
	}
	exp, err := javaWebToken.Claims.GetExpirationTime()
	if err != nil {
		return err
	}
	if c.retryEnabled {
		c.client = c.client.SetRetryCount(c.retry)
	}
	if c.requestTimeoutEnabled {
		c.client = c.client.SetTimeout(c.requestTimeout)
	}
	slog.Info("Token expires", slog.Time("exp", exp.Time))
	return nil
}

func (c *Client) login(user, password string) error {
	r := resty.New()
	verificationToken, err := getVerificationToken(r, c.baseURL)
	if err != nil {
		return err
	}
	resp, err := r.
		R().SetHeaderVerbatim("RequestVerificationToken", verificationToken).
		SetHeader("Content-Type", ApplicationJson).
		SetBody(map[string]string{"email": user, "password": password}).
		Post(c.baseURL + LoginPath)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("login response is nil")
	}
	if resp.IsError() {
		return &UnexpectedResponseCodeError{Code: resp.StatusCode()}
	}
	tokenResp := strings.Trim(resp.String(), "\"")
	_, _, err = jwt.NewParser().ParseUnverified(tokenResp, jwt.MapClaims{})
	if err != nil {
		return err
	}
	c.currentToken = tokenResp
	r = r.SetHeaders(map[string]string{"Authorization": c.currentToken})
	token, err := getVerificationToken(r, c.baseURL)
	if err != nil {
		return err
	}
	r = r.SetHeaderVerbatim("RequestVerificationToken", token).SetDebug(c.debug)
	c.client = r
	slog.Info("Logged in without TOTP", slog.String("user", user))
	javaWebToken, _, err := jwt.NewParser().ParseUnverified(c.currentToken, jwt.MapClaims{})
	if err != nil {
		return err
	}
	exp, err := javaWebToken.Claims.GetExpirationTime()
	if err != nil {
		return err
	}
	if c.retryEnabled {
		c.client = c.client.SetRetryCount(c.retry)
	}
	if c.requestTimeoutEnabled {
		c.client = c.client.SetTimeout(c.requestTimeout)
	}
	slog.Info("Token expires", slog.Time("exp", exp.Time))
	return nil
}

func (c *Client) GetRevocationReasons() ([]models.RevocationReasonsResponse, error) {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	var response []models.RevocationReasonsResponse
	resp, err := c.client.R().
		ExpectContentType(ApplicationJson).
		SetResult(&response).
		Post(c.baseURL + RevocationReasonsPath)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("revocation reasons response is nil")
	}
	if resp.IsError() {
		return nil, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: resp.Body()}
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type"), Body: resp.Body()}
	}
	fmt.Printf("Response: %v", resp)
	return response, nil
}

func (c *Client) RevokeCertificate(reason models.RevocationReasonsResponse, comment string, transactionId string) error {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	resp, err := c.client.R().
		SetHeader("Content-Type", ApplicationJson).
		SetBody(map[string]interface{}{
			"transactionId": transactionId,
			"notes":         comment,
			"name":          reason.Name,
			"message":       "",
		}).
		Post(c.baseURL + RevokeCertificatePath)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("revoke certificate response is nil")
	}
	if resp.IsError() {
		return &UnexpectedResponseCodeError{Code: resp.StatusCode()}
	}
	return nil
}

func (c *Client) CheckMatchingOrganization(domains []string) ([]models.OrganizationResponse, error) {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	var domainDto []Domain
	for _, domain := range domains {
		domainDto = append(domainDto, Domain{Domain: domain})
	}
	var response []models.OrganizationResponse
	resp, err := c.client.R().
		SetHeader("Content-Type", ApplicationJson).
		ExpectContentType(ApplicationJson).
		SetResult(&response).SetBody(domainDto).
		Post(c.baseURL + CheckMatchingOrganizationPath)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("check matching organization response is nil")
	}
	if resp.IsError() {
		return nil, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: resp.Body()}
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type"), Body: resp.Body()}
	}
	return response, nil
}

func (c *Client) GetMyTransactions() ([]models.TransactionResponse, error) {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	var transactions []models.TransactionResponse
	resp, err := c.client.R().
		SetResult(&transactions).
		SetHeader("Content-Type", ApplicationJson).
		ExpectContentType(ApplicationJson).
		Post(c.baseURL + GetMyTransactionsPath)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("my-transactions response is nil")
	}
	if resp.IsError() {
		return nil, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: resp.Body()}
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type"), Body: resp.Body()}
	}
	return transactions, nil
}

func (c *Client) GetCertificate(id string) (*models.CertificateResponse, error) {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	var cert models.CertificateResponse
	resp, err := c.client.R().
		SetResult(&cert).
		SetHeader("Content-Type", ApplicationJson).
		ExpectContentType(ApplicationJson).
		SetBody(map[string]interface{}{"id": id}).
		Post(c.baseURL + GetCertificatePath)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("certificate response is nil")
	}
	if resp.IsError() {
		return nil, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: resp.Body()}
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type"), Body: resp.Body()}
	}
	return &cert, nil
}

func (c *Client) CheckDomainNames(domains []string) ([]models.DomainResponse, error) {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	domainDto := make([]Domain, 0)
	for _, domain := range domains {
		domainDto = append(domainDto, Domain{Domain: domain})
	}
	domainResp := make([]models.DomainResponse, 0)
	resp, err := c.client.R().
		SetResult(&domainResp).
		SetHeader("Content-Type", ApplicationJson).
		ExpectContentType(ApplicationJson).
		SetBody(domainDto).
		Post(c.baseURL + CheckDomainNamesPath)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("check domain names response is nil")
	}
	if resp.IsError() {
		return nil, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: resp.Body()}
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type"), Body: resp.Body()}
	}
	return domainResp, nil
}

func (c *Client) RequestCertificate(domains []string, csr string, transactionType string, organization models.OrganizationResponse) (*models.CertificateRequestResponse, error) {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	var domainDto []Domain
	for _, domain := range domains {
		domainDto = append(domainDto, Domain{Domain: domain})
	}

	// Ensure that the CSR is in the correct format so we parse it and transform it again
	csrParsed, err := ParseCSR([]byte(csr))
	if err != nil {
		return nil, err
	}
	// Write the CSR as a PEM encoded string again
	csr = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrParsed.Raw,
	}))

	domainJsonBytes, _ := json.Marshal(domainDto)
	domainJson := string(domainJsonBytes)
	var result models.CertificateRequestResponse

	body := map[string]string{
		"domains":         domainJson,
		"domainsString":   domainJson,
		"csr":             csr,
		"isManualCsr":     "true",
		"consentSameKey":  "true",
		"transactionType": transactionType,
		"duration":        "1",
	}

	if transactionType == "OV" {
		body["organizationDN"] = fmt.Sprintf("OrganizationId:%s&C:%s&ST:%s&L:%s&O:%s",
			organization.ID,
			organization.Country,
			organization.State,
			organization.Locality,
			organization.OrganizationName)
	}

	resp, err := c.client.R().
		SetHeader("Content-Type", "multipart/form-data").
		SetResult(&result).
		ExpectContentType(ApplicationJson).
		SetMultipartFormData(body).
		Post(c.baseURL + RequestServerCertificatePath)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("server certificate response is nil")
	}
	if resp.IsError() {
		return nil, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: resp.Body()}
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type"), Body: resp.Body()}
	}
	return &result, nil
}

func (c *Client) GetPendingReviews() ([]models.ReviewResponse, error) {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	var pending []models.ReviewResponse
	resp, err := c.client.R().
		SetResult(&pending).
		SetHeader("Content-Type", ApplicationJson).
		ExpectContentType(ApplicationJson).
		SetBody(models.ReviewRequest{
			StartIndex:     0,
			Status:         "Pending",
			FilterPostDTOs: []any{},
		}).
		Post(c.baseURL + GetReviewableTransactionsPath)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("pending reviews response is nil")
	}
	if resp.IsError() {
		return nil, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: resp.Body()}
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type"), Body: resp.Body()}
	}
	return pending, nil
}

func (c *Client) ApproveRequest(id, message, value string) error {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	resp, err := c.client.R().
		SetHeader("Content-Type", "multipart/form-data").
		SetMultipartFormData(map[string]string{
			"reviewId":        id,
			"isValid":         "true",
			"informApplicant": "true",
			"reviewMessage":   message,
			"reviewValue":     value,
		}).
		Post(c.baseURL + UpdateReviewsPath)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("approve request response is nil")
	}
	if resp.IsError() {
		return &UnexpectedResponseCodeError{Code: resp.StatusCode()}
	}
	return nil
}

func (c *Client) GetOrganizations() ([]models.Organization, error) {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	orgs := []models.Organization{}
	resp, err := c.client.R().
		SetResult(&orgs).
		SetHeader("Content-Type", ApplicationJson).
		ExpectContentType(ApplicationJson).
		Post(c.baseURL + GetOrganizationsPath)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("organizations response is nil")
	}
	if resp.IsError() {
		return nil, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: resp.Body()}
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type"), Body: resp.Body()}
	}
	return orgs, nil
}

func (c *Client) GetOrganizationsBulk() ([]models.Organization, error) {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	orgs := []models.Organization{}
	resp, err := c.client.R().
		SetResult(&orgs).
		SetHeader("Content-Type", ApplicationJson).
		ExpectContentType(ApplicationJson).
		Post(c.baseURL + GetOrganizationsPath)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("bulk organizations response is nil")
	}
	if resp.IsError() {
		return nil, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: resp.Body()}
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type"), Body: resp.Body()}
	}
	return orgs, nil
}
func (c *Client) TriggerValidation(organizatonId, email string) error {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	resp, err := c.client.R().
		SetHeader("Content-Type", ApplicationJson).
		SetBody(map[string]string{
			"organizationId":       organizatonId,
			"usersEmail":           email,
			"validationMethodName": DnsValidation,
			"whoisEmail":           "",
		}).
		Post(c.baseURL + CreatePrevalidaitonPath)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("validation response is nil")
	}
	if resp.IsError() {
		return &UnexpectedResponseCodeError{Code: resp.StatusCode()}
	}
	return nil
}

func (c *Client) RequestSmimeBulkCertificates(groupId string, request models.SmimeBulkRequest) (*models.SmimeBulkResponse, error) {

	b := new(bytes.Buffer)
	data := csv.NewWriter(b)

	err := data.Write([]string{
		"FriendlyName",
		"Email",
		"Email2",
		"Email3",
		"GivenName",
		"Surname",
		"PickupPassword",
		"CertType",
		"CSR",
	})
	if err != nil {
		return nil, err
	}

	if request.CertType != "email_only" && request.CertType != "natural_legal_lcp" {
		return nil, errors.New("invalid certificate type")
	}

	err = data.Write([]string{
		request.FriendlyName,
		request.Email,
		request.Email2,
		request.Email3,
		request.GivenName,
		request.Surname,
		request.PickupPassword,
		request.CertType,
		request.CSR,
	})
	if err != nil {
		return nil, err
	}
	data.Flush()
	c.bulkLock.Lock()
	defer c.bulkLock.Unlock()
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()

	entriesBefore, err := c.GetSmimeBulkCertificateEntries()
	if err != nil {
		return nil, err
	}

	resp, err := c.client.R().
		SetHeader("Content-Type", "multipart/form-data").
		SetMultipartFormData(map[string]string{
			"groupId": groupId,
		}).
		SetMultipartField("csv", "bulk.csv", "text/csv", bytes.NewReader(b.Bytes())).
		Post(c.baseURL + CreateBulkCertificatesSMIMEPath)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("bulk smime certificate request response is nil")
	}
	if resp.IsError() {
		return nil, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: resp.Body()}
	}
	// Determine the difference ...
	entriesAfter, err := c.GetSmimeBulkCertificateEntries()
	if err != nil {
		return nil, err
	}
	var newEntries []models.BulkCertificateListEntry
	for _, entry := range *entriesAfter {
		found := false
		for _, oldEntry := range *entriesBefore {
			if entry.ID == oldEntry.ID {
				found = true
				break
			}
		}
		if !found {
			newEntries = append(newEntries, entry)
		}
	}
	if len(newEntries) != 1 {
		return nil, errors.New("unexpected number of new entries")
	}
	// Get the single certificate
	cert, err := c.GetSingleSmimeBulkCertificateEntry(newEntries[0].ID)
	if err != nil {
		return nil, err
	}

	return &models.SmimeBulkResponse{TransactionID: cert.ID, Certificate: cert.Certificate, Pkcs7: cert.Pkcs7}, nil
}

func (c *Client) GetSmimeBulkCertificateEntries() (*[]models.BulkCertificateListEntry, error) {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	var certs []models.BulkCertificateListEntry
	resp, err := c.client.R().
		SetResult(&certs).
		SetHeader("Content-Type", ApplicationJson).
		ExpectContentType(ApplicationJson).
		Post(c.baseURL + GetBulkCertificateEntriesPath)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("bulk smime certificates entries response is nil")
	}
	if resp.IsError() {
		return nil, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: resp.Body()}
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type"), Body: resp.Body()}
	}
	return &certs, nil
}

func (c *Client) GetSingleSmimeBulkCertificateEntry(id string) (*models.BulkCertificateEntry, error) {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	var cert []models.BulkCertificateEntry
	resp, err := c.client.R().
		SetResult(&cert).
		SetHeader("Content-Type", ApplicationJson).
		ExpectContentType(ApplicationJson).
		SetBody(map[string]interface{}{"id": id}).
		Post(c.baseURL + GetBulkCertificatesOfAnEntryPath)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("bulk smime certificates entry response is nil")
	}
	if resp.IsError() {
		return nil, &UnexpectedResponseCodeError{Code: resp.StatusCode(), Body: resp.Body()}
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type"), Body: resp.Body()}
	}
	if len(cert) == 0 {
		return nil, errors.New("no certificate found")
	}
	if len(cert) > 1 {
		return nil, errors.New("multiple certificates found")
	}

	return &cert[0], nil
}

func (c *Client) RevokeSmimeBulkCertificateEntry(transactionId string, comment string, reason string) error {
	c.loginLock.RLock()
	defer c.loginLock.RUnlock()
	resp, err := c.client.R().
		SetHeader("Content-Type", ApplicationJson).
		SetBody(map[string]interface{}{
			"transactionId": transactionId,
			"name":          reason,
			"message":       comment,
		}).
		Post(c.baseURL + RevokeBulkCertificatePath)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("revoke bulk smime certificate response is nil")
	}
	if resp.IsError() {
		return &UnexpectedResponseCodeError{Code: resp.StatusCode()}
	}
	return nil
}
