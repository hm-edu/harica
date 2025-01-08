package client

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"log/slog"

	"github.com/go-co-op/gocron/v2"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hm-edu/harica/models"
	"github.com/pquerna/otp/totp"
)

const (
	BaseURL = "https://cm.harica.gr"

	LoginPath     = "/api/User/Login"
	LoginPathTotp = "/api/User/Login2FA"

	CreatePrevalidaitonPath = "/api/OrganizationAdmin/CreatePrevalidatedValidation"
	GetOrganizationsPath    = "/api/OrganizationAdmin/GetOrganizations"

	UpdateReviewsPath             = "/api/OrganizationValidatorSSL/UpdateReviews"
	GetReviewableTransactionsPath = "/api/OrganizationValidatorSSL/GetSSLReviewableTransactions"
	RevokeCertificatePath         = "/api/OrganizationValidatorSSL/RevokeCertificate"

	GetCertificatePath    = "/api/Certificate/GetCertificate"
	RevocationReasonsPath = "/api/Certificate/GetRevocationReasons"

	DomainValidationsPath         = "/api/ServerCertificate/GetDomainValidations"
	CheckMatchingOrganizationPath = "/api/ServerCertificate/CheckMachingOrganization"
	CheckDomainNamesPath          = "/api/ServerCertificate/CheckDomainNames"
	RequestServerCertificatePath  = "/api/ServerCertificate/RequestServerCertificate"

	ApplicationJson = "application/json"
	DnsValidation   = "3.2.2.4.7"
	RefreshInterval = 15 * time.Minute
)

type Client struct {
	client       *resty.Client
	scheduler    gocron.Scheduler
	currentToken string
	debug        bool
}

type Domain struct {
	Domain string `json:"domain"`
}

type Option func(*Client)

type UnexpectedResponseContentTypeError struct {
	ContentType string
}

func (e *UnexpectedResponseContentTypeError) Error() string {
	return fmt.Sprintf("unexpected response content type: %s", e.ContentType)
}

func NewClient(user, password, totpSeed string, options ...Option) (*Client, error) {
	c := Client{}
	for _, option := range options {
		option(&c)
	}
	err := c.prepareClient(user, password, totpSeed)
	if err != nil {
		return nil, err
	}
	s, err := gocron.NewScheduler()
	if err != nil {
		return nil, err
	}
	_, err = s.NewJob(gocron.DurationJob(RefreshInterval), gocron.NewTask(func() {
		err := c.prepareClient(user, password, totpSeed)
		if err != nil {
			slog.Error("failed to prepare client", slog.Any("error", err))
			return
		}
	}))
	if err != nil {
		return nil, err
	}
	s.Start()
	c.scheduler = s
	return &c, nil
}

func WithDebug(debug bool) Option {
	return func(c *Client) {
		c.debug = debug
	}
}

func (c *Client) prepareClient(user, password, totpSeed string) error {
	renew := false

	if c.currentToken != "" {
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
		if exp.Before(time.Now()) || exp.Before(time.Now().Add(RefreshInterval)) {
			renew = true
			slog.Info("Token expired or will expire soon, renewing")
		}
	}
	if c.client == nil || c.currentToken == "" || renew {
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
	verificationToken, err := getVerificationToken(r)
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
		Post(BaseURL + LoginPathTotp)
	if err != nil {
		return err
	}
	tokenResp := strings.Trim(resp.String(), "\"")
	_, _, err = jwt.NewParser().ParseUnverified(tokenResp, jwt.MapClaims{})
	if err != nil {
		return err
	}
	c.currentToken = tokenResp
	r = r.SetHeaders(map[string]string{"Authorization": c.currentToken})
	token, err := getVerificationToken(r)
	if err != nil {
		return err
	}
	r = r.SetHeaderVerbatim("RequestVerificationToken", token).SetDebug(c.debug)
	c.client = r
	slog.Info("Logged in with TOTP", slog.String("user", user))
	return nil
}

func (c *Client) login(user, password string) error {
	r := resty.New()
	verificationToken, err := getVerificationToken(r)
	if err != nil {
		return err
	}
	resp, err := r.
		R().SetHeaderVerbatim("RequestVerificationToken", verificationToken).
		SetHeader("Content-Type", ApplicationJson).
		SetBody(map[string]string{"email": user, "password": password}).
		Post(BaseURL + LoginPath)
	if err != nil {
		return err
	}
	tokenResp := strings.Trim(resp.String(), "\"")
	_, _, err = jwt.NewParser().ParseUnverified(tokenResp, jwt.MapClaims{})
	if err != nil {
		return err
	}
	c.currentToken = tokenResp
	r = r.SetHeaders(map[string]string{"Authorization": c.currentToken})
	token, err := getVerificationToken(r)
	if err != nil {
		return err
	}
	r = r.SetHeaderVerbatim("RequestVerificationToken", token).SetDebug(c.debug)
	c.client = r
	slog.Info("Logged in without TOTP", slog.String("user", user))
	return nil
}

func (c *Client) Shutdown() error {
	err := c.scheduler.Shutdown()
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) GetRevocationReasons() ([]models.RevocationReasonsResponse, error) {
	var response []models.RevocationReasonsResponse
	resp, err := c.client.R().
		ExpectContentType(ApplicationJson).
		SetResult(&response).
		Post(BaseURL + RevocationReasonsPath)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type")}
	}
	fmt.Printf("Response: %v", resp)
	return response, nil
}

func (c *Client) RevokeCertificate(reason models.RevocationReasonsResponse, comment string, transactionId string) error {
	_, err := c.client.R().
		SetHeader("Content-Type", ApplicationJson).
		SetBody(map[string]interface{}{
			"transactionId": transactionId,
			"notes":         comment,
			"name":          reason.Name,
			"message":       "",
		}).
		Post(BaseURL + RevokeCertificatePath)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) CheckMatchingOrganization(domains []string) ([]models.OrganizationResponse, error) {
	var domainDto []Domain
	for _, domain := range domains {
		domainDto = append(domainDto, Domain{Domain: domain})
	}
	var response []models.OrganizationResponse
	resp, err := c.client.R().
		SetHeader("Content-Type", ApplicationJson).
		ExpectContentType(ApplicationJson).
		SetResult(&response).SetBody(domainDto).
		Post(BaseURL + CheckMatchingOrganizationPath)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type")}
	}
	return response, nil
}

func (c *Client) GetCertificate(id string) (*models.CertificateResponse, error) {
	var cert models.CertificateResponse
	resp, err := c.client.R().
		SetResult(&cert).
		SetHeader("Content-Type", ApplicationJson).
		ExpectContentType(ApplicationJson).
		SetBody(map[string]interface{}{"id": id}).
		Post(BaseURL + GetCertificatePath)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type")}
	}
	return &cert, nil
}

func (c *Client) CheckDomainNames(domains []string) ([]models.DomainResponse, error) {
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
		Post(BaseURL + CheckDomainNamesPath)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type")}
	}
	return domainResp, nil
}

func (c *Client) RequestCertificate(domains []string, csr string, transactionType string, organization models.OrganizationResponse) (*models.CertificateRequestResponse, error) {
	var domainDto []Domain
	for _, domain := range domains {
		domainDto = append(domainDto, Domain{Domain: domain})
	}

	// Ensure that the CSR is in the correct format so we parse it and transform it again
	// Parse the CSR
	block, _ := pem.Decode([]byte(csr))
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
		Post(BaseURL + RequestServerCertificatePath)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type")}
	}
	return &result, nil
}

func (c *Client) GetPendingReviews() ([]models.ReviewResponse, error) {
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
		Post(BaseURL + GetReviewableTransactionsPath)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type")}
	}
	return pending, nil
}

func (c *Client) ApproveRequest(id, message, value string) error {
	_, err := c.client.R().
		SetHeader("Content-Type", "multipart/form-data").
		SetMultipartFormData(map[string]string{
			"reviewId":        id,
			"isValid":         "true",
			"informApplicant": "true",
			"reviewMessage":   message,
			"reviewValue":     value,
		}).
		Post(BaseURL + UpdateReviewsPath)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) GetOrganizations() ([]models.Organization, error) {
	orgs := []models.Organization{}
	resp, err := c.client.R().
		SetResult(&orgs).
		SetHeader("Content-Type", ApplicationJson).
		ExpectContentType(ApplicationJson).
		Post(BaseURL + GetOrganizationsPath)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(resp.Header().Get("Content-Type"), ApplicationJson) {
		return nil, &UnexpectedResponseContentTypeError{ContentType: resp.Header().Get("Content-Type")}
	}
	return orgs, nil
}

func (c *Client) TriggerValidation(organizatonId, email string) error {
	_, err := c.client.R().
		SetHeader("Content-Type", ApplicationJson).
		SetBody(map[string]string{
			"organizationId":       organizatonId,
			"usersEmail":           email,
			"validationMethodName": DnsValidation,
			"whoisEmail":           "",
		}).
		Post(BaseURL + CreatePrevalidaitonPath)
	if err != nil {
		return err
	}
	return nil
}
