package models

type CertificateResponse struct {
	PKCS7                  string   `json:"pKCS7"`
	Certificate            string   `json:"certificate"`
	PemBundle              string   `json:"pemBundle"`
	DN                     string   `json:"dN"`
	SANS                   string   `json:"sANS"`
	RevocationCode         string   `json:"revocationCode"`
	Serial                 string   `json:"serial"`
	IsRevoked              bool     `json:"isRevoked"`
	RevokedAt              any      `json:"revokedAt"`
	ValidFrom              string   `json:"validFrom"`
	ValidTo                string   `json:"validTo"`
	IssuerDN               string   `json:"issuerDN"`
	AuthorizationDomains   string   `json:"authorizationDomains"`
	KeyType                string   `json:"keyType"`
	FriendlyName           any      `json:"friendlyName"`
	Approver               any      `json:"approver"`
	ApproversAddress       any      `json:"approversAddress"`
	TokenDeviceID          any      `json:"tokenDeviceId"`
	Orders                 []Orders `json:"orders"`
	NeedsImportWithFortify bool     `json:"needsImportWithFortify"`
	IsTokenCertificate     bool     `json:"isTokenCertificate"`
	IssuerCertificate      string   `json:"issuerCertificate"`
	TransactionID          any      `json:"transactionId"`
}
type Orders struct {
	OrderID              string `json:"orderId"`
	IsChainedTransaction bool   `json:"isChainedTransaction"`
	IssuedAt             string `json:"issuedAt"`
	Duration             int    `json:"duration"`
}

type CertificateRequestResponse struct {
	TransactionID      string `json:"id"`
	RequiresConsentKey bool   `json:"requiresConsentKey"`
}

type RevocationReasonsResponse struct {
	Name                       string `json:"name"`
	IsClient                   bool   `json:"isClient"`
	RevocationMesasge          string `json:"revocationMessage"`
	RevocationMessageLocalized string `json:"revocationMessageLocalised"`
}

type TransactionResponse struct {
	TransactionID            string `json:"transactionId"`
	ChainedTransactionID     any    `json:"chainedTransactionId"`
	TransactionTypeName      string `json:"transactionTypeName"`
	TransactionStatus        string `json:"transactionStatus"`
	TransactionStatusMessage string `json:"transactionStatusMessage"`
	Notes                    any    `json:"notes"`
	Organization             any    `json:"organization"`
	PurchaseDuration         int    `json:"purchaseDuration"`
	AdditionalEmails         string `json:"additionalEmails"`
	UserEmail                string `json:"userEmail"`
	User                     any    `json:"user"`
	FriendlyName             any    `json:"friendlyName"`
	ReviewValue              any    `json:"reviewValue"`
	ReviewMessage            any    `json:"reviewMessage"`
	ReviewedBy               any    `json:"reviewedBy"`
	RequestedAt              string `json:"requestedAt"`
	ReviewedAt               any    `json:"reviewedAt"`
	DN                       any    `json:"dN"`
	HasReview                bool   `json:"hasReview"`
	CanRenew                 bool   `json:"canRenew"`
	IsRevoked                any    `json:"isRevoked"`
	IsPaid                   bool   `json:"isPaid"`
	IsEidasValidated         any    `json:"isEidasValidated"`
	HasEidasValidation       any    `json:"hasEidasValidation"`
	IsHighRisk               bool   `json:"isHighRisk"`
	IsShortTerm              any    `json:"isShortTerm"`
	IsExpired                bool   `json:"isExpired"`
	IssuedAt                 any    `json:"issuedAt"`
	CertificateValidTo       any    `json:"certificateValidTo"`
	Domains                  []struct {
		Fqdn        string `json:"fqdn"`
		IncludesWWW bool   `json:"includesWWW"`
		Validations []any  `json:"validations"`
	} `json:"domains"`
	Validations           any   `json:"validations"`
	ChainedTransactions   []any `json:"chainedTransactions"`
	TokenType             any   `json:"tokenType"`
	CsrType               any   `json:"csrType"`
	AcceptanceRetrievalAt any   `json:"acceptanceRetrievalAt"`
	ReviewGetDTOs         any   `json:"reviewGetDTOs"`
	UserDescription       any   `json:"userDescription"`
	UserOrganization      any   `json:"userOrganization"`
	TransactionType       any   `json:"transactionType"`
	IsPendingP12          any   `json:"isPendingP12"`
}

type SmimeBulkRequest struct {
	FriendlyName   string
	Email          string
	Email2         string
	Email3         string
	GivenName      string
	Surname        string
	PickupPassword string
	CertType       string
	CSR            string
}

type SmimeBulkResponse struct {
	TransactionID string `json:"id"`
	Certificate   string `json:"certificate"`
	Pkcs7         string `json:"pkcs7"`
}

type BulkCertificateListEntry struct {
	ID         string `json:"id"`
	EntityID   string `json:"entityId"`
	CreatedAt  string `json:"createdAt"`
	CustomTags string `json:"customTags"`
	UserEmail  string `json:"userEmail"`
}

type BulkCertificateEntry struct {
	ID                      string `json:"id"`
	BulkCertificatesEntryID string `json:"bulkCertificatesEntryId"`
	StatusName              string `json:"statusName"`
	FriendlyName            string `json:"friendlyName"`
	Duration                int    `json:"duration"`
	CustomTags              any    `json:"customTags"`
	RevocationMessage       string `json:"revocationMessage"`
	Pkcs12                  any    `json:"pkcs12"`
	IssuedAt                string `json:"issuedAt"`
	ValidFrom               string `json:"validFrom"`
	ValidTo                 string `json:"validTo"`
	RevocationCode          string `json:"revocationCode"`
	IsRevoked               bool   `json:"isRevoked"`
	RevokedAt               any    `json:"revokedAt"`
	CommonName              string `json:"commonName"`
	OrganizationUnit1       string `json:"organizationUnit1"`
	OrganizationUnit2       string `json:"organizationUnit2"`
	OrganizationUnit3       string `json:"organizationUnit3"`
	KeySpec                 string `json:"keySpec"`
	KeyAlg                  string `json:"keyAlg"`
	Serial                  string `json:"serial"`
	Certificate             string `json:"certificate"`
	Notes                   any    `json:"notes"`
	RevokedByEmail          any    `json:"revokedByEmail"`
	Pkcs7                   string `json:"pkcs7"`
}
