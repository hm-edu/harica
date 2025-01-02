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
