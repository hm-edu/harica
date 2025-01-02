package models

type ReviewRequest struct {
	StartIndex     int    `json:"startIndex"`
	Status         string `json:"status"`
	FilterPostDTOs []any  `json:"filterPostDTOs"`
}

type ReviewResponse struct {
	TransactionID            string          `json:"transactionId,omitempty"`
	ChainedTransactionID     any             `json:"chainedTransactionId,omitempty"`
	TransactionTypeName      string          `json:"transactionTypeName,omitempty"`
	TransactionStatus        string          `json:"transactionStatus,omitempty"`
	TransactionStatusMessage string          `json:"transactionStatusMessage,omitempty"`
	Notes                    any             `json:"notes,omitempty"`
	Organization             string          `json:"organization,omitempty"`
	PurchaseDuration         int             `json:"purchaseDuration,omitempty"`
	AdditionalEmails         string          `json:"additionalEmails,omitempty"`
	UserEmail                string          `json:"userEmail,omitempty"`
	User                     string          `json:"user,omitempty"`
	FriendlyName             any             `json:"friendlyName,omitempty"`
	ReviewValue              string          `json:"reviewValue,omitempty"`
	ReviewMessage            string          `json:"reviewMessage,omitempty"`
	ReviewedBy               any             `json:"reviewedBy,omitempty"`
	RequestedAt              string          `json:"requestedAt,omitempty"`
	ReviewedAt               any             `json:"reviewedAt,omitempty"`
	DN                       string          `json:"dN,omitempty"`
	HasReview                bool            `json:"hasReview,omitempty"`
	CanRenew                 bool            `json:"canRenew,omitempty"`
	IsRevoked                any             `json:"isRevoked,omitempty"`
	IsPaid                   any             `json:"isPaid,omitempty"`
	IsEidasValidated         any             `json:"isEidasValidated,omitempty"`
	HasEidasValidation       any             `json:"hasEidasValidation,omitempty"`
	IsHighRisk               any             `json:"isHighRisk,omitempty"`
	IsShortTerm              any             `json:"isShortTerm,omitempty"`
	IsExpired                any             `json:"isExpired,omitempty"`
	IssuedAt                 string          `json:"issuedAt,omitempty"`
	CertificateValidTo       any             `json:"certificateValidTo,omitempty"`
	Domains                  []Domains       `json:"domains,omitempty"`
	Validations              any             `json:"validations,omitempty"`
	ChainedTransactions      any             `json:"chainedTransactions,omitempty"`
	TokenType                any             `json:"tokenType,omitempty"`
	CsrType                  any             `json:"csrType,omitempty"`
	AcceptanceRetrievalAt    any             `json:"acceptanceRetrievalAt,omitempty"`
	ReviewGetDTOs            []ReviewGetDTOs `json:"reviewGetDTOs,omitempty"`
	UserDescription          string          `json:"userDescription,omitempty"`
	UserOrganization         string          `json:"userOrganization,omitempty"`
	TransactionType          string          `json:"transactionType,omitempty"`
	IsPendingP12             any             `json:"isPendingP12,omitempty"`
}

type Domains struct {
	Fqdn        string `json:"fqdn,omitempty"`
	IncludesWWW bool   `json:"includesWWW,omitempty"`
	Validations []any  `json:"validations,omitempty"`
}

type ReviewGetDTOs struct {
	ReviewID               string `json:"reviewId,omitempty"`
	IsValidated            bool   `json:"isValidated,omitempty"`
	IsReviewed             bool   `json:"isReviewed,omitempty"`
	CreatedAt              string `json:"createdAt,omitempty"`
	UserUpdatedAt          string `json:"userUpdatedAt,omitempty"`
	ReviewedAt             string `json:"reviewedAt,omitempty"`
	ReviewValue            string `json:"reviewValue,omitempty"`
	ValidatorReviewGetDTOs []any  `json:"validatorReviewGetDTOs,omitempty"`
}
