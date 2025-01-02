package models

type Organization struct {
	OrganizationID                      string `json:"organizationId"`
	Domain                              string `json:"domain"`
	Organization                        string `json:"organization"`
	OrganizationLocalized               string `json:"organizationLocalized"`
	Country                             string `json:"country"`
	State                               string `json:"state"`
	StateLocalized                      string `json:"stateLocalized"`
	Locality                            string `json:"locality"`
	LocalityLocalized                   string `json:"localityLocalized"`
	OrganizationalUnit                  string `json:"organizationalUnit"`
	OrganizationalUnitLocalized         any    `json:"organizationalUnitLocalized"`
	Dn                                  string `json:"dn"`
	Validity                            string `json:"validity"`
	GroupID                             string `json:"groupId"`
	ProductListID                       string `json:"productListId"`
	IsBaseDomain                        bool   `json:"isBaseDomain"`
	IsRemoteSignatureEnabled            bool   `json:"isRemoteSignatureEnabled"`
	DSAAccounts                         int    `json:"dSAAccounts"`
	MaxDSAAccounts                      int    `json:"maxDSAAccounts"`
	HistoryOrganizationHierarchyGetDTOs any    `json:"historyOrganizationHierarchyGetDTOs"`
	SubUnits                            []any  `json:"subUnits"`
	DisabledAt                          string `json:"disabledAt"`
	OrganizationIdentifier              any    `json:"organizationIdentifier"`
	ValidityOV                          string `json:"validityOV"`
	ValidityEV                          string `json:"validityEV"`
	DetailsHistory                      string `json:"detailsHistory"`
	JurisdictionCountry                 any    `json:"jurisdictionCountry"`
	JurisdictionState                   any    `json:"jurisdictionState"`
	JurisdictionLocality                any    `json:"jurisdictionLocality"`
	BusinessCategory                    any    `json:"businessCategory"`
	Serial                              any    `json:"serial"`
	GroupDomains                        string `json:"groupDomains"`
	GroupName                           string `json:"groupName"`
	CustomTags                          any    `json:"customTags"`
}
