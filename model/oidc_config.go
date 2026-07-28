package model

import "github.com/rancher/go-rancher/v2"

// OIDCConfig stores a generic OpenID Connect authorization-code client
// configuration. Provider discovery results are deliberately not persisted;
// they are revalidated when the provider is loaded.
type OIDCConfig struct {
	client.Resource
	DisplayName          string `json:"displayName"`
	WellKnownURL         string `json:"wellKnownUrl"`
	ClientID             string `json:"clientId"`
	ClientSecret         string `json:"clientSecret,omitempty"`
	ClientSecretSet      bool   `json:"clientSecretSet"`
	Scopes               string `json:"scopes"`
	UsePKCE              bool   `json:"usePkce"`
	UsernameClaim        string `json:"usernameClaim"`
	DisplayNameClaim     string `json:"displayNameClaim"`
	EmailClaim           string `json:"emailClaim"`
	GroupsClaim          string `json:"groupsClaim"`
	CertificateAuthority string `json:"certificateAuthority,omitempty"`

	PlatformAPIHost string `json:"-"`
}
