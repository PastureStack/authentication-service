package model

import (
	"net/http"

	"github.com/crewjam/saml"
	"github.com/rancher/go-rancher/v2"
)

// ShibbolethConfig stores the shibboleth config
type ShibbolethConfig struct {
	client.Resource
	IDPMetadataURL     string `json:"idpMetadataUrl"`
	IDPMetadataContent string `json:"idpMetadataContent"`
	SPSelfSignedCert   string `json:"spCert"`
	SPSelfSignedKey    string `json:"spKey"`
	GroupsField        string `json:"groupsField"`
	DisplayNameField   string `json:"displayNameField"`
	UserNameField      string `json:"userNameField"`
	UIDField           string `json:"uidField"`

	IDPMetadataFilePath      string
	SPSelfSignedCertFilePath string
	SPSelfSignedKeyFilePath  string
	PlatformAPIHost          string

	SamlServiceProvider *PlatformSamlServiceProvider
}

type PlatformSamlServiceProvider struct {
	ServiceProvider   saml.ServiceProvider
	ClientState       SAMLClientState
	RedirectBackPath  string
	RedirectBackBase  string
	XForwardedProto   string
	RedirectWhitelist string
}

// SAMLClientState is the compatibility contract for the signed RelayState
// cookie used by the existing authentication flow.  Keeping this small
// interface local avoids coupling the control platform to samlsp's request
// tracker implementation, which changed after the security-fixed releases.
type SAMLClientState interface {
	SetState(w http.ResponseWriter, r *http.Request, id string, value string)
	GetStates(r *http.Request) map[string]string
	GetState(r *http.Request, id string) string
	DeleteState(w http.ResponseWriter, r *http.Request, id string) error
}
