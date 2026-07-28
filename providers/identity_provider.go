package providers

import (
	"github.com/PastureStack/authentication-service/model"
	"github.com/PastureStack/authentication-service/providers/github"
	ad "github.com/PastureStack/authentication-service/providers/ldap/ad"
	"github.com/PastureStack/authentication-service/providers/oidc"
	"github.com/PastureStack/authentication-service/providers/shibboleth"
	v1client "github.com/rancher/go-rancher/client"
	"github.com/rancher/go-rancher/v2"
)

// Providers map
var Providers []string

// RegisterProviders creates object of type driver for every request
func RegisterProviders() {
	Providers = []string{"githubconfig", "shibbolethconfig", "ldapconfig", "oidcconfig"}
}

// IdentityProvider interfacse defines what methods an identity provider should implement
type IdentityProvider interface {
	GetName() string
	GetUserType() string
	GenerateToken(json map[string]string) (model.Token, int, error)
	RefreshToken(json map[string]string) (model.Token, int, error)
	GetIdentities(accessToken string) ([]client.Identity, error)
	GetIdentity(externalID string, externalIDType string, accessToken string) (client.Identity, error)
	SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error)
	LoadConfig(authConfig *model.AuthConfig) error
	GetSettings() map[string]string
	GetConfig() model.AuthConfig
	GetProviderSettingList(listOnly bool) []string
	AddProviderConfig(authConfig *model.AuthConfig, providerSettings map[string]string)
	GetLegacySettings() map[string]string
	GetRedirectURL() string
	GetIdentitySeparator() string
	TestLogin(testAuthConfig *model.TestAuthConfig, accessToken string, originalLogin string) (int, error)
	GetProviderConfigResource() interface{}
	CustomizeSchema(schema *v1client.Schema) *v1client.Schema
	GetProviderSecretSettings() []string
	IsIdentityLookupSupported() bool
}

// TokenTestingProvider is implemented by redirect-based providers that can
// validate an authorization response before the active login provider is
// changed. This keeps the current authentication method available until the
// replacement has completed a real sign-in.
type TokenTestingProvider interface {
	TestToken(testAuthConfig *model.TestAuthConfig, accessToken string, originalLogin string) (model.Token, int, error)
}

// GetProvider returns an instance of an identyityProvider by name
func GetProvider(name string) (IdentityProvider, error) {
	switch name {
	case "githubconfig":
		return github.InitializeProvider()
	case "shibbolethconfig":
		return shibboleth.InitializeProvider()
	case "ldapconfig":
		return ad.InitializeProvider()
	case "oidcconfig":
		return oidc.InitializeProvider()
	default:
		return nil, nil
	}
}

// IsProviderSupported returns if provider by name is supported
func IsProviderSupported(name string) bool {
	switch name {
	case "githubconfig":
		return true
	case "shibbolethconfig":
		return true
	case "ldapconfig":
		return true
	case "oidcconfig":
		return true
	default:
		return false
	}
}
