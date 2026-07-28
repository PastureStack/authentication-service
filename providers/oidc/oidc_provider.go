package oidc

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/PastureStack/authentication-service/model"
	v1client "github.com/rancher/go-rancher/client"
	"github.com/rancher/go-rancher/v2"
)

const (
	Name      = "oidc"
	Config    = Name + "config"
	TokenType = Name + "jwt"
	UserType  = Name + "_user"
	GroupType = Name + "_group"

	displayNameSetting          = "api.auth.oidc.display.name"
	wellKnownURLSetting         = "api.auth.oidc.well.known.url"
	clientIDSetting             = "api.auth.oidc.client.id"
	clientSecretSetting         = "api.auth.oidc.client.secret"
	clientSecretSetSetting      = "api.auth.oidc.client.secret.set"
	scopesSetting               = "api.auth.oidc.scopes"
	usePKCESetting              = "api.auth.oidc.use.pkce"
	usernameClaimSetting        = "api.auth.oidc.claim.username"
	displayNameClaimSetting     = "api.auth.oidc.claim.display.name"
	emailClaimSetting           = "api.auth.oidc.claim.email"
	groupsClaimSetting          = "api.auth.oidc.claim.groups"
	certificateAuthoritySetting = "api.auth.oidc.certificate.authority"
)

// Provider implements the generic external-provider contract for OpenID
// Connect authorization-code clients.
type Provider struct {
	client *Client
}

// InitializeProvider returns a provider with bounded HTTP defaults. Network
// discovery is performed only after a configuration is loaded.
func InitializeProvider() (*Provider, error) {
	return &Provider{
		client: &Client{httpClient: &http.Client{}},
	}, nil
}

func (p *Provider) GetName() string {
	return Name
}

func (p *Provider) GetUserType() string {
	return UserType
}

func (p *Provider) GenerateToken(input map[string]string) (model.Token, int, error) {
	return p.client.generateToken(input)
}

func (p *Provider) RefreshToken(input map[string]string) (model.Token, int, error) {
	accessToken := strings.TrimSpace(input["accessToken"])
	if accessToken == "" {
		return model.Token{}, http.StatusBadRequest, fmt.Errorf("OIDC access token is required")
	}
	return p.client.tokenFromUserInfo(accessToken)
}

func (p *Provider) GetIdentities(accessToken string) ([]client.Identity, error) {
	claims, err := p.client.getUserInfo(accessToken)
	if err != nil {
		return nil, err
	}
	return p.client.identitiesFromClaims(claims)
}

func (p *Provider) GetIdentity(externalID string, externalIDType string, accessToken string) (client.Identity, error) {
	if externalIDType != UserType && externalIDType != GroupType {
		return client.Identity{}, fmt.Errorf("unsupported OIDC identity type %q", externalIDType)
	}

	identity := client.Identity{
		Resource: client.Resource{
			Id:   externalIDType + ":" + externalID,
			Type: "identity",
		},
		ExternalId:     externalID,
		ExternalIdType: externalIDType,
		Login:          externalID,
		Name:           externalID,
		User:           externalIDType == UserType,
	}
	return identity, nil
}

func (p *Provider) SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error) {
	identity, err := p.GetIdentity(name, UserType, accessToken)
	if err != nil {
		return nil, err
	}
	return []client.Identity{identity}, nil
}

func (p *Provider) LoadConfig(authConfig *model.AuthConfig) error {
	config := authConfig.OIDCConfig
	p.client.config = &config
	return p.client.initialize()
}

func (p *Provider) GetConfig() model.AuthConfig {
	authConfig := model.AuthConfig{
		Resource: client.Resource{
			Type: "config",
		},
		Provider:   Config,
		OIDCConfig: *p.client.config,
	}
	authConfig.OIDCConfig.Resource = client.Resource{Type: Config}
	authConfig.OIDCConfig.ClientSecretSet = authConfig.OIDCConfig.ClientSecret != ""
	return authConfig
}

func (p *Provider) GetSettings() map[string]string {
	config := p.client.config
	settings := map[string]string{
		displayNameSetting:          config.DisplayName,
		wellKnownURLSetting:         config.WellKnownURL,
		clientIDSetting:             config.ClientID,
		clientSecretSetSetting:      fmt.Sprintf("%t", config.ClientSecret != "" || config.ClientSecretSet),
		scopesSetting:               config.Scopes,
		usePKCESetting:              fmt.Sprintf("%t", config.UsePKCE),
		usernameClaimSetting:        config.UsernameClaim,
		displayNameClaimSetting:     config.DisplayNameClaim,
		emailClaimSetting:           config.EmailClaim,
		groupsClaimSetting:          config.GroupsClaim,
		certificateAuthoritySetting: config.CertificateAuthority,
	}
	if config.ClientSecret != "" {
		settings[clientSecretSetting] = config.ClientSecret
	}
	return settings
}

func (p *Provider) GetProviderSettingList(listOnly bool) []string {
	settings := []string{
		displayNameSetting,
		wellKnownURLSetting,
		clientIDSetting,
		clientSecretSetSetting,
		scopesSetting,
		usePKCESetting,
		usernameClaimSetting,
		displayNameClaimSetting,
		emailClaimSetting,
		groupsClaimSetting,
		certificateAuthoritySetting,
	}
	if !listOnly {
		settings = append(settings, clientSecretSetting)
	}
	return settings
}

func (p *Provider) AddProviderConfig(authConfig *model.AuthConfig, settings map[string]string) {
	usePKCE := true
	if value, present := settings[usePKCESetting]; present {
		usePKCE = !strings.EqualFold(value, "false")
	}

	config := model.OIDCConfig{
		Resource:             client.Resource{Type: Config},
		DisplayName:          valueOrDefault(settings[displayNameSetting], "OpenID Connect"),
		WellKnownURL:         settings[wellKnownURLSetting],
		ClientID:             settings[clientIDSetting],
		ClientSecret:         settings[clientSecretSetting],
		ClientSecretSet:      strings.EqualFold(settings[clientSecretSetSetting], "true") || settings[clientSecretSetting] != "",
		Scopes:               valueOrDefault(settings[scopesSetting], "openid"),
		UsePKCE:              usePKCE,
		UsernameClaim:        valueOrDefault(settings[usernameClaimSetting], "preferred_username"),
		DisplayNameClaim:     valueOrDefault(settings[displayNameClaimSetting], "name"),
		EmailClaim:           valueOrDefault(settings[emailClaimSetting], "email"),
		GroupsClaim:          settings[groupsClaimSetting],
		CertificateAuthority: settings[certificateAuthoritySetting],
	}
	authConfig.OIDCConfig = config
}

func (p *Provider) GetLegacySettings() map[string]string {
	return map[string]string{}
}

func (p *Provider) GetRedirectURL() string {
	return p.client.authorizationURL()
}

func (p *Provider) GetIdentitySeparator() string {
	return "#oidc#"
}

func (p *Provider) TestLogin(testAuthConfig *model.TestAuthConfig, accessToken string, originalLogin string) (int, error) {
	_, status, err := p.TestToken(testAuthConfig, accessToken, originalLogin)
	return status, err
}

func (p *Provider) TestToken(testAuthConfig *model.TestAuthConfig, accessToken string, originalLogin string) (model.Token, int, error) {
	return p.GenerateToken(map[string]string{"code": testAuthConfig.Code})
}

func (p *Provider) GetProviderConfigResource() interface{} {
	return model.OIDCConfig{}
}

func (p *Provider) CustomizeSchema(schema *v1client.Schema) *v1client.Schema {
	delete(schema.ResourceFields, "-")
	defaults := map[string]interface{}{
		"displayName":      "OpenID Connect",
		"scopes":           "openid",
		"usePkce":          true,
		"usernameClaim":    "preferred_username",
		"displayNameClaim": "name",
		"emailClaim":       "email",
		"groupsClaim":      "groups",
	}
	for name, value := range defaults {
		field := schema.ResourceFields[name]
		field.Default = value
		schema.ResourceFields[name] = field
	}

	clientSecretSet := schema.ResourceFields["clientSecretSet"]
	clientSecretSet.Create = false
	clientSecretSet.Update = false
	schema.ResourceFields["clientSecretSet"] = clientSecretSet
	return schema
}

func (p *Provider) GetProviderSecretSettings() []string {
	return []string{clientSecretSetting}
}

func (p *Provider) IsIdentityLookupSupported() bool {
	return false
}

func valueOrDefault(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
