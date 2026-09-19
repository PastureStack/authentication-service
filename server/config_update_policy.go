package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/PastureStack/authentication-service/model"
	"github.com/PastureStack/authentication-service/providers/oidc"
	"github.com/rancher/go-rancher/v2"
)

const (
	oidcProviderName                = "oidcconfig"
	oidcAccessPolicyUpdatePurpose   = "oidcAccessPolicyUpdate"
	configErrorLocalRecovery        = "LocalRecoveryRequired"
	configErrorMFAConfirmation      = "MfaConfirmationRequired"
	configErrorMFAUnavailable       = "MfaConfirmationUnavailable"
	configErrorInvalidAccessMode    = "InvalidAccessMode"
	configErrorInvalidIdentity      = "InvalidAllowedIdentity"
	securityConfirmationBodyLimit   = 1 << 20
	securityConfirmationRequestTime = 10 * time.Second
)

var validOIDCAccessModes = map[string]bool{
	"unrestricted": true,
	"restricted":   true,
	"required":     true,
}

var validOIDCIdentityTypes = map[string]bool{
	"oidc_user":  true,
	"oidc_group": true,
}

// ConfigUpdateRequest contains only the caller proof needed to consume a
// one-time security confirmation. Authentication material is never persisted.
type ConfigUpdateRequest struct {
	Context       context.Context
	Authorization string
	Cookie        string
	HTTPClient    *http.Client
}

// ConfigUpdateError is returned to clients with a stable machine-readable
// code. RequestDigest is present only when the client must complete MFA for
// this exact normalized access-policy request.
type ConfigUpdateError struct {
	HTTPStatus    int
	Code          string
	Message       string
	RequestDigest string
}

func (e *ConfigUpdateError) Error() string {
	return e.Message
}

type oidcConfigUpdatePlan struct {
	SameProvider                   bool
	SourceChanged                  bool
	InitialEnable                  bool
	RequiresLocalRecovery          bool
	RequiresProviderInitialization bool
	PermissionExpansion            bool
	RequestDigest                  string
}

type canonicalOIDCIdentity struct {
	ExternalIDType string `json:"externalIdType"`
	ExternalID     string `json:"externalId"`
}

type canonicalOIDCAccessPolicy struct {
	Provider          string                  `json:"provider"`
	Enabled           bool                    `json:"enabled"`
	AccessMode        string                  `json:"accessMode"`
	AllowedIdentities []canonicalOIDCIdentity `json:"allowedIdentities"`
}

func normalizeOIDCAccessPolicy(config *model.AuthConfig, strict bool) error {
	config.AccessMode = strings.ToLower(strings.TrimSpace(config.AccessMode))
	if !validOIDCAccessModes[config.AccessMode] {
		if !strict && config.AccessMode == "" {
			config.AccessMode = "restricted"
		} else {
			return &ConfigUpdateError{
				HTTPStatus: http.StatusUnprocessableEntity,
				Code:       configErrorInvalidAccessMode,
				Message:    "OpenID Connect accessMode must be unrestricted, restricted, or required",
			}
		}
	}

	if config.AccessMode == "unrestricted" {
		config.AllowedIdentities = []client.Identity{}
		return nil
	}

	separator := "#oidc#"
	seen := make(map[string]bool)
	normalized := make([]client.Identity, 0, len(config.AllowedIdentities))
	for _, identity := range config.AllowedIdentities {
		identityType := strings.TrimSpace(identity.ExternalIdType)
		externalID := strings.TrimSpace(identity.ExternalId)
		if !validOIDCIdentityTypes[identityType] || externalID == "" || strings.Contains(externalID, separator) {
			if !strict {
				continue
			}
			return &ConfigUpdateError{
				HTTPStatus: http.StatusUnprocessableEntity,
				Code:       configErrorInvalidIdentity,
				Message:    "OpenID Connect allowed identities must be non-empty oidc_user or oidc_group values",
			}
		}

		key := identityType + "\x00" + externalID
		if seen[key] {
			continue
		}
		seen[key] = true
		identity.ExternalIdType = identityType
		identity.ExternalId = externalID
		identity.Resource.Id = identityType + ":" + externalID
		normalized = append(normalized, identity)
	}
	config.AllowedIdentities = normalized
	return nil
}

func planOIDCConfigUpdate(current model.AuthConfig, requested model.AuthConfig) (oidcConfigUpdatePlan, error) {
	if err := normalizeOIDCAccessPolicy(&current, false); err != nil {
		return oidcConfigUpdatePlan{}, err
	}
	if err := normalizeOIDCAccessPolicy(&requested, true); err != nil {
		return oidcConfigUpdatePlan{}, err
	}
	oidc.NormalizeConfig(&current.OIDCConfig)
	oidc.NormalizeConfig(&requested.OIDCConfig)

	sameProvider := strings.EqualFold(current.Provider, oidcProviderName) &&
		strings.EqualFold(requested.Provider, oidcProviderName)
	sourceChanged := !sameProvider || oidcIdentitySourceChanged(current.OIDCConfig, requested.OIDCConfig)
	initialEnable := requested.Enabled && (!current.Enabled || !sameProvider)
	permissionExpansion := current.Enabled && requested.Enabled && sameProvider &&
		oidcAccessPolicyExpands(current, requested)
	digest, err := oidcAccessPolicyDigest(requested)
	if err != nil {
		return oidcConfigUpdatePlan{}, err
	}

	return oidcConfigUpdatePlan{
		SameProvider:                   sameProvider,
		SourceChanged:                  sourceChanged,
		InitialEnable:                  initialEnable,
		RequiresLocalRecovery:          initialEnable || sourceChanged,
		RequiresProviderInitialization: initialEnable || sourceChanged,
		PermissionExpansion:            permissionExpansion,
		RequestDigest:                  digest,
	}, nil
}

// canApplyOIDCReloadWithoutInitialization keeps platform setting events from
// turning an access-policy-only save into a second provider initialization.
// The provider must already be live; startup, first enablement, provider
// switches, and identity-source changes continue through the full reload path.
func canApplyOIDCReloadWithoutInitialization(current model.AuthConfig,
	requested model.AuthConfig, providerReady bool) bool {
	if !providerReady {
		return false
	}
	plan, err := planOIDCConfigUpdate(current, requested)
	return err == nil && plan.SameProvider && !plan.RequiresProviderInitialization
}

func oidcIdentitySourceChanged(current model.OIDCConfig, requested model.OIDCConfig) bool {
	return current.WellKnownURL != requested.WellKnownURL ||
		current.ClientID != requested.ClientID ||
		current.ClientSecret != requested.ClientSecret ||
		current.Scopes != requested.Scopes ||
		current.UsePKCE != requested.UsePKCE ||
		current.UsernameClaim != requested.UsernameClaim ||
		current.DisplayNameClaim != requested.DisplayNameClaim ||
		current.EmailClaim != requested.EmailClaim ||
		current.GroupsClaim != requested.GroupsClaim ||
		current.CertificateAuthority != requested.CertificateAuthority
}

func oidcAccessPolicyExpands(current model.AuthConfig, requested model.AuthConfig) bool {
	if current.AccessMode == "unrestricted" {
		return false
	}
	if requested.AccessMode == "unrestricted" ||
		(current.AccessMode == "required" && requested.AccessMode == "restricted") {
		return true
	}

	currentIdentities := make(map[string]bool, len(current.AllowedIdentities))
	for _, identity := range current.AllowedIdentities {
		currentIdentities[identity.ExternalIdType+"\x00"+identity.ExternalId] = true
	}
	for _, identity := range requested.AllowedIdentities {
		if !currentIdentities[identity.ExternalIdType+"\x00"+identity.ExternalId] {
			return true
		}
	}
	return false
}

func oidcAccessPolicyDigest(config model.AuthConfig) (string, error) {
	identities := make([]canonicalOIDCIdentity, 0, len(config.AllowedIdentities))
	for _, identity := range config.AllowedIdentities {
		identities = append(identities, canonicalOIDCIdentity{
			ExternalIDType: identity.ExternalIdType,
			ExternalID:     identity.ExternalId,
		})
	}
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].ExternalIDType == identities[j].ExternalIDType {
			return identities[i].ExternalID < identities[j].ExternalID
		}
		return identities[i].ExternalIDType < identities[j].ExternalIDType
	})
	payload, err := json.Marshal(canonicalOIDCAccessPolicy{
		Provider:          strings.ToLower(config.Provider),
		Enabled:           config.Enabled,
		AccessMode:        config.AccessMode,
		AllowedIdentities: identities,
	})
	if err != nil {
		return "", fmt.Errorf("failed to encode the OpenID Connect access policy: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func requireBoundSecurityConfirmation(request ConfigUpdateRequest, confirmation string, digest string) error {
	if strings.TrimSpace(confirmation) == "" {
		return mfaConfirmationRequired(digest)
	}

	endpoint, err := platformEndpoint("/v2-beta/mfaOperation")
	if err != nil {
		return &ConfigUpdateError{
			HTTPStatus: http.StatusBadGateway,
			Code:       configErrorMFAUnavailable,
			Message:    "The MFA confirmation service is unavailable",
		}
	}
	body, err := json.Marshal(map[string]string{
		"operation":            "consumeSecurityConfirmation",
		"securityConfirmation": confirmation,
		"purpose":              oidcAccessPolicyUpdatePurpose,
		"requestDigest":        digest,
	})
	if err != nil {
		return err
	}

	ctx := request.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, securityConfirmationRequestTime)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if request.Authorization != "" {
		httpRequest.Header.Set("Authorization", request.Authorization)
	}
	if request.Cookie != "" {
		httpRequest.Header.Set("Cookie", request.Cookie)
	}

	httpClient := request.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: securityConfirmationRequestTime}
	}
	response, err := httpClient.Do(httpRequest)
	if err != nil {
		return &ConfigUpdateError{
			HTTPStatus: http.StatusBadGateway,
			Code:       configErrorMFAUnavailable,
			Message:    "The MFA confirmation service is unavailable",
		}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, securityConfirmationBodyLimit))
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden ||
		response.StatusCode == http.StatusUnprocessableEntity {
		return mfaConfirmationRequired(digest)
	}
	return &ConfigUpdateError{
		HTTPStatus: http.StatusBadGateway,
		Code:       configErrorMFAUnavailable,
		Message:    "The MFA confirmation service is unavailable",
	}
}

func mfaConfirmationRequired(digest string) error {
	return &ConfigUpdateError{
		HTTPStatus:    http.StatusForbidden,
		Code:          configErrorMFAConfirmation,
		Message:       "A one-time MFA confirmation is required to expand OpenID Connect access",
		RequestDigest: digest,
	}
}

func platformEndpoint(path string) (string, error) {
	parsed, err := url.Parse(PlatformURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid platform URL")
	}
	parsed.Path = path
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}
