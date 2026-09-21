package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PastureStack/authentication-service/model"
	"github.com/rancher/go-rancher/v2"
)

func TestOIDCPolicyOnlyUpdateSkipsRecoveryAndProviderInitialization(t *testing.T) {
	current := oidcConfigForPolicyTest(true, "required", oidcIdentity("oidc_user", "alice"))
	requested := current
	requested.AccessMode = "restricted"

	plan, err := planOIDCConfigUpdate(current, requested)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RequiresLocalRecovery || plan.RequiresProviderInitialization {
		t.Fatalf("policy-only update unexpectedly required recovery or provider initialization: %#v", plan)
	}
	if !plan.PermissionExpansion {
		t.Fatal("required to restricted is an access expansion and must require bound MFA")
	}
}

func TestOIDCPolicyOnlyReloadSkipsProviderInitialization(t *testing.T) {
	current := oidcConfigForPolicyTest(true, "restricted",
		oidcIdentity("oidc_user", "alice"))
	policyOnly := current
	policyOnly.AllowedIdentities = append(policyOnly.AllowedIdentities,
		oidcIdentity("oidc_group", "operators"))

	if !canApplyOIDCReloadWithoutInitialization(current, policyOnly, true) {
		t.Fatal("a live unchanged OIDC provider would be initialized for a policy-only reload")
	}
	if canApplyOIDCReloadWithoutInitialization(current, policyOnly, false) {
		t.Fatal("startup skipped required OIDC provider initialization")
	}

	sourceChange := policyOnly
	sourceChange.OIDCConfig.ClientID = "replacement-client"
	if canApplyOIDCReloadWithoutInitialization(current, sourceChange, true) {
		t.Fatal("an OIDC identity-source change skipped provider initialization")
	}

	initialEnable := current
	initialEnable.Enabled = false
	if canApplyOIDCReloadWithoutInitialization(initialEnable, current, true) {
		t.Fatal("initial OIDC enablement skipped provider initialization")
	}
}

func TestExpiredLocalRecoveryOnlyBlocksIdentitySourceChanges(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	expiredRecovery := map[string]string{
		localRecoveryEnabledSetting:    "true",
		localRecoveryMFAReadySetting:   "true",
		localRecoveryVerifiedAtSetting: strconv.FormatInt(now.Add(-6*time.Minute).UnixMilli(), 10),
	}
	if localRecoveryReady(expiredRecovery, now) {
		t.Fatal("a six-minute-old local recovery verification was accepted")
	}

	current := oidcConfigForPolicyTest(true, "restricted", oidcIdentity("oidc_user", "alice"))
	policyOnly := current
	policyOnly.AllowedIdentities = append(policyOnly.AllowedIdentities,
		oidcIdentity("oidc_group", "operators"))
	policyPlan, err := planOIDCConfigUpdate(current, policyOnly)
	if err != nil {
		t.Fatal(err)
	}
	if policyPlan.RequiresLocalRecovery || policyPlan.RequiresProviderInitialization {
		t.Fatalf("an expired recovery incorrectly blocked a policy-only update: %#v", policyPlan)
	}

	sourceChange := current
	sourceChange.OIDCConfig.ClientID = "replacement-client"
	sourcePlan, err := planOIDCConfigUpdate(current, sourceChange)
	if err != nil {
		t.Fatal(err)
	}
	if !sourcePlan.RequiresLocalRecovery || !sourcePlan.RequiresProviderInitialization {
		t.Fatalf("an identity-source change bypassed expired-recovery enforcement: %#v", sourcePlan)
	}
}

func TestOIDCIdentitySourceChangesRequireRecoveryAndInitialization(t *testing.T) {
	base := oidcConfigForPolicyTest(true, "restricted", oidcIdentity("oidc_user", "alice"))
	tests := []struct {
		name   string
		change func(*model.AuthConfig)
	}{
		{"well-known URL", func(config *model.AuthConfig) {
			config.OIDCConfig.WellKnownURL = "https://new.example/.well-known/openid-configuration"
		}},
		{"client ID", func(config *model.AuthConfig) { config.OIDCConfig.ClientID = "new-client" }},
		{"client secret", func(config *model.AuthConfig) { config.OIDCConfig.ClientSecret = "new-secret" }},
		{"certificate authority", func(config *model.AuthConfig) { config.OIDCConfig.CertificateAuthority = "new-ca" }},
		{"scope", func(config *model.AuthConfig) { config.OIDCConfig.Scopes = "openid email groups" }},
		{"PKCE", func(config *model.AuthConfig) { config.OIDCConfig.UsePKCE = false }},
		{"username claim", func(config *model.AuthConfig) { config.OIDCConfig.UsernameClaim = "preferred_username" }},
		{"display-name claim", func(config *model.AuthConfig) { config.OIDCConfig.DisplayNameClaim = "display_name" }},
		{"email claim", func(config *model.AuthConfig) { config.OIDCConfig.EmailClaim = "mail" }},
		{"groups claim", func(config *model.AuthConfig) { config.OIDCConfig.GroupsClaim = "roles" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requested := base
			test.change(&requested)
			plan, err := planOIDCConfigUpdate(base, requested)
			if err != nil {
				t.Fatal(err)
			}
			if !plan.SourceChanged || !plan.RequiresLocalRecovery || !plan.RequiresProviderInitialization {
				t.Fatalf("identity-source change was not gated: %#v", plan)
			}
		})
	}
}

func TestDisabledOIDCIdentitySourceChangeStillRequiresRecovery(t *testing.T) {
	current := oidcConfigForPolicyTest(false, "restricted", oidcIdentity("oidc_user", "alice"))
	requested := current
	requested.OIDCConfig.ClientID = "replacement-client"

	plan, err := planOIDCConfigUpdate(current, requested)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.SourceChanged || !plan.RequiresLocalRecovery || !plan.RequiresProviderInitialization {
		t.Fatalf("disabled identity-source change bypassed the recovery gate: %#v", plan)
	}
}

func TestOIDCInitialEnableAndProviderSwitchRequireRecovery(t *testing.T) {
	requested := oidcConfigForPolicyTest(true, "restricted", oidcIdentity("oidc_user", "alice"))
	for name, current := range map[string]model.AuthConfig{
		"initial enable":  oidcConfigForPolicyTest(false, "restricted", oidcIdentity("oidc_user", "alice")),
		"provider switch": {Provider: "githubconfig", Enabled: true, AccessMode: "restricted"},
	} {
		t.Run(name, func(t *testing.T) {
			plan, err := planOIDCConfigUpdate(current, requested)
			if err != nil {
				t.Fatal(err)
			}
			if !plan.InitialEnable || !plan.RequiresLocalRecovery || !plan.RequiresProviderInitialization {
				t.Fatalf("activation was not gated: %#v", plan)
			}
		})
	}
}

func TestOIDCDisplayNameUpdateDoesNotInitializeProvider(t *testing.T) {
	current := oidcConfigForPolicyTest(true, "restricted", oidcIdentity("oidc_user", "alice"))
	requested := current
	requested.OIDCConfig.DisplayName = "Company login"
	plan, err := planOIDCConfigUpdate(current, requested)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SourceChanged || plan.RequiresProviderInitialization || plan.RequiresLocalRecovery {
		t.Fatalf("display-only update was treated as an identity-source change: %#v", plan)
	}
}

func TestOIDCAccessExpansionRequiresMFAWhileContractionDoesNot(t *testing.T) {
	alice := oidcIdentity("oidc_user", "alice")
	operators := oidcIdentity("oidc_group", "operators")
	tests := []struct {
		name      string
		current   model.AuthConfig
		requested model.AuthConfig
		expands   bool
	}{
		{
			name:      "add an allowed group",
			current:   oidcConfigForPolicyTest(true, "restricted", alice),
			requested: oidcConfigForPolicyTest(true, "restricted", alice, operators),
			expands:   true,
		},
		{
			name:      "switch to unrestricted",
			current:   oidcConfigForPolicyTest(true, "restricted", alice),
			requested: oidcConfigForPolicyTest(true, "unrestricted"),
			expands:   true,
		},
		{
			name:      "remove an allowed group",
			current:   oidcConfigForPolicyTest(true, "restricted", alice, operators),
			requested: oidcConfigForPolicyTest(true, "restricted", alice),
			expands:   false,
		},
		{
			name:      "tighten restricted to required",
			current:   oidcConfigForPolicyTest(true, "restricted", alice),
			requested: oidcConfigForPolicyTest(true, "required", alice),
			expands:   false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := planOIDCConfigUpdate(test.current, test.requested)
			if err != nil {
				t.Fatal(err)
			}
			if plan.PermissionExpansion != test.expands {
				t.Fatalf("PermissionExpansion = %v, expected %v: %#v",
					plan.PermissionExpansion, test.expands, plan)
			}
		})
	}
}

func TestNormalizeOIDCAccessPolicyClearsUnrestrictedAndDeduplicatesRestricted(t *testing.T) {
	unrestricted := oidcConfigForPolicyTest(true, " unrestricted ",
		oidcIdentity("oidc_user", "alice"), oidcIdentity("oidc_group", "operators"))
	if err := normalizeOIDCAccessPolicy(&unrestricted, true); err != nil {
		t.Fatal(err)
	}
	if unrestricted.AllowedIdentities == nil || len(unrestricted.AllowedIdentities) != 0 {
		t.Fatalf("unrestricted policy retained identities: %#v", unrestricted.AllowedIdentities)
	}

	restricted := oidcConfigForPolicyTest(true, "restricted",
		oidcIdentity("oidc_user", "alice"), oidcIdentity(" oidc_user ", " alice "),
		oidcIdentity("oidc_group", "operators"))
	if err := normalizeOIDCAccessPolicy(&restricted, true); err != nil {
		t.Fatal(err)
	}
	if len(restricted.AllowedIdentities) != 2 {
		t.Fatalf("duplicate identities were not removed: %#v", restricted.AllowedIdentities)
	}
}

func TestNormalizeOIDCAccessPolicyRejectsIllegalIdentityTypes(t *testing.T) {
	for _, identity := range []client.Identity{
		oidcIdentity("github_user", "alice"),
		oidcIdentity("oidc_user", ""),
		oidcIdentity("oidc_group", "bad#oidc#value"),
	} {
		config := oidcConfigForPolicyTest(true, "restricted", identity)
		err := normalizeOIDCAccessPolicy(&config, true)
		assertConfigUpdateError(t, err, configErrorInvalidIdentity)
	}
}

func TestOnlyTheAllowedIdentitySettingAcceptsAnExplicitEmptyValue(t *testing.T) {
	if !shouldUpdateCommonSetting(allowedIdentitiesSetting, "") {
		t.Fatal("the OIDC allowlist cannot be explicitly cleared")
	}
	if shouldUpdateCommonSetting(accessModeSetting, "") ||
		shouldUpdateCommonSetting(providerSetting, "") {
		t.Fatal("unrelated common settings lost their historical empty-means-unchanged behavior")
	}
}

func TestOIDCAccessPolicyDigestIsStableForIdentityOrder(t *testing.T) {
	first := oidcConfigForPolicyTest(true, "restricted",
		oidcIdentity("oidc_user", "alice"), oidcIdentity("oidc_group", "operators"))
	second := oidcConfigForPolicyTest(true, "restricted",
		oidcIdentity("oidc_group", "operators"), oidcIdentity("oidc_user", "alice"))
	firstDigest, err := oidcAccessPolicyDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := oidcAccessPolicyDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest || len(firstDigest) != 64 {
		t.Fatalf("policy digest was not canonical: %q != %q", firstDigest, secondDigest)
	}
}

func TestBoundSecurityConfirmationForwardsActorAndExactDigest(t *testing.T) {
	digest := strings.Repeat("a", 64)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2-beta/mfaOperation" {
			t.Errorf("unexpected MFA path %q", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer actor-token" ||
			request.Header.Get("Cookie") != "token=actor-cookie" {
			t.Errorf("actor credentials were not forwarded")
		}
		var payload map[string]string
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["operation"] != "consumeSecurityConfirmation" ||
			payload["purpose"] != oidcAccessPolicyUpdatePurpose ||
			payload["requestDigest"] != digest || payload["securityConfirmation"] != "ticket" {
			t.Errorf("unexpected MFA consume payload: %#v", payload)
		}
		response.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	previousPlatformURL := PlatformURL
	PlatformURL = server.URL + "/v1"
	defer func() { PlatformURL = previousPlatformURL }()
	err := requireBoundSecurityConfirmation(ConfigUpdateRequest{
		Authorization: "Bearer actor-token",
		Cookie:        "token=actor-cookie",
		HTTPClient:    server.Client(),
	}, "ticket", digest)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBoundSecurityConfirmationReturnsStableChallenge(t *testing.T) {
	digest := strings.Repeat("b", 64)
	err := requireBoundSecurityConfirmation(ConfigUpdateRequest{}, "", digest)
	updateError := assertConfigUpdateError(t, err, configErrorMFAConfirmation)
	if updateError.RequestDigest != digest || updateError.HTTPStatus != http.StatusForbidden {
		t.Fatalf("missing exact policy digest in MFA challenge: %#v", updateError)
	}
}

func TestSecurityConfirmationIsRemovedBeforeAnyProviderFlow(t *testing.T) {
	config := oidcConfigForPolicyTest(true, "restricted", oidcIdentity("oidc_user", "alice"))
	config.SecurityConfirmation = "one-time-ticket"

	confirmation := detachSecurityConfirmation(&config)

	if confirmation != "one-time-ticket" {
		t.Fatalf("request-scoped confirmation was not captured: %q", confirmation)
	}
	if config.SecurityConfirmation != "" {
		t.Fatal("request-scoped confirmation remained on the persistable configuration")
	}
}

func TestPolicyOnlyUpdateClearsStoredAllowlistWithoutDiscovery(t *testing.T) {
	discoveryRequests := 0
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		discoveryRequests++
		response.WriteHeader(http.StatusInternalServerError)
	}))
	defer discoveryServer.Close()

	settings := map[string]string{
		allowedIdentitiesSetting:         "oidc_user:alice#oidc#oidc_group:operators",
		accessModeSetting:                "restricted",
		securitySetting:                  "true",
		authServiceConfigUpdateTimestamp: "unchanged-provider-reload-generation",
		userTypeSetting:                  "legacy_user",
		identitySeparatorSetting:         "#legacy#",
		noIdentityLookupSupportedSetting: "false",
		providerNameSetting:              "legacyconfig",
		providerSetting:                  "legacyconfig",
		externalProviderSetting:          "false",
	}
	var writes []string
	var platformServer *httptest.Server
	platformServer = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && request.URL.Path == "/v2-beta" {
			response.Header().Set("X-API-Schemas", platformServer.URL+"/v2-beta")
			_, _ = fmt.Fprintf(response, `{"data":[{"id":"setting","type":"schema","pluralName":"settings","collectionMethods":["GET"],"resourceMethods":["GET","PUT"],"links":{"collection":%q}}]}`,
				platformServer.URL+"/v2-beta/settings")
			return
		}
		prefix := "/v2-beta/settings/"
		if !strings.HasPrefix(request.URL.Path, prefix) {
			http.Error(response, "unexpected platform path", http.StatusNotFound)
			return
		}
		name := strings.TrimPrefix(request.URL.Path, prefix)
		if request.Method == http.MethodGet {
			_, _ = fmt.Fprintf(response, `{"id":%q,"type":"setting","activeValue":%q,"value":%q,"links":{"self":%q}}`,
				name, settings[name], settings[name], platformServer.URL+request.URL.Path)
			return
		}
		if request.Method == http.MethodPut {
			var update map[string]interface{}
			if err := json.NewDecoder(request.Body).Decode(&update); err != nil {
				t.Fatal(err)
			}
			rawValue, present := update["value"]
			value, stringValue := rawValue.(string)
			if !present || !stringValue {
				t.Errorf("setting update omitted an explicit string value: %#v", update)
				http.Error(response, "missing explicit setting value", http.StatusUnprocessableEntity)
				return
			}
			settings[name] = value
			writes = append(writes, name)
			_, _ = fmt.Fprintf(response, `{"id":%q,"type":"setting","activeValue":%q,"value":%q,"links":{"self":%q}}`,
				name, value, value, platformServer.URL+request.URL.Path)
			return
		}
		http.Error(response, "unexpected platform method", http.StatusMethodNotAllowed)
	}))
	defer platformServer.Close()

	platformClient, err := newPlatformClient(platformServer.URL, "access", "secret")
	if err != nil {
		t.Fatal(err)
	}
	previousPlatformClient := PlatformClient
	previousRefreshChannel := refreshReqChannel
	previousConfig := authConfigInMemory
	PlatformClient = platformClient
	refreshReqChannel = nil
	defer func() {
		PlatformClient = previousPlatformClient
		refreshReqChannel = previousRefreshChannel
		authConfigInMemory = previousConfig
	}()

	current := oidcConfigForPolicyTest(true, "restricted", oidcIdentity("oidc_user", "alice"))
	current.OIDCConfig.WellKnownURL = discoveryServer.URL + "/.well-known/openid-configuration"
	requested := current
	requested.AccessMode = "unrestricted"
	requested.AllowedIdentities = []client.Identity{oidcIdentity("oidc_user", "stale")}
	if err := normalizeOIDCAccessPolicy(&requested, true); err != nil {
		t.Fatal(err)
	}
	if err := updateOIDCConfigWithoutInitialization(current, requested); err != nil {
		t.Fatal(err)
	}

	if discoveryRequests != 0 {
		t.Fatalf("policy-only update performed %d OIDC discovery requests", discoveryRequests)
	}
	if settings[allowedIdentitiesSetting] != "" {
		t.Fatalf("stored allowlist was not cleared: %q", settings[allowedIdentitiesSetting])
	}
	expectedPrefix := []string{
		userTypeSetting,
		identitySeparatorSetting,
		noIdentityLookupSupportedSetting,
		providerNameSetting,
		providerSetting,
		externalProviderSetting,
		allowedIdentitiesSetting,
		accessModeSetting,
		securitySetting,
	}
	if len(writes) != len(expectedPrefix) {
		t.Fatalf("unexpected OIDC repair/policy writes: %#v", writes)
	}
	for index, expected := range expectedPrefix {
		if writes[index] != expected {
			t.Fatalf("OIDC settings were not repaired in fail-closed order: got %#v, expected %#v", writes, expectedPrefix)
		}
	}
	for key, expected := range map[string]string{
		userTypeSetting:                  "oidc_user",
		identitySeparatorSetting:         "#oidc#",
		noIdentityLookupSupportedSetting: "true",
		providerNameSetting:              "oidcconfig",
		providerSetting:                  "oidcconfig",
		externalProviderSetting:          "true",
	} {
		if settings[key] != expected {
			t.Fatalf("OIDC platform contract setting %s = %q, expected %q", key, settings[key], expected)
		}
	}
	for _, setting := range writes {
		if setting == authServiceConfigUpdateTimestamp {
			t.Fatalf("policy-only update signalled an external provider reload: %#v", writes)
		}
	}
	if settings[authServiceConfigUpdateTimestamp] != "unchanged-provider-reload-generation" {
		t.Fatalf("policy-only update changed the provider reload generation: %q",
			settings[authServiceConfigUpdateTimestamp])
	}
	reread, err := readCommonSettings([]string{allowedIdentitiesSetting, accessModeSetting})
	if err != nil {
		t.Fatal(err)
	}
	if reread[allowedIdentitiesSetting] != "" || reread[accessModeSetting] != "unrestricted" {
		t.Fatalf("stored policy did not round-trip after clearing: %#v", reread)
	}
}

func TestOIDCCommonSettingReconciliationIsIdempotentAndDoesNotTouchPolicy(t *testing.T) {
	settings := map[string]string{
		userTypeSetting:                  "oidc_user",
		identitySeparatorSetting:         "#oidc#",
		noIdentityLookupSupportedSetting: "true",
		providerNameSetting:              "oidcconfig",
		providerSetting:                  "oidcconfig",
		externalProviderSetting:          "true",
		allowedIdentitiesSetting:         "oidc_group:operators",
		accessModeSetting:                "restricted",
		securitySetting:                  "true",
	}
	var writes []string
	var platformServer *httptest.Server
	platformServer = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && request.URL.Path == "/v2-beta" {
			response.Header().Set("X-API-Schemas", platformServer.URL+"/v2-beta")
			_, _ = fmt.Fprintf(response, `{"data":[{"id":"setting","type":"schema","pluralName":"settings","collectionMethods":["GET"],"resourceMethods":["GET","PUT"],"links":{"collection":%q}}]}`,
				platformServer.URL+"/v2-beta/settings")
			return
		}
		const prefix = "/v2-beta/settings/"
		if !strings.HasPrefix(request.URL.Path, prefix) {
			http.Error(response, "unexpected platform path", http.StatusNotFound)
			return
		}
		name := strings.TrimPrefix(request.URL.Path, prefix)
		switch request.Method {
		case http.MethodGet:
			_, _ = fmt.Fprintf(response, `{"id":%q,"type":"setting","activeValue":%q,"value":%q,"links":{"self":%q}}`,
				name, settings[name], settings[name], platformServer.URL+request.URL.Path)
		case http.MethodPut:
			writes = append(writes, name)
			http.Error(response, "an aligned setting must not be rewritten", http.StatusInternalServerError)
		default:
			http.Error(response, "unexpected platform method", http.StatusMethodNotAllowed)
		}
	}))
	defer platformServer.Close()

	platformClient, err := newPlatformClient(platformServer.URL, "access", "secret")
	if err != nil {
		t.Fatal(err)
	}
	previousPlatformClient := PlatformClient
	PlatformClient = platformClient
	defer func() { PlatformClient = previousPlatformClient }()

	if err := reconcileOIDCCommonSettings(oidcConfigForPolicyTest(true, "restricted")); err != nil {
		t.Fatal(err)
	}
	if len(writes) != 0 {
		t.Fatalf("idempotent reconciliation rewrote aligned settings: %#v", writes)
	}
	if settings[allowedIdentitiesSetting] != "oidc_group:operators" ||
		settings[accessModeSetting] != "restricted" || settings[securitySetting] != "true" {
		t.Fatalf("reconciliation touched access policy: %#v", settings)
	}
}

func TestUpgradeSettingsDoesNotReplayLegacyMigrationAfterCanonicalConfigExists(t *testing.T) {
	genericObjectReads := 0
	settingRequests := 0
	var platformServer *httptest.Server
	platformServer = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v2-beta":
			response.Header().Set("X-API-Schemas", platformServer.URL+"/v2-beta")
			_, _ = fmt.Fprintf(response, `{"data":[{"id":"genericObject","type":"schema","pluralName":"genericObjects","collectionMethods":["GET"],"resourceMethods":["GET","PUT"],"links":{"collection":%q}},{"id":"setting","type":"schema","pluralName":"settings","collectionMethods":["GET"],"resourceMethods":["GET","PUT"],"links":{"collection":%q}}]}`,
				platformServer.URL+"/v2-beta/genericObjects", platformServer.URL+"/v2-beta/settings")
		case request.Method == http.MethodGet && request.URL.Path == "/v2-beta/genericObjects":
			genericObjectReads++
			_, _ = fmt.Fprint(response, `{"type":"collection","resourceType":"genericObject","data":[{"id":"1go1","type":"genericObject","key":"auth.config","name":"auth.config","kind":"authConfig","resourceData":{}}]}`)
		case strings.HasPrefix(request.URL.Path, "/v2-beta/settings"):
			settingRequests++
			http.Error(response, "legacy settings must not be read after migration", http.StatusInternalServerError)
		default:
			t.Errorf("unexpected platform request %s %s", request.Method, request.URL.String())
			http.Error(response, "unexpected request", http.StatusNotFound)
		}
	}))
	defer platformServer.Close()

	platformClient, err := newPlatformClient(platformServer.URL, "access", "secret")
	if err != nil {
		t.Fatal(err)
	}
	previousPlatformClient := PlatformClient
	PlatformClient = platformClient
	defer func() { PlatformClient = previousPlatformClient }()

	if err := UpgradeSettings(); err != nil {
		t.Fatal(err)
	}
	if genericObjectReads != 1 {
		t.Fatalf("expected one canonical config lookup, got %d", genericObjectReads)
	}
	if settingRequests != 0 {
		t.Fatalf("legacy settings were touched %d times after migration", settingRequests)
	}
}

func oidcConfigForPolicyTest(enabled bool, accessMode string, identities ...client.Identity) model.AuthConfig {
	return model.AuthConfig{
		Provider:          oidcProviderName,
		Enabled:           enabled,
		AccessMode:        accessMode,
		AllowedIdentities: identities,
		OIDCConfig: model.OIDCConfig{
			DisplayName:      "Company login",
			WellKnownURL:     "https://id.example/.well-known/openid-configuration",
			ClientID:         "client",
			ClientSecret:     "secret",
			ClientSecretSet:  true,
			Scopes:           "openid email",
			UsePKCE:          true,
			UsernameClaim:    "username",
			DisplayNameClaim: "name",
			EmailClaim:       "email",
			GroupsClaim:      "groups",
		},
	}
}

func oidcIdentity(identityType string, externalID string) client.Identity {
	return client.Identity{ExternalIdType: identityType, ExternalId: externalID}
}

func assertConfigUpdateError(t *testing.T, err error, code string) *ConfigUpdateError {
	t.Helper()
	updateError, ok := err.(*ConfigUpdateError)
	if !ok || updateError.Code != code {
		t.Fatalf("got error %#v, expected ConfigUpdateError %s", err, code)
	}
	return updateError
}
