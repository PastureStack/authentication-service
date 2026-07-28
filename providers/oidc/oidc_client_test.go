package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PastureStack/authentication-service/model"
	"github.com/golang-jwt/jwt/v5"
)

type mockProvider struct {
	server            *httptest.Server
	key               *rsa.PrivateKey
	issuer            string
	issuedNonce       string
	idTokenIssuer     string
	userInfoSubject   string
	expectedVerifier  string
	expectedRedirect  string
	tokenRequestCount int
	omitIssuedAt      bool
}

func newMockProvider(t *testing.T) *mockProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	mock := &mockProvider{
		key:              key,
		issuedNonce:      strings.Repeat("n", 43),
		userInfoSubject:  "subject-123",
		expectedVerifier: strings.Repeat("v", 43),
		expectedRedirect: "https://platform.example/login/oidc-auth",
	}
	mux := http.NewServeMux()
	mock.server = httptest.NewServer(mux)
	mock.issuer = mock.server.URL
	mock.idTokenIssuer = mock.issuer

	mux.HandleFunc("/.well-known/openid-configuration", mock.discovery)
	mux.HandleFunc("/jwks", mock.jwks)
	mux.HandleFunc("/token", mock.token)
	mux.HandleFunc("/userinfo", mock.userInfo)
	t.Cleanup(mock.server.Close)
	return mock
}

func (m *mockProvider) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"issuer":                                         m.issuer,
		"authorization_endpoint":                         m.server.URL + "/authorize",
		"token_endpoint":                                 m.server.URL + "/token",
		"userinfo_endpoint":                              m.server.URL + "/userinfo",
		"jwks_uri":                                       m.server.URL + "/jwks",
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (m *mockProvider) jwks(w http.ResponseWriter, r *http.Request) {
	exponent := big.NewInt(int64(m.key.PublicKey.E)).Bytes()
	w.Header().Set("Cache-Control", "public, max-age=120")
	writeJSON(w, map[string]interface{}{
		"keys": []map[string]interface{}{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": "test-key",
			"n":   base64.RawURLEncoding.EncodeToString(m.key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(exponent),
		}},
	})
}

func (m *mockProvider) token(w http.ResponseWriter, r *http.Request) {
	m.tokenRequestCount++
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok || clientID != "client-id" || clientSecret != "client-secret" {
		http.Error(w, "invalid client credentials", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" ||
		r.Form.Get("code") != "authorization-code" ||
		r.Form.Get("code_verifier") != m.expectedVerifier ||
		r.Form.Get("redirect_uri") != m.expectedRedirect {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}

	accessToken := "access-token"
	hash := sha256.Sum256([]byte(accessToken))
	atHash := base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])
	claims := jwt.MapClaims{
		"iss":                m.idTokenIssuer,
		"aud":                "client-id",
		"sub":                "subject-123",
		"exp":                time.Now().Add(5 * time.Minute).Unix(),
		"nonce":              m.issuedNonce,
		"at_hash":            atHash,
		"preferred_username": "person",
		"name":               "Test Person",
		"groups":             []string{"operators", "reviewers"},
		"amr":                []string{"pwd", "mfa"},
		"acr":                "urn:example:aal2",
		"auth_time":          time.Now().Add(-time.Minute).Unix(),
	}
	if !m.omitIssuedAt {
		claims["iat"] = time.Now().Unix()
	}
	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	idToken.Header["kid"] = "test-key"
	signed, err := idToken.SignedString(m.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{
		"access_token": accessToken,
		"id_token":     signed,
		"token_type":   "Bearer",
	})
}

func (m *mockProvider) userInfo(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer access-token" {
		http.Error(w, "invalid bearer token", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]interface{}{
		"sub":                m.userInfoSubject,
		"preferred_username": "person",
		"name":               "Test Person",
		"picture":            "https://identity.example/avatar.png",
		"groups":             []string{"operators", "reviewers"},
		"amr":                []string{"pwd"},
		"acr":                "untrusted-userinfo-value",
		"auth_time":          1,
	})
}

func writeJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func testConfig(mock *mockProvider) model.AuthConfig {
	return model.AuthConfig{
		Provider: Config,
		OIDCConfig: model.OIDCConfig{
			DisplayName:      "Company Login",
			WellKnownURL:     mock.server.URL + "/.well-known/openid-configuration",
			ClientID:         "client-id",
			ClientSecret:     "client-secret",
			Scopes:           "openid profile email",
			UsePKCE:          true,
			UsernameClaim:    "preferred_username",
			DisplayNameClaim: "name",
			EmailClaim:       "email",
			GroupsClaim:      "groups",
			PlatformAPIHost:  "https://platform.example",
		},
	}
}

func testAuthorizationPayload(mock *mockProvider) map[string]string {
	payload, _ := json.Marshal(authorizationResponse{
		AuthorizationCode: "authorization-code",
		CodeVerifier:      mock.expectedVerifier,
		Nonce:             mock.issuedNonce,
	})
	return map[string]string{"code": string(payload)}
}

func TestAuthorizationCodeFlow(t *testing.T) {
	mock := newMockProvider(t)
	provider, err := InitializeProvider()
	if err != nil {
		t.Fatal(err)
	}
	config := testConfig(mock)
	if err := provider.LoadConfig(&config); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	redirect, err := url.Parse(provider.GetRedirectURL())
	if err != nil {
		t.Fatal(err)
	}
	query := redirect.Query()
	if redirect.Path != "/authorize" ||
		query.Get("client_id") != "client-id" ||
		query.Get("response_type") != "code" ||
		query.Get("scope") != "openid profile email" ||
		query.Get("redirect_uri") != mock.expectedRedirect {
		t.Fatalf("unexpected authorization URL: %s", redirect.String())
	}
	if strings.Contains(redirect.String(), "client-secret") {
		t.Fatal("client secret leaked into the authorization URL")
	}

	token, status, err := provider.GenerateToken(testAuthorizationPayload(mock))
	if err != nil || status != 0 {
		t.Fatalf("GenerateToken failed with status %d: %v", status, err)
	}
	if token.AccessToken != "access-token" || token.ExternalAccountID != mock.issuer+"|subject-123" {
		t.Fatalf("unexpected token: %#v", token)
	}
	if len(token.IdentityList) != 3 {
		t.Fatalf("expected one user and two groups, got %d identities", len(token.IdentityList))
	}
	if len(token.AuthenticationMethods) != 2 ||
		token.AuthenticationMethods[1] != "mfa" ||
		token.AuthenticationContext != "urn:example:aal2" ||
		token.AuthenticatedAt <= 1 ||
		token.AuthenticationIssuer != mock.issuer {
		t.Fatalf("verified authentication evidence was not preserved: %#v", token)
	}
	if token.IdentityList[0].Name != "Test Person" ||
		token.IdentityList[0].ExternalId != mock.issuer+"|subject-123" ||
		token.IdentityList[1].ExternalId != mock.issuer+"|operators" {
		t.Fatalf("unexpected identities: %#v", token.IdentityList)
	}
	if mock.tokenRequestCount != 1 {
		t.Fatalf("expected one token request, got %d", mock.tokenRequestCount)
	}
}

func TestRejectsNonceMismatch(t *testing.T) {
	mock := newMockProvider(t)
	provider, _ := InitializeProvider()
	config := testConfig(mock)
	if err := provider.LoadConfig(&config); err != nil {
		t.Fatal(err)
	}
	payload := testAuthorizationPayload(mock)
	mock.issuedNonce = strings.Repeat("x", 43)

	_, status, err := provider.GenerateToken(payload)
	if err == nil || status != http.StatusUnauthorized || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("expected nonce rejection, got status %d, err %v", status, err)
	}
}

func TestRejectsIssuerMismatch(t *testing.T) {
	mock := newMockProvider(t)
	provider, _ := InitializeProvider()
	config := testConfig(mock)
	if err := provider.LoadConfig(&config); err != nil {
		t.Fatal(err)
	}
	mock.idTokenIssuer = "https://attacker.invalid"

	_, status, err := provider.GenerateToken(testAuthorizationPayload(mock))
	if err == nil || status != http.StatusUnauthorized {
		t.Fatalf("expected issuer rejection, got status %d, err %v", status, err)
	}
}

func TestRejectsMissingIssuedAt(t *testing.T) {
	mock := newMockProvider(t)
	provider, _ := InitializeProvider()
	config := testConfig(mock)
	if err := provider.LoadConfig(&config); err != nil {
		t.Fatal(err)
	}
	mock.omitIssuedAt = true

	_, status, err := provider.GenerateToken(testAuthorizationPayload(mock))
	if err == nil || status != http.StatusUnauthorized || !strings.Contains(err.Error(), "iat") {
		t.Fatalf("expected iat rejection, got status %d, err %v", status, err)
	}
}

func TestRejectsUserInfoSubjectMismatch(t *testing.T) {
	mock := newMockProvider(t)
	provider, _ := InitializeProvider()
	config := testConfig(mock)
	if err := provider.LoadConfig(&config); err != nil {
		t.Fatal(err)
	}
	mock.userInfoSubject = "different-subject"

	_, status, err := provider.GenerateToken(testAuthorizationPayload(mock))
	if err == nil || status != http.StatusUnauthorized || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("expected UserInfo subject rejection, got status %d, err %v", status, err)
	}
}

func TestRejectsInvalidPKCEVerifierBeforeNetwork(t *testing.T) {
	mock := newMockProvider(t)
	provider, _ := InitializeProvider()
	config := testConfig(mock)
	if err := provider.LoadConfig(&config); err != nil {
		t.Fatal(err)
	}
	payload := testAuthorizationPayload(mock)
	payload["code"] = fmt.Sprintf(`{"authorizationCode":"authorization-code","codeVerifier":"short","nonce":"%s"}`, mock.issuedNonce)

	_, status, err := provider.GenerateToken(payload)
	if err == nil || status != http.StatusBadRequest || mock.tokenRequestCount != 0 {
		t.Fatalf("expected local PKCE rejection, got status %d, requests %d, err %v", status, mock.tokenRequestCount, err)
	}
}

func TestRejectsNonHTTPSDiscovery(t *testing.T) {
	provider, _ := InitializeProvider()
	config := model.AuthConfig{
		Provider: Config,
		OIDCConfig: model.OIDCConfig{
			WellKnownURL: "http://identity.example/.well-known/openid-configuration",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			Scopes:       "openid",
			UsePKCE:      true,
		},
	}
	if err := provider.LoadConfig(&config); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS validation error, got %v", err)
	}
}

func TestJWKSelectionRejectsAmbiguousKeyWithoutKid(t *testing.T) {
	keys := []jwk{
		{KeyID: "one", KeyType: "RSA", Algorithm: "RS256", Use: "sig"},
		{KeyID: "two", KeyType: "RSA", Algorithm: "RS256", Use: "sig"},
	}
	if _, found := selectJWK(keys, "", "RS256"); found {
		t.Fatal("ambiguous JWK set must not select a key without kid")
	}
}
