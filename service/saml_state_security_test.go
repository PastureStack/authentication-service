package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PastureStack/authentication-service/model"
	"github.com/PastureStack/authentication-service/server"
	"github.com/crewjam/saml"
	"github.com/golang-jwt/jwt/v5"
)

func validSAMLStateClaims(now time.Time, relayState string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": samlStateIssuer,
		"aud": samlStateAudience,
		"iat": now.Unix(),
		"nbf": now.Add(-time.Second).Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"jti": relayState,
		"id":  "request-id",
		"uri": "/v1-auth/saml/login?redirectBackBase=https%3A%2F%2Fconsole.example&redirectBackPath=%2Flogin%2Fshibboleth-auth",
	}
}

func TestSAMLStateSigningSecretIsStableAndKeySpecific(t *testing.T) {
	firstKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate first signing key: %v", err)
	}
	secondKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate second signing key: %v", err)
	}

	firstSecret, err := samlStateSigningSecret(firstKey)
	if err != nil {
		t.Fatalf("derive first secret: %v", err)
	}
	repeatedSecret, err := samlStateSigningSecret(firstKey)
	if err != nil {
		t.Fatalf("derive repeated secret: %v", err)
	}
	secondSecret, err := samlStateSigningSecret(secondKey)
	if err != nil {
		t.Fatalf("derive second secret: %v", err)
	}

	if len(firstSecret) != 32 {
		t.Fatalf("unexpected secret length %d", len(firstSecret))
	}
	if !bytes.Equal(firstSecret, repeatedSecret) {
		t.Fatal("the same signing key must derive the same state secret")
	}
	if bytes.Equal(firstSecret, secondSecret) {
		t.Fatal("different signing keys must not derive the same state secret")
	}
}

func TestSAMLStateRejectsMissingKeyAndTampering(t *testing.T) {
	if _, err := samlStateSigningSecret(nil); err == nil {
		t.Fatal("a missing signing key must be rejected")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	secret, err := samlStateSigningSecret(key)
	if err != nil {
		t.Fatalf("derive signing secret: %v", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, validSAMLStateClaims(time.Now().UTC(), "relay"))
	signed, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("sign state token: %v", err)
	}
	claims, err := parseSamlState(signed, secret)
	if err != nil {
		t.Fatalf("parse valid state token: %v", err)
	}
	if value, ok := stringClaim(claims, "id"); !ok || value != "request-id" {
		t.Fatalf("unexpected request id claim: %#v", claims["id"])
	}

	parts := strings.Split(signed, ".")
	if len(parts) != 3 || len(parts[1]) == 0 {
		t.Fatalf("unexpected signed token format %q", signed)
	}
	replacement := "A"
	if parts[1][0] == 'A' {
		replacement = "B"
	}
	parts[1] = replacement + parts[1][1:]
	tampered := strings.Join(parts, ".")
	if _, err := parseSamlState(tampered, secret); err == nil {
		t.Fatal("a tampered state token must be rejected")
	}

	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"id": "request-id"})
	unsignedString, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("build unsigned token: %v", err)
	}
	if _, err := parseSamlState(unsignedString, secret); err == nil {
		t.Fatal("an unsigned state token must be rejected")
	}
}

func TestSAMLStateRejectsExpiredOrWrongContext(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	secret, err := samlStateSigningSecret(key)
	if err != nil {
		t.Fatalf("derive signing secret: %v", err)
	}
	for name, mutate := range map[string]func(jwt.MapClaims){
		"expired": func(claims jwt.MapClaims) { claims["exp"] = time.Now().Add(-time.Minute).Unix() },
		"issuer":  func(claims jwt.MapClaims) { claims["iss"] = "unexpected" },
		"audience": func(claims jwt.MapClaims) {
			claims["aud"] = "unexpected"
		},
		"missing expiration": func(claims jwt.MapClaims) { delete(claims, "exp") },
	} {
		t.Run(name, func(t *testing.T) {
			claims := validSAMLStateClaims(time.Now().UTC(), "relay")
			mutate(claims)
			signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
			if err != nil {
				t.Fatalf("sign state: %v", err)
			}
			if _, err := parseSamlState(signed, secret); err == nil {
				t.Fatal("invalid state context was accepted")
			}
		})
	}
}

type testSAMLStateStore struct {
	states   map[string]string
	setID    string
	setValue string
	deleted  string
}

func (s *testSAMLStateStore) SetState(_ http.ResponseWriter, _ *http.Request, id string, value string) {
	s.setID = id
	s.setValue = value
	if s.states == nil {
		s.states = map[string]string{}
	}
	s.states[id] = value
}
func (s *testSAMLStateStore) GetStates(*http.Request) map[string]string  { return s.states }
func (s *testSAMLStateStore) GetState(_ *http.Request, id string) string { return s.states[id] }
func (s *testSAMLStateStore) DeleteState(_ http.ResponseWriter, _ *http.Request, id string) error {
	s.deleted = id
	return nil
}

func TestSAMLRedirectStateIsBoundAndConsumed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	secret, err := samlStateSigningSecret(key)
	if err != nil {
		t.Fatalf("derive signing secret: %v", err)
	}
	stateID := "relay"
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, validSAMLStateClaims(time.Now().UTC(), stateID)).SignedString(secret)
	if err != nil {
		t.Fatalf("sign state: %v", err)
	}
	store := &testSAMLStateStore{states: map[string]string{stateID: signed}}
	provider := &model.PlatformSamlServiceProvider{
		ServiceProvider: saml.ServiceProvider{Key: key},
		ClientState:     store,
	}
	form := url.Values{"RelayState": {stateID}}
	request := httptest.NewRequest(http.MethodPost, "/v1-auth/saml/acs", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()

	base, path, err := GetRedirectParams(recorder, request, provider)
	if err != nil {
		t.Fatalf("get redirect params: %v", err)
	}
	if base != "https://console.example" || path != defaultSAMLPath {
		t.Fatalf("unexpected redirect %q %q", base, path)
	}
	if store.deleted != stateID {
		t.Fatalf("state was not consumed: %q", store.deleted)
	}
}

func TestSAMLRedirectStateRejectsMissingAndMismatchedState(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	secret, err := samlStateSigningSecret(key)
	if err != nil {
		t.Fatalf("derive signing secret: %v", err)
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, validSAMLStateClaims(time.Now().UTC(), "different")).SignedString(secret)
	if err != nil {
		t.Fatalf("sign state: %v", err)
	}
	store := &testSAMLStateStore{states: map[string]string{"relay": signed}}
	provider := &model.PlatformSamlServiceProvider{ServiceProvider: saml.ServiceProvider{Key: key}, ClientState: store}

	for name, form := range map[string]url.Values{
		"missing":    {},
		"mismatched": {"RelayState": {"relay"}},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1-auth/saml/acs", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if _, _, err := GetRedirectParams(httptest.NewRecorder(), request, provider); err == nil {
				t.Fatal("invalid RelayState was accepted")
			}
		})
	}
	if store.deleted != "" {
		t.Fatal("invalid state must not be consumed")
	}
}

func newTestSAMLRuntime(t *testing.T, store *testSAMLStateStore) *model.PlatformSamlServiceProvider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return &model.PlatformSamlServiceProvider{
		ServiceProvider: saml.ServiceProvider{
			Key:         key,
			MetadataURL: url.URL{Scheme: "https", Host: "platform.example", Path: "/v1-auth/saml/metadata"},
			AcsURL:      url.URL{Scheme: "https", Host: "platform.example", Path: "/v1-auth/saml/acs"},
			IDPMetadata: &saml.EntityDescriptor{
				EntityID: "https://idp.example/metadata",
				IDPSSODescriptors: []saml.IDPSSODescriptor{{
					SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: "https://idp.example/sso"}},
				}},
			},
		},
		ClientState:       store,
		RedirectWhitelist: "console.example",
	}
}

func signTestSAMLState(t *testing.T, provider *model.PlatformSamlServiceProvider, relayState string) string {
	t.Helper()
	secret, err := samlStateSigningSecret(provider.ServiceProvider.Key)
	if err != nil {
		t.Fatalf("derive SAML state secret: %v", err)
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, validSAMLStateClaims(time.Now().UTC(), relayState)).SignedString(secret)
	if err != nil {
		t.Fatalf("sign SAML state: %v", err)
	}
	return signed
}

func TestHandleSamlLoginRejectsUnsafeInputsAndCreatesBoundState(t *testing.T) {
	previousProvider := server.SamlServiceProvider
	previousPlatformClient := server.PlatformClient
	server.PlatformClient = nil
	t.Cleanup(func() {
		server.SamlServiceProvider = previousProvider
		server.PlatformClient = previousPlatformClient
	})

	server.SamlServiceProvider = nil
	unavailable := httptest.NewRecorder()
	HandleSamlLogin(unavailable, httptest.NewRequest(http.MethodGet, "/v1-auth/saml/login", nil))
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured login returned %d", unavailable.Code)
	}

	store := &testSAMLStateStore{states: map[string]string{}}
	provider := newTestSAMLRuntime(t, store)
	server.SamlServiceProvider = provider
	wrongMethod := httptest.NewRecorder()
	HandleSamlLogin(wrongMethod, httptest.NewRequest(http.MethodPost, "/v1-auth/saml/login", nil))
	if wrongMethod.Code != http.StatusMethodNotAllowed || wrongMethod.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("unexpected method response: %d %q", wrongMethod.Code, wrongMethod.Header().Get("Allow"))
	}

	unsafeQuery := url.Values{
		redirectBackBase: {"https://attacker.example"},
		redirectBackPath: {"//attacker.example/login"},
	}
	unsafe := httptest.NewRecorder()
	HandleSamlLogin(unsafe, httptest.NewRequest(http.MethodGet, "/v1-auth/saml/login?"+unsafeQuery.Encode(), nil))
	if unsafe.Code != http.StatusFound || unsafe.Header().Get("Location") != "http://localhost:8080/login/shibboleth-auth?errCode=422" {
		t.Fatalf("unsafe login redirect was not contained: %d %q", unsafe.Code, unsafe.Header().Get("Location"))
	}

	safeQuery := url.Values{
		redirectBackBase: {"https://console.example"},
		redirectBackPath: {defaultSAMLPath},
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1-auth/saml/login?"+safeQuery.Encode(), nil)
	HandleSamlLogin(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected SAML login response: %d %#v", response.Code, response.Header())
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Scheme != "https" || location.Host != "idp.example" || location.Path != "/sso" {
		t.Fatalf("unexpected IDP redirect %q: %v", response.Header().Get("Location"), err)
	}
	if location.Query().Get("RelayState") == "" || location.Query().Get("RelayState") != store.setID || store.setValue == "" {
		t.Fatalf("SAML request was not bound to stored RelayState: %#v", store)
	}
	secret, err := samlStateSigningSecret(provider.ServiceProvider.Key)
	if err != nil {
		t.Fatalf("derive state secret: %v", err)
	}
	claims, err := parseSamlState(store.setValue, secret)
	if err != nil {
		t.Fatalf("parse stored state: %v", err)
	}
	if claims["jti"] != store.setID || claims["uri"] != request.URL.RequestURI() {
		t.Fatalf("stored state does not bind the request: %#v", claims)
	}
}

func TestServeHTTPSAMLRoutesAndPendingRequestValidation(t *testing.T) {
	previousProvider := server.SamlServiceProvider
	store := &testSAMLStateStore{states: map[string]string{}}
	provider := newTestSAMLRuntime(t, store)
	server.SamlServiceProvider = provider
	t.Cleanup(func() { server.SamlServiceProvider = previousProvider })

	metadata := httptest.NewRecorder()
	ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, "/v1-auth/saml/metadata", nil))
	if metadata.Code != http.StatusOK || metadata.Header().Get("Content-Type") != "application/samlmetadata+xml" || metadata.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected metadata response: %d %#v", metadata.Code, metadata.Header())
	}

	for name, request := range map[string]*http.Request{
		"metadata method": httptest.NewRequest(http.MethodPost, "/v1-auth/saml/metadata", nil),
		"acs method":      httptest.NewRequest(http.MethodGet, "/v1-auth/saml/acs", nil),
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ServeHTTP(recorder, request)
			if recorder.Code != http.StatusMethodNotAllowed {
				t.Fatalf("unexpected method status %d", recorder.Code)
			}
		})
	}

	missingState := httptest.NewRecorder()
	acsRequest := httptest.NewRequest(http.MethodPost, "/v1-auth/saml/acs", strings.NewReader("SAMLResponse=invalid"))
	acsRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ServeHTTP(missingState, acsRequest)
	if missingState.Code != http.StatusForbidden {
		t.Fatalf("ACS accepted a response without pending state: %d", missingState.Code)
	}

	notFound := httptest.NewRecorder()
	ServeHTTP(notFound, httptest.NewRequest(http.MethodGet, "/v1-auth/saml/unknown", nil))
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("unknown SAML route returned %d", notFound.Code)
	}
}

func TestPendingRequestIDAndAssertionFailurePaths(t *testing.T) {
	previousPlatformClient := server.PlatformClient
	server.PlatformClient = nil
	t.Cleanup(func() { server.PlatformClient = previousPlatformClient })

	store := &testSAMLStateStore{states: map[string]string{}}
	provider := newTestSAMLRuntime(t, store)
	store.states["relay"] = signTestSAMLState(t, provider, "relay")
	form := url.Values{"RelayState": {"relay"}}
	request := httptest.NewRequest(http.MethodPost, "/v1-auth/saml/acs", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ids := getPossibleRequestIDs(request, provider)
	if len(ids) != 1 || ids[0] != "request-id" {
		t.Fatalf("unexpected pending request IDs: %#v", ids)
	}

	nilAssertion := httptest.NewRecorder()
	HandleSamlAssertion(nilAssertion, request, nil, provider)
	if nilAssertion.Code != http.StatusForbidden {
		t.Fatalf("nil assertion returned %d", nilAssertion.Code)
	}

	invalidState := httptest.NewRecorder()
	invalidRequest := httptest.NewRequest(http.MethodPost, "/v1-auth/saml/acs", strings.NewReader("RelayState=missing"))
	invalidRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	HandleSamlAssertion(invalidState, invalidRequest, &saml.Assertion{}, provider)
	if invalidState.Code != http.StatusFound || !strings.Contains(invalidState.Header().Get("Location"), "errCode=403") {
		t.Fatalf("invalid state was not rejected safely: %d %q", invalidState.Code, invalidState.Header().Get("Location"))
	}

	store.states["relay-2"] = signTestSAMLState(t, provider, "relay-2")
	validForm := url.Values{"RelayState": {"relay-2"}}
	validRequest := httptest.NewRequest(http.MethodPost, "/v1-auth/saml/acs", strings.NewReader(validForm.Encode()))
	validRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	noPlatform := httptest.NewRecorder()
	HandleSamlAssertion(noPlatform, validRequest, &saml.Assertion{}, provider)
	if noPlatform.Code != http.StatusFound || !strings.Contains(noPlatform.Header().Get("Location"), "errCode=503") {
		t.Fatalf("missing platform client was not handled safely: %d %q", noPlatform.Code, noPlatform.Header().Get("Location"))
	}
	if store.deleted != "relay-2" {
		t.Fatalf("validated state was not consumed: %q", store.deleted)
	}
}

func TestRandomBytesRejectsInvalidSizesAndPropagatesEntropyFailure(t *testing.T) {
	for _, size := range []int{0, -1, 4097} {
		if _, err := randomBytes(size); err == nil {
			t.Fatalf("invalid random byte count %d was accepted", size)
		}
	}
	value, err := randomBytes(32)
	if err != nil || len(value) != 32 {
		t.Fatalf("secure random generation failed: %d %v", len(value), err)
	}
	previousReader := saml.RandReader
	saml.RandReader = strings.NewReader("")
	t.Cleanup(func() { saml.RandReader = previousReader })
	if _, err := randomBytes(32); err == nil {
		t.Fatal("entropy source failure was ignored")
	}
}
