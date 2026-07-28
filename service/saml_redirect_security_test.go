package service

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/PastureStack/authentication-service/model"
	"github.com/PastureStack/authentication-service/server"
)

func TestRedirectWhitelistUsesExactHosts(t *testing.T) {
	for name, test := range map[string]struct {
		target    string
		whitelist string
		allowed   bool
	}{
		"exact hostname":          {"https://console.example", "console.example", true},
		"hostname with port":      {"https://console.example:8443", "console.example", false},
		"hostname with default":   {"https://console.example:443", "console.example", true},
		"explicit bare host port": {"https://console.example:8443", "console.example:8443", true},
		"exact origin":            {"https://console.example:8443", "https://console.example:8443", true},
		"wrong origin port":       {"https://console.example:8443", "https://console.example", false},
		"suffix impersonation":    {"https://console.example.evil.test", "console.example", false},
		"prefix impersonation":    {"https://console.example@evil.test", "console.example", false},
		"wildcard":                {"https://sub.console.example", "*.console.example", false},
		"non HTTP":                {"javascript:alert(1)", "console.example", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := isWhitelisted(test.target, test.whitelist); got != test.allowed {
				t.Fatalf("isWhitelisted(%q, %q) = %v, want %v", test.target, test.whitelist, got, test.allowed)
			}
		})
	}
}

func TestAllowedRedirectURLPreservesPathAndQueryButRejectsUnsafeAuthority(t *testing.T) {
	if !isAllowedRedirectURL("https://console.example/login?error=403", "console.example") {
		t.Fatal("allowed redirect path and query were rejected")
	}
	for _, value := range []string{
		"https://console.example@evil.test/login",
		"//console.example/login",
		"javascript:alert(1)",
	} {
		if isAllowedRedirectURL(value, "console.example") {
			t.Fatalf("unsafe redirect URL %q was accepted", value)
		}
	}
}

func TestValidateRedirectPathRejectsAuthorityAndControlCharacters(t *testing.T) {
	for _, value := range []string{"//evil.test/login", "https://evil.test/login", "login", "/login\r\nX-Test: yes"} {
		if err := validateRedirectPath(value); err == nil {
			t.Fatalf("unsafe redirect path %q was accepted", value)
		}
	}
	if err := validateRedirectPath("/login/shibboleth-auth?from=saml"); err != nil {
		t.Fatalf("safe redirect path was rejected: %v", err)
	}
}

func TestRequestIsHTTPSHonorsTLSAndForwardedProto(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "http://console.example/login", nil)
	if requestIsHTTPS(plain) {
		t.Fatal("plain HTTP request was treated as HTTPS")
	}
	forwarded := httptest.NewRequest(http.MethodGet, "http://console.example/login", nil)
	forwarded.Header.Set("X-Forwarded-Proto", "https, http")
	if !requestIsHTTPS(forwarded) {
		t.Fatal("trusted proxy HTTPS signal was ignored")
	}
	tlsRequest := httptest.NewRequest(http.MethodGet, "https://console.example/login", nil)
	tlsRequest.TLS = &tls.ConnectionState{}
	if !requestIsHTTPS(tlsRequest) {
		t.Fatal("TLS request was not treated as HTTPS")
	}
}

func TestRequestAndHandoffOriginUseExactSchemeHostAndPort(t *testing.T) {
	previousPlatformClient := server.PlatformClient
	server.PlatformClient = nil
	t.Cleanup(func() { server.PlatformClient = previousPlatformClient })

	target, err := url.Parse("https://console.example")
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://console.example/login", nil)
	if !sameRequestOrigin(request, target) {
		t.Fatal("same request origin was not recognized")
	}
	differentPort, _ := url.Parse("https://console.example:8443")
	if sameRequestOrigin(request, differentPort) {
		t.Fatal("a different port was accepted as the same origin")
	}

	handoff := httptest.NewRequest(http.MethodPost, "https://console.example/v1-auth/saml/tokenhtml", nil)
	handoff.Header.Set("Origin", "http://localhost:8080")
	if !validSAMLHandoffOrigin(handoff) {
		t.Fatal("the configured platform origin was rejected")
	}
	handoff.Header.Set("Origin", "http://localhost:8081")
	if validSAMLHandoffOrigin(handoff) {
		t.Fatal("an unconfigured handoff origin was accepted")
	}
}

func TestSAMLRedirectURLRejectsUnsafeBaseAndPath(t *testing.T) {
	previousPlatformClient := server.PlatformClient
	server.PlatformClient = nil
	t.Cleanup(func() { server.PlatformClient = previousPlatformClient })

	if got := samlRedirectURL("https://console.example/base", "/login?from=saml"); got != "https://console.example/base/login?from=saml" {
		t.Fatalf("unexpected safe redirect %q", got)
	}
	if got := samlRedirectURL("https://console.example", "//evil.test/login"); got != "https://console.example/login/shibboleth-auth" {
		t.Fatalf("unsafe path was retained in %q", got)
	}
	if got := samlRedirectURL("javascript:alert(1)", "/login"); got != "http://localhost:8080/login" {
		t.Fatalf("unsafe base did not fall back safely: %q", got)
	}
}

func TestPostSamlTokenHTMLValidatesOriginTokenRedirectAndCookie(t *testing.T) {
	previousValidator := validatePlatformToken
	previousProvider := server.SamlServiceProvider
	previousPlatformClient := server.PlatformClient
	server.PlatformClient = nil
	server.SamlServiceProvider = &model.PlatformSamlServiceProvider{RedirectWhitelist: "console.example"}
	validatePlatformToken = func(value string) error {
		if value != "signed-platform-token" {
			return errors.New("invalid token")
		}
		return nil
	}
	t.Cleanup(func() {
		validatePlatformToken = previousValidator
		server.SamlServiceProvider = previousProvider
		server.PlatformClient = previousPlatformClient
	})

	newRequest := func(origin, token, redirect string) *http.Request {
		form := url.Values{"token": {token}, "finalRedirectURL": {redirect}}
		request := httptest.NewRequest(http.MethodPost, "https://console.example/v1-auth/saml/tokenhtml", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", origin)
		return request
	}

	recorder := httptest.NewRecorder()
	PostSamlTokenHTML(recorder, newRequest("http://localhost:8080", "signed-platform-token", "https://console.example/login?from=saml"))
	result := recorder.Result()
	if result.StatusCode != http.StatusFound || result.Header.Get("Location") != "https://console.example/login?from=saml" {
		t.Fatalf("unexpected successful handoff response: status=%d location=%q", result.StatusCode, result.Header.Get("Location"))
	}
	cookies := result.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "token" || cookies[0].Value != "signed-platform-token" ||
		!cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("platform token cookie is missing security attributes: %#v", cookies)
	}

	for name, request := range map[string]*http.Request{
		"origin":   newRequest("https://attacker.example", "signed-platform-token", "https://console.example/login"),
		"token":    newRequest("http://localhost:8080", "forged", "https://console.example/login"),
		"redirect": newRequest("http://localhost:8080", "signed-platform-token", "https://attacker.example/login"),
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			PostSamlTokenHTML(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("unsafe handoff returned %d", recorder.Code)
			}
		})
	}

	methodRecorder := httptest.NewRecorder()
	PostSamlTokenHTML(methodRecorder, httptest.NewRequest(http.MethodGet, "https://console.example/v1-auth/saml/tokenhtml", nil))
	if methodRecorder.Code != http.StatusMethodNotAllowed || methodRecorder.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("unexpected method response: %d %q", methodRecorder.Code, methodRecorder.Header().Get("Allow"))
	}
}
