package model

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/crewjam/saml"
)

func TestCookieSAMLClientStateLifecycle(t *testing.T) {
	state := CookieSAMLClientState{ServiceProvider: &saml.ServiceProvider{
		AcsURL: url.URL{Scheme: "https", Host: "platform.example", Path: "/v1-saml/acs"},
	}}
	request := httptest.NewRequest(http.MethodGet, "https://platform.example/v1-saml/login", nil)
	recorder := httptest.NewRecorder()

	state.SetState(recorder, request, "relay", "signed-value")
	result := recorder.Result()
	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one state cookie, got %d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != "saml_relay" || cookie.Value != "signed-value" {
		t.Fatalf("unexpected state cookie: %#v", cookie)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/v1-saml/acs" || cookie.MaxAge <= 0 {
		t.Fatalf("state cookie is missing security attributes: %#v", cookie)
	}
	if cookie.SameSite != http.SameSiteNoneMode {
		t.Fatalf("HTTPS SAML POST state cookie must use SameSite=None: %#v", cookie)
	}

	callback := httptest.NewRequest(http.MethodPost, "https://platform.example/v1-saml/acs", nil)
	callback.AddCookie(cookie)
	if got := state.GetState(callback, "relay"); got != "signed-value" {
		t.Fatalf("unexpected state value %q", got)
	}
	if got := state.GetStates(callback)["relay"]; got != "signed-value" {
		t.Fatalf("unexpected state map value %q", got)
	}

	deleteRecorder := httptest.NewRecorder()
	if err := state.DeleteState(deleteRecorder, callback, "relay"); err != nil {
		t.Fatalf("delete state: %v", err)
	}
	deleted := deleteRecorder.Result().Cookies()[0]
	if deleted.Value != "" || deleted.MaxAge != -1 || deleted.Path != "/v1-saml/acs" || deleted.SameSite != http.SameSiteNoneMode {
		t.Fatalf("state cookie was not expired safely: %#v", deleted)
	}
}

func TestCookieSAMLClientStateIgnoresUnrelatedCookies(t *testing.T) {
	state := CookieSAMLClientState{}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/callback", nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: "do-not-read"})
	request.AddCookie(&http.Cookie{Name: "saml_expected", Value: "signed"})
	states := state.GetStates(request)
	if len(states) != 1 || states["expected"] != "signed" {
		t.Fatalf("unexpected state cookies: %#v", states)
	}
}
