package github

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PastureStack/authentication-service/model"
	"github.com/PastureStack/authentication-service/outbound"
	log "github.com/sirupsen/logrus"
)

func githubTestClient(t *testing.T, server *httptest.Server) *GClient {
	t.Helper()
	t.Setenv(outbound.AllowedOriginsEnvironment, server.URL)
	config := &model.GithubConfig{
		Scheme:       "http://",
		Hostname:     strings.TrimPrefix(server.URL, "http://"),
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}
	client := &GClient{}
	if err := client.configure(config); err != nil {
		t.Fatalf("configure GitHub test client: %v", err)
	}
	return client
}

func TestGetAccessTokenDoesNotExposeRejectedResponse(t *testing.T) {
	const sentinel = "upstream-secret-description"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"error":"bad_verification_code","error_description":%q}`, sentinel)
	}))
	defer server.Close()

	var logs bytes.Buffer
	previousOutput := log.StandardLogger().Out
	log.SetOutput(&logs)
	defer log.SetOutput(previousOutput)

	_, err := githubTestClient(t, server).getAccessToken("authorization-code")
	if err == nil {
		t.Fatal("expected the rejected token request to fail")
	}
	if strings.Contains(err.Error(), sentinel) || strings.Contains(logs.String(), sentinel) {
		t.Fatal("the upstream error description must not be exposed")
	}
}

func TestGetAccessTokenAcceptsStringToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{"access_token":"expected-token"}`)
	}))
	defer server.Close()

	token, err := githubTestClient(t, server).getAccessToken("authorization-code")
	if err != nil {
		t.Fatalf("expected a valid token response: %v", err)
	}
	if token != "expected-token" {
		t.Fatalf("unexpected token %q", token)
	}
}

func TestGitHubHTTPErrorDoesNotExposeResponseBody(t *testing.T) {
	const sentinel = "sensitive-response-body"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, sentinel, http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := githubTestClient(t, server).getAccessToken("authorization-code")
	if err == nil {
		t.Fatal("expected the HTTP error to be returned")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatal("the upstream response body must not be exposed")
	}
}

func TestReadGithubResponseRejectsOversizedBody(t *testing.T) {
	_, err := readGithubResponse(strings.NewReader(strings.Repeat("x", maxGithubResponseSize+1)))
	if err == nil {
		t.Fatal("expected an oversized response to be rejected")
	}
}

func TestGitHubRejectsUntrustedIdentityPathBeforeNetwork(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{}`)
	}))
	defer server.Close()
	client := githubTestClient(t, server)

	for _, value := range []string{"../admin", "1?redirect=http://169.254.169.254", "0", "01", "-1"} {
		if _, err := client.getUserOrgByID(value, "token"); err == nil {
			t.Fatalf("unsafe GitHub identity ID %q was accepted", value)
		}
	}
	for _, value := range []string{"../admin", "name/teams", "name?x=y", "name%2fadmin", "-leading", "trailing-"} {
		if _, err := client.getGithubOrgByName(value, "token"); err == nil {
			t.Fatalf("unsafe GitHub login %q was accepted", value)
		}
	}
	if requests != 0 {
		t.Fatalf("unsafe identity input caused %d network requests", requests)
	}
}

func TestGitHubAllowsValidatedIdentityPath(t *testing.T) {
	var requestedPath string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestedPath = request.URL.EscapedPath()
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{"id":123,"login":"alice"}`)
	}))
	defer server.Close()
	account, err := githubTestClient(t, server).getUserOrgByID("123", "token")
	if err != nil {
		t.Fatalf("validated identity request failed: %v", err)
	}
	if requestedPath != "/api/v3/user/123" || account.ID != 123 {
		t.Fatalf("unexpected validated identity response path=%q account=%#v", requestedPath, account)
	}
}

func TestGitHubAllowsEnterpriseManagedUserLogins(t *testing.T) {
	var requestedPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestedPaths = append(requestedPaths, request.URL.EscapedPath())
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{"id":123,"login":"managed_user"}`)
	}))
	defer server.Close()
	client := githubTestClient(t, server)
	for _, login := range []string{"octo_admin", "mona-cat_octo", "managed.user"} {
		if _, err := client.getGithubOrgByName(login, "token"); err != nil {
			t.Fatalf("valid enterprise login %q was rejected: %v", login, err)
		}
	}
	if len(requestedPaths) != 3 {
		t.Fatalf("expected three validated enterprise requests, got %d", len(requestedPaths))
	}
}

func TestGitHubPaginationCannotLeaveAuthorizedOrigin(t *testing.T) {
	attackerRequests := 0
	attacker := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attackerRequests++
		fmt.Fprint(writer, `[]`)
	}))
	defer attacker.Close()

	trusted := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Link", "<"+attacker.URL+"/steal>; rel=\"next\"")
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `[]`)
	}))
	defer trusted.Close()
	client := githubTestClient(t, trusted)

	if _, err := client.getGithubOrgs("secret-token"); err == nil {
		t.Fatal("cross-origin GitHub pagination target was accepted")
	}
	if attackerRequests != 0 {
		t.Fatalf("attacker pagination origin received %d requests", attackerRequests)
	}
}

func TestGitHubRedirectCannotLeaveAuthorizedOrigin(t *testing.T) {
	attackerRequests := 0
	attacker := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attackerRequests++
		fmt.Fprint(writer, `{"access_token":"stolen"}`)
	}))
	defer attacker.Close()

	trusted := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, attacker.URL+"/steal", http.StatusFound)
	}))
	defer trusted.Close()
	client := githubTestClient(t, trusted)

	if _, err := client.getAccessToken("authorization-code"); err == nil {
		t.Fatal("cross-origin GitHub redirect was accepted")
	}
	if attackerRequests != 0 {
		t.Fatalf("attacker redirect origin received %d requests", attackerRequests)
	}
}

func TestGitHubEnterpriseRequiresOperatorAuthorizedOrigin(t *testing.T) {
	t.Setenv(outbound.AllowedOriginsEnvironment, "")
	client := &GClient{}
	err := client.configure(&model.GithubConfig{Scheme: "https://", Hostname: "ghe.internal.example"})
	if err == nil || !strings.Contains(err.Error(), outbound.AllowedOriginsEnvironment) {
		t.Fatalf("unauthorized GitHub Enterprise origin was accepted: %v", err)
	}
}
