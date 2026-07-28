package github

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PastureStack/authentication-service/model"
	log "github.com/sirupsen/logrus"
)

func githubTestClient(server *httptest.Server) *GClient {
	return &GClient{
		httpClient: server.Client(),
		config: &model.GithubConfig{
			Scheme:       "http://",
			Hostname:     strings.TrimPrefix(server.URL, "http://"),
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		},
	}
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

	_, err := githubTestClient(server).getAccessToken("authorization-code")
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

	token, err := githubTestClient(server).getAccessToken("authorization-code")
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

	_, err := githubTestClient(server).getAccessToken("authorization-code")
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
