package outbound

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type countingTransport struct {
	requests int
}

func (transport *countingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.requests++
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    request,
	}, nil
}

func TestOriginPolicyAllowsOnlyExactAuthorizedOrigin(t *testing.T) {
	policy, err := NewOriginPolicy("https://idp.example", "http://127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	for _, allowed := range []string{
		"https://idp.example/.well-known/openid-configuration",
		"https://IDP.EXAMPLE:443/token?tenant=one",
		"http://127.0.0.1:18080/metadata",
	} {
		if _, err := policy.AuthorizeURL(allowed); err != nil {
			t.Fatalf("authorized URL %q was rejected: %v", allowed, err)
		}
	}
	for _, denied := range []string{
		"http://idp.example/token",
		"https://idp.example:444/token",
		"https://idp.example.attacker.invalid/token",
		"https://user:secret@idp.example/token",
		"http://169.254.169.254/latest/meta-data",
		"https://idp.example/token#fragment",
		"https://idp.example/\r\nHost: attacker.invalid",
	} {
		if _, err := policy.AuthorizeURL(denied); err == nil {
			t.Fatalf("unauthorized URL %q was accepted", denied)
		}
	}
}

func TestOriginPolicyRejectsMisleadingEntries(t *testing.T) {
	for _, entry := range []string{
		"https://idp.example/path",
		"https://idp.example?tenant=one",
		"https://user@idp.example",
		"file:///etc/passwd",
	} {
		if _, err := NewOriginPolicy(entry); err == nil {
			t.Fatalf("invalid origin entry %q was accepted", entry)
		}
	}
}

func TestSameOriginNormalizesDefaultPortsAndRejectsChanges(t *testing.T) {
	parse := func(raw string) *url.URL {
		value, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	if !SameOrigin(parse("https://IDP.example/start"), parse("https://idp.example:443/next")) {
		t.Fatal("equivalent HTTPS origins were not recognized")
	}
	for name, candidate := range map[string]string{
		"scheme": "http://idp.example/next",
		"port":   "https://idp.example:444/next",
		"host":   "https://attacker.invalid/next",
	} {
		t.Run(name, func(t *testing.T) {
			if SameOrigin(parse("https://idp.example/start"), parse(candidate)) {
				t.Fatalf("changed origin %q was accepted", candidate)
			}
		})
	}
}

func TestEnvironmentCannotBeExtendedByURLText(t *testing.T) {
	t.Setenv(AllowedOriginsEnvironment, "https://idp.example, https://login.example")
	policy, err := FromEnvironment("https://api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.AuthorizeURL("https://login.example/authorize"); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.AuthorizeURL("https://attacker.invalid/?next=" + strings.Repeat("a", 16)); err == nil {
		t.Fatal("request URL text extended the trusted origin set")
	}
}

func TestPolicyTransportRejectsUnauthorizedInitialRequest(t *testing.T) {
	policy, err := NewOriginPolicy("https://trusted.example")
	if err != nil {
		t.Fatal(err)
	}
	base := &countingTransport{}
	client := &http.Client{Transport: &PolicyTransport{Base: base, Policy: policy}}
	if _, err := client.Get("https://attacker.invalid/steal"); err == nil {
		t.Fatal("unauthorized initial request was accepted")
	}
	if base.requests != 0 {
		t.Fatalf("unauthorized request reached the base transport %d times", base.requests)
	}
	response, err := client.Get("https://trusted.example/token")
	if err != nil {
		t.Fatalf("authorized initial request failed: %v", err)
	}
	response.Body.Close()
	if base.requests != 1 {
		t.Fatalf("authorized request reached the base transport %d times", base.requests)
	}
}
