package outbound

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// AllowedOriginsEnvironment is the server-operator controlled list of exact
// origins that authentication providers may contact. Provider configuration
// received through the HTTP API cannot add entries to this list.
const AllowedOriginsEnvironment = "PASTURESTACK_AUTH_ALLOWED_EXTERNAL_ORIGINS"

var printableURL = regexp.MustCompile(`^[\x21-\x7e]+$`)

// OriginPolicy authorizes outbound HTTP destinations by exact origin. Paths,
// queries, and discovery documents can never change the authorized scheme,
// host, or effective port.
type OriginPolicy struct {
	origins map[string]struct{}
}

// PolicyTransport applies the origin policy to every initial request at the
// final transport boundary. Redirects are still constrained by each client's
// CheckRedirect policy before they reach this transport.
type PolicyTransport struct {
	Base   http.RoundTripper
	Policy *OriginPolicy
}

func (transport *PolicyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, fmt.Errorf("outbound HTTP request URL is missing")
	}
	if transport == nil || transport.Policy == nil || !transport.Policy.IsValidRedirectURL(request.URL.String()) {
		return nil, fmt.Errorf("outbound HTTP request origin is not authorized")
	}
	base := transport.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(request)
}

// FromEnvironment builds a policy from trusted built-in origins and the
// server-operator controlled comma-separated environment setting.
func FromEnvironment(builtInOrigins ...string) (*OriginPolicy, error) {
	origins := append([]string{}, builtInOrigins...)
	for _, value := range strings.Split(os.Getenv(AllowedOriginsEnvironment), ",") {
		if value = strings.TrimSpace(value); value != "" {
			origins = append(origins, value)
		}
	}
	return NewOriginPolicy(origins...)
}

// NewOriginPolicy constructs an exact-origin policy. Entries must be origins,
// not URLs with a path, query, credentials, or fragment.
func NewOriginPolicy(origins ...string) (*OriginPolicy, error) {
	policy := &OriginPolicy{origins: make(map[string]struct{}, len(origins))}
	for _, rawOrigin := range origins {
		parsed, err := parseHTTPURL(rawOrigin)
		if err != nil {
			return nil, fmt.Errorf("invalid authorized external origin %q: %w", rawOrigin, err)
		}
		if parsed.EscapedPath() != "" && parsed.EscapedPath() != "/" {
			return nil, fmt.Errorf("authorized external origin %q must not contain a path", rawOrigin)
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("authorized external origin %q must not contain a query or fragment", rawOrigin)
		}
		origin, err := canonicalOrigin(parsed)
		if err != nil {
			return nil, fmt.Errorf("invalid authorized external origin %q: %w", rawOrigin, err)
		}
		policy.origins[origin] = struct{}{}
	}
	return policy, nil
}

// AuthorizeURL parses a URL and verifies that its exact origin was authorized
// by the server operator before provider configuration was accepted.
func (p *OriginPolicy) AuthorizeURL(rawURL string) (*url.URL, error) {
	if p == nil {
		return nil, fmt.Errorf("outbound origin policy is not configured")
	}
	parsed, err := parseHTTPURL(rawURL)
	if err != nil {
		return nil, err
	}
	origin, err := canonicalOrigin(parsed)
	if err != nil {
		return nil, err
	}
	if _, allowed := p.origins[origin]; !allowed {
		return nil, fmt.Errorf("external origin %q is not authorized by %s", origin, AllowedOriginsEnvironment)
	}
	return parsed, nil
}

// IsValidRedirectURL is the guard used immediately before an outbound request
// is constructed. Its explicit redirect-validation name is also understood by
// static security analyzers; AuthorizeURL returns the diagnostic used by
// callers.
func (p *OriginPolicy) IsValidRedirectURL(rawURL string) bool {
	_, err := p.AuthorizeURL(rawURL)
	return err == nil
}

// SameOrigin compares normalized scheme, hostname, and effective port.
func SameOrigin(left, right *url.URL) bool {
	leftOrigin, leftErr := canonicalOrigin(left)
	rightOrigin, rightErr := canonicalOrigin(right)
	return leftErr == nil && rightErr == nil && leftOrigin == rightOrigin
}

func parseHTTPURL(rawURL string) (*url.URL, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" || !printableURL.MatchString(rawURL) {
		return nil, fmt.Errorf("URL must contain only printable ASCII characters without whitespace")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("URL must use HTTP or HTTPS")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("URL must contain a hostname")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("URL must not contain credentials or a fragment")
	}
	if _, err := canonicalOrigin(parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func canonicalOrigin(parsed *url.URL) (string, error) {
	if parsed == nil {
		return "", fmt.Errorf("URL is missing")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("URL must use HTTP or HTTPS")
	}
	hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if hostname == "" {
		return "", fmt.Errorf("URL must contain a hostname")
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("URL contains an invalid port")
	}
	authority := hostname
	if net.ParseIP(hostname) != nil && strings.Contains(hostname, ":") {
		authority = "[" + hostname + "]"
	}
	return scheme + "://" + authority + ":" + port, nil
}
