package model

import (
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml"
)

const samlStateCookiePrefix = "saml_"

// CookieSAMLClientState preserves the historical RelayState cookie contract
// while the SAML parser and signature verifier use the maintained upstream
// implementation.  The value stored here is already integrity-protected by
// the service's short-lived signed state token.
type CookieSAMLClientState struct {
	ServiceProvider *saml.ServiceProvider
}

func (c CookieSAMLClientState) cookiePath() string {
	if c.ServiceProvider == nil || c.ServiceProvider.AcsURL.Path == "" {
		return "/"
	}
	return c.ServiceProvider.AcsURL.Path
}

// SetState stores a single, short-lived RelayState value.
func (c CookieSAMLClientState) SetState(w http.ResponseWriter, r *http.Request, id string, value string) {
	secure := samlRequestIsHTTPS(r)
	sameSite := http.SameSiteLaxMode
	if secure {
		sameSite = http.SameSiteNoneMode
	}
	http.SetCookie(w, &http.Cookie{
		Name:     samlStateCookiePrefix + id,
		Value:    value,
		MaxAge:   int(saml.MaxIssueDelay.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		Path:     c.cookiePath(),
	})
}

// GetStates returns all pending RelayState values from the request.
func (c CookieSAMLClientState) GetStates(r *http.Request) map[string]string {
	states := map[string]string{}
	if r == nil {
		return states
	}
	for _, cookie := range r.Cookies() {
		if !strings.HasPrefix(cookie.Name, samlStateCookiePrefix) {
			continue
		}
		states[strings.TrimPrefix(cookie.Name, samlStateCookiePrefix)] = cookie.Value
	}
	return states
}

// GetState returns one pending RelayState value.
func (c CookieSAMLClientState) GetState(r *http.Request, id string) string {
	if r == nil {
		return ""
	}
	cookie, err := r.Cookie(samlStateCookiePrefix + id)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// DeleteState expires one RelayState cookie after successful consumption.
func (c CookieSAMLClientState) DeleteState(w http.ResponseWriter, r *http.Request, id string) error {
	if r == nil {
		return http.ErrNoCookie
	}
	cookie, err := r.Cookie(samlStateCookiePrefix + id)
	if err != nil {
		return err
	}
	cookie.Value = ""
	cookie.Path = c.cookiePath()
	cookie.MaxAge = -1
	cookie.Expires = time.Unix(1, 0)
	cookie.HttpOnly = true
	cookie.Secure = samlRequestIsHTTPS(r)
	if cookie.Secure {
		cookie.SameSite = http.SameSiteNoneMode
	} else {
		cookie.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, cookie)
	return nil
}

func samlRequestIsHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil || strings.EqualFold(r.URL.Scheme, "https") {
		return true
	}
	forwardedProto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	return strings.EqualFold(forwardedProto, "https")
}

var _ SAMLClientState = CookieSAMLClientState{}
