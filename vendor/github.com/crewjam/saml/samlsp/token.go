package samlsp

import (
	"context"

	jwt "github.com/golang-jwt/jwt/v5"
)

// AuthorizationToken represents the data stored in the authorization cookie.
type AuthorizationToken struct {
	jwt.RegisteredClaims
	Attributes Attributes `json:"attr"`
}

func init() {
	// Preserve the jwt-go v3 StandardClaims wire format for existing Rancher SAML
	// session cookies. golang-jwt v5 defaults a single audience to an array.
	jwt.MarshalSingleStringAsArray = false
}

// Attributes is a map of attributes provided in the SAML assertion
type Attributes map[string][]string

// Get returns the first attribute named `key` or an empty string if
// no such attributes is present.
func (a Attributes) Get(key string) string {
	if a == nil {
		return ""
	}
	v := a[key]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

type indexType int

const tokenIndex indexType = iota

// Token returns the token associated with ctx, or nil if no token are associated
func Token(ctx context.Context) *AuthorizationToken {
	v := ctx.Value(tokenIndex)
	if v == nil {
		return nil
	}
	return v.(*AuthorizationToken)
}

// WithToken returns a new context with token associated
func WithToken(ctx context.Context, token *AuthorizationToken) context.Context {
	return context.WithValue(ctx, tokenIndex, token)
}
