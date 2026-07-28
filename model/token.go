package model

import (
	"github.com/rancher/go-rancher/v2"
)

// Token structure defines all properties that can be present in a token
type Token struct {
	client.Resource
	Type              string            `json:"tokenType"`
	ExternalAccountID string            `json:"accountID"`
	IdentityList      []client.Identity `json:"identities"`
	AccessToken       string
	JwtToken          string `json:"jwt"`
	OriginalLogin     string `json:"originalLogin"`
	// IdentityProof is a short-lived, signed, single-use proof returned only
	// from the administrator-protected provider test flow.  It never contains
	// an upstream access or refresh token.
	IdentityProof string `json:"identityProof,omitempty"`
}

type V2Token struct {
	Data []Token `json:"data"`
}
