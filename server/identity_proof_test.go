package server

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/PastureStack/authentication-service/model"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/rancher/go-rancher/v2"
)

func TestCreateIdentityProofIsSignedAndDoesNotContainProviderTokens(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey = key

	input := model.Token{
		AccessToken: "must-not-leak",
		JwtToken:    "must-not-leak",
		IdentityList: []client.Identity{{
			ExternalId:     "https://id.example.test|subject-123",
			ExternalIdType: "oidc_user",
			Name:           "Test Administrator",
			Login:          "admin",
		}},
	}

	proof, err := createIdentityProof(input, "oidcconfig", "oidc_user")
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := jwt.Parse(proof, func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil {
		t.Fatal(err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		t.Fatal("identity proof was not a valid signed JWT")
	}
	if claims["purpose"] != "auth-identity-proof" {
		t.Fatalf("unexpected purpose: %#v", claims["purpose"])
	}
	if claims["external_id"] != "https://id.example.test|subject-123" {
		t.Fatalf("unexpected external identity: %#v", claims["external_id"])
	}
	if _, ok := claims["access_token"]; ok {
		t.Fatal("identity proof leaked an access token")
	}
	if _, ok := claims["refresh_token"]; ok {
		t.Fatal("identity proof leaked a refresh token")
	}
	if claims["jti"] == "" || claims["exp"] == nil {
		t.Fatal("identity proof is missing replay or expiry claims")
	}
}

func TestCreateIdentityProofRejectsMissingUser(t *testing.T) {
	if _, err := createIdentityProof(model.Token{}, "oidcconfig", "oidc_user"); err == nil {
		t.Fatal("expected a missing user identity to be rejected")
	}
}
