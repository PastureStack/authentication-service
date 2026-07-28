package server

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/PastureStack/authentication-service/util"
	"github.com/golang-jwt/jwt/v5"
)

func TestValidatePlatformTokenRequiresSignatureAndTokenType(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	previousPublicKey := publicKey
	publicKey = &key.PublicKey
	defer func() { publicKey = previousPublicKey }()

	valid, err := util.CreateTokenWithPayload(map[string]interface{}{"access_token": ""}, key)
	if err != nil {
		t.Fatalf("sign platform token: %v", err)
	}
	if err := ValidatePlatformToken(valid); err != nil {
		t.Fatalf("valid platform token was rejected: %v", err)
	}

	wrongType, err := util.CreateTokenWithPayload(map[string]interface{}{"purpose": "auth-identity-proof"}, key)
	if err != nil {
		t.Fatalf("sign wrong token type: %v", err)
	}
	if err := ValidatePlatformToken(wrongType); err == nil {
		t.Fatal("identity proof was accepted as a platform token")
	}
	wrongClaimType, err := util.CreateTokenWithPayload(map[string]interface{}{"access_token": map[string]string{"unexpected": "value"}}, key)
	if err != nil {
		t.Fatalf("sign wrong claim type: %v", err)
	}
	if err := ValidatePlatformToken(wrongClaimType); err == nil {
		t.Fatal("non-string access token claim was accepted")
	}

	hmacToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"access_token": ""}).SignedString([]byte("not-the-rsa-key"))
	if err != nil {
		t.Fatalf("sign HMAC token: %v", err)
	}
	if err := ValidatePlatformToken(hmacToken); err == nil {
		t.Fatal("HMAC algorithm-confusion token was accepted")
	}

	publicKey = nil
	if err := ValidatePlatformToken(valid); err == nil {
		t.Fatal("token validation succeeded without a public key")
	}
}
