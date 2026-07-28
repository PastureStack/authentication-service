package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KeyID     string `json:"kid"`
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	N         string `json:"n"`
	E         string `json:"e"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

func (c *Client) signingKey(ctx context.Context, keyID string, algorithm string) (interface{}, error) {
	keys, err := c.getSigningKeys(ctx, false)
	if err != nil {
		return nil, err
	}
	if key, found := selectJWK(keys, keyID, algorithm); found {
		return key.publicKey()
	}

	keys, err = c.getSigningKeys(ctx, true)
	if err != nil {
		return nil, err
	}
	if key, found := selectJWK(keys, keyID, algorithm); found {
		return key.publicKey()
	}
	return nil, fmt.Errorf("OIDC signing key was not found for kid %q and alg %q", keyID, algorithm)
}

func (c *Client) invalidateSigningKeys() {
	c.keyMutex.Lock()
	c.keys = nil
	c.keysUntil = time.Time{}
	c.keyMutex.Unlock()
}

func (c *Client) getSigningKeys(ctx context.Context, forceRefresh bool) ([]jwk, error) {
	c.keyMutex.Lock()
	defer c.keyMutex.Unlock()
	if !forceRefresh && len(c.keys) > 0 && time.Now().Before(c.keysUntil) {
		return append([]jwk(nil), c.keys...), nil
	}

	if c.originPolicy == nil || !c.originPolicy.IsValidRedirectURL(c.discovery.JWKSURI) {
		return nil, fmt.Errorf("OIDC JWKS endpoint origin is not authorized")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.discovery.JWKSURI, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("OIDC JWKS request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("OIDC JWKS endpoint returned HTTP %d", response.StatusCode)
	}

	var set jwkSet
	if err := decodeJSON(response.Body, &set); err != nil {
		return nil, fmt.Errorf("OIDC JWKS response is invalid: %v", err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("OIDC JWKS response contains no keys")
	}
	if len(set.Keys) > 100 {
		return nil, fmt.Errorf("OIDC JWKS response contains too many keys")
	}

	c.keys = append([]jwk(nil), set.Keys...)
	c.keysUntil = time.Now().Add(jwksCacheDuration(response.Header.Get("Cache-Control")))
	return append([]jwk(nil), c.keys...), nil
}

func jwksCacheDuration(cacheControl string) time.Duration {
	duration := 15 * time.Minute
	for _, directive := range strings.Split(cacheControl, ",") {
		parts := strings.SplitN(strings.TrimSpace(directive), "=", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "max-age") {
			continue
		}
		seconds, err := strconv.Atoi(strings.Trim(parts[1], `"`))
		if err == nil && seconds >= 0 {
			duration = time.Duration(seconds) * time.Second
		}
	}
	if duration > time.Hour {
		return time.Hour
	}
	return duration
}

func selectJWK(keys []jwk, keyID string, algorithm string) (jwk, bool) {
	var candidates []jwk
	for _, key := range keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if key.Algorithm != "" && key.Algorithm != algorithm {
			continue
		}
		if keyID != "" && key.KeyID != keyID {
			continue
		}
		if !key.supportsAlgorithm(algorithm) {
			continue
		}
		candidates = append(candidates, key)
	}
	if len(candidates) != 1 {
		return jwk{}, false
	}
	return candidates[0], true
}

func (key jwk) supportsAlgorithm(algorithm string) bool {
	switch key.KeyType {
	case "RSA":
		return strings.HasPrefix(algorithm, "RS") || strings.HasPrefix(algorithm, "PS")
	case "EC":
		return strings.HasPrefix(algorithm, "ES")
	case "OKP":
		return algorithm == "EdDSA" && key.Curve == "Ed25519"
	default:
		return false
	}
}

func (key jwk) publicKey() (interface{}, error) {
	switch key.KeyType {
	case "RSA":
		modulus, err := decodeBigInteger(key.N)
		if err != nil || modulus.Sign() <= 0 {
			return nil, fmt.Errorf("OIDC RSA JWK has an invalid modulus")
		}
		if modulus.BitLen() < 2048 {
			return nil, fmt.Errorf("OIDC RSA JWK modulus is smaller than 2048 bits")
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
			return nil, fmt.Errorf("OIDC RSA JWK has an invalid exponent")
		}
		exponent := 0
		for _, value := range exponentBytes {
			exponent = exponent<<8 + int(value)
		}
		if exponent < 3 {
			return nil, fmt.Errorf("OIDC RSA JWK exponent is too small")
		}
		return &rsa.PublicKey{N: modulus, E: exponent}, nil

	case "EC":
		var curve elliptic.Curve
		switch key.Curve {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("OIDC EC JWK uses unsupported curve %q", key.Curve)
		}
		x, err := decodeBigInteger(key.X)
		if err != nil {
			return nil, fmt.Errorf("OIDC EC JWK has invalid x coordinate")
		}
		y, err := decodeBigInteger(key.Y)
		if err != nil || !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("OIDC EC JWK is not on the advertised curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil

	case "OKP":
		if key.Curve != "Ed25519" {
			return nil, fmt.Errorf("OIDC OKP JWK uses unsupported curve %q", key.Curve)
		}
		publicKey, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("OIDC Ed25519 JWK has invalid key material")
		}
		return ed25519.PublicKey(publicKey), nil
	}
	return nil, fmt.Errorf("OIDC JWK uses unsupported key type %q", key.KeyType)
}

func decodeBigInteger(value string) (*big.Int, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return nil, fmt.Errorf("invalid base64url integer")
	}
	return new(big.Int).SetBytes(decoded), nil
}
