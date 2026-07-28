package service

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PastureStack/authentication-service/providers"
)

func TestReadAuthRequestBodyRejectsOversizedInput(t *testing.T) {
	request := httptest.NewRequest("POST", "/v1-auth/testlogin", strings.NewReader(strings.Repeat("x", maxAuthRequestSize+1)))
	if _, err := readAuthRequestBody(request); err == nil {
		t.Fatal("oversized authentication request must be rejected")
	}
}

func TestReadAuthRequestBodyAcceptsLimit(t *testing.T) {
	request := httptest.NewRequest("POST", "/v1-auth/testlogin", strings.NewReader(strings.Repeat("x", maxAuthRequestSize)))
	body, err := readAuthRequestBody(request)
	if err != nil {
		t.Fatalf("request at the size limit was rejected: %v", err)
	}
	if len(body) != maxAuthRequestSize {
		t.Fatalf("read %d bytes, expected %d", len(body), maxAuthRequestSize)
	}
}

func TestOIDCSchemaIsRegisteredWithSafeDefaults(t *testing.T) {
	providers.RegisterProviders()
	allSchemas := getSchemas()
	schema, found := allSchemas.CheckSchema("oidcconfig")
	if !found {
		t.Fatal("oidcconfig schema was not registered")
	}
	if _, found := schema.ResourceFields["-"]; found {
		t.Fatal("internal OIDC runtime fields leaked into the public schema")
	}

	expectedDefaults := map[string]interface{}{
		"displayName":      "OpenID Connect",
		"scopes":           "openid",
		"usePkce":          true,
		"usernameClaim":    "preferred_username",
		"displayNameClaim": "name",
		"emailClaim":       "email",
		"groupsClaim":      "groups",
	}
	for name, expected := range expectedDefaults {
		field, found := schema.ResourceFields[name]
		if !found {
			t.Fatalf("OIDC schema is missing %s", name)
		}
		if field.Default != expected {
			t.Fatalf("OIDC schema field %s has default %#v, expected %#v", name, field.Default, expected)
		}
	}

	clientSecretSet := schema.ResourceFields["clientSecretSet"]
	if clientSecretSet.Create || clientSecretSet.Update {
		t.Fatal("clientSecretSet must be read-only")
	}
}
