package service

import (
	"encoding/json"
	"net/http"
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
	if field := allSchemas.Schema("config").ResourceFields["securityConfirmation"]; field.Type != "password" {
		t.Fatalf("securityConfirmation field type = %q, expected password", field.Type)
	}
}

func TestConfigUpdateErrorIncludesStableCodeAndRequestDigest(t *testing.T) {
	schemas = getSchemas()
	request := httptest.NewRequest(http.MethodPost, "/v1-auth/config", strings.NewReader("{}"))
	response := httptest.NewRecorder()
	digest := strings.Repeat("a", 64)
	returnHTTPError(response, request, http.StatusForbidden, "MfaConfirmationRequired",
		"confirmation required", digest)

	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusForbidden || body["code"] != "MfaConfirmationRequired" ||
		body["requestDigest"] != digest {
		t.Fatalf("unexpected stable error response: status=%d body=%#v", response.Code, body)
	}
}
