package shibboleth

import (
	"net/http"
	"testing"

	"github.com/PastureStack/authentication-service/model"
)

func testSAMLProvider() *SProvider {
	config := &model.ShibbolethConfig{
		UIDField:         "uid",
		UserNameField:    "username",
		DisplayNameField: "displayName",
		GroupsField:      "groups",
	}
	return &SProvider{shibClient: &SPClient{config: config}}
}

func TestGenerateTokenRejectsMalformedOrUnmappedSAMLData(t *testing.T) {
	provider := testSAMLProvider()
	for name, test := range map[string]struct {
		code   string
		status int
	}{
		"missing":      {"", http.StatusBadRequest},
		"invalid JSON": {"{", http.StatusBadRequest},
		"missing UID":  {`{"groups":["ops"]}`, http.StatusUnauthorized},
		"empty UID":    {`{"uid":[]}`, http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			if _, status, err := provider.GenerateToken(map[string]string{"code": test.code}); err == nil || status != test.status {
				t.Fatalf("GenerateToken status=%d err=%v, want status=%d and an error", status, err, test.status)
			}
		})
	}
}

func TestGenerateTokenBuildsOneUserAndDeduplicatedGroups(t *testing.T) {
	provider := testSAMLProvider()
	token, status, err := provider.GenerateToken(map[string]string{"code": `{
		"uid":["user-1"],
		"username":["alice"],
		"displayName":["Alice"],
		"groups":["ops","ops","dev"]
	}`})
	if err != nil || status != http.StatusOK {
		t.Fatalf("GenerateToken status=%d err=%v", status, err)
	}
	if token.ExternalAccountID != "user-1" || len(token.IdentityList) != 3 {
		t.Fatalf("unexpected token identities: %#v", token)
	}
	if !token.IdentityList[0].User || token.IdentityList[0].Login != "alice" {
		t.Fatalf("unexpected user identity: %#v", token.IdentityList[0])
	}
}
