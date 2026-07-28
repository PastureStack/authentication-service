package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestShibbolethRuntimeConfigurationIsNotJSONAddressable(t *testing.T) {
	payload := []byte(`{
		"idpMetadataUrl":"https://idp.example.test/metadata",
		"IDPMetadataFilePath":"../../attacker-metadata.xml",
		"idpMetadataFilePath":"../../attacker-metadata-lower.xml",
		"SPSelfSignedCertFilePath":"../../attacker-cert.pem",
		"SPSelfSignedKeyFilePath":"../../attacker-key.pem",
		"PlatformAPIHost":"https://attacker.example.test",
		"SamlServiceProvider":{"RedirectBackPath":"/attacker"}
	}`)

	var config ShibbolethConfig
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatalf("unmarshal SAML configuration: %v", err)
	}
	if config.IDPMetadataURL != "https://idp.example.test/metadata" {
		t.Fatalf("expected public configuration to be decoded, got %q", config.IDPMetadataURL)
	}
	if config.IDPMetadataFilePath != "" || config.SPSelfSignedCertFilePath != "" ||
		config.SPSelfSignedKeyFilePath != "" || config.PlatformAPIHost != "" ||
		config.SamlServiceProvider != nil {
		t.Fatal("runtime-only SAML configuration was accepted from JSON")
	}
}

func TestShibbolethRuntimeConfigurationIsNotSerialized(t *testing.T) {
	config := ShibbolethConfig{
		IDPMetadataURL:           "https://idp.example.test/metadata",
		IDPMetadataFilePath:      "/run/secrets/idp-metadata.xml",
		SPSelfSignedCertFilePath: "/run/secrets/saml-cert.pem",
		SPSelfSignedKeyFilePath:  "/run/secrets/saml-key.pem",
		PlatformAPIHost:          "https://platform.internal.test",
		SamlServiceProvider:      &PlatformSamlServiceProvider{},
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal SAML configuration: %v", err)
	}
	for _, forbidden := range []string{
		"IDPMetadataFilePath",
		"SPSelfSignedCertFilePath",
		"SPSelfSignedKeyFilePath",
		"PlatformAPIHost",
		"SamlServiceProvider",
		"/run/secrets/",
		"platform.internal.test",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("runtime-only value %q leaked through JSON: %s", forbidden, encoded)
		}
	}
}
