package shibboleth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PastureStack/authentication-service/model"
)

const testIDPMetadata = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/metadata"></EntityDescriptor>`

func generateSAMLKeyPair(t *testing.T, bits int) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "sp.example"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(keyPEM), string(certPEM)
}

func validSAMLConfig(t *testing.T) model.ShibbolethConfig {
	t.Helper()
	key, cert := generateSAMLKeyPair(t, minimumRSAKeyBits)
	return model.ShibbolethConfig{
		PlatformAPIHost:    "https://platform.example",
		SPSelfSignedKey:    key,
		SPSelfSignedCert:   cert,
		IDPMetadataContent: testIDPMetadata,
		UIDField:           "uid",
		UserNameField:      "username",
		DisplayNameField:   "displayName",
		GroupsField:        "groups",
	}
}

func TestInitializeSPClientValidatesKeyCertificateAndMetadata(t *testing.T) {
	config := validSAMLConfig(t)
	client := &SPClient{}
	if err := client.initializeSPClient(&config); err != nil {
		t.Fatalf("initialize SAML client: %v", err)
	}
	if client.config != &config || config.SamlServiceProvider == nil {
		t.Fatal("validated SAML configuration was not activated")
	}
	provider := config.SamlServiceProvider.ServiceProvider
	if provider.Key == nil || provider.Certificate == nil || provider.IDPMetadata == nil {
		t.Fatal("validated SAML runtime is incomplete")
	}
	if provider.MetadataURL.String() != "https://platform.example/v1-auth/saml/metadata" {
		t.Fatalf("unexpected metadata URL %q", provider.MetadataURL.String())
	}
}

func TestInitializeSPClientRejectsMissingOrUnsafeBaseConfiguration(t *testing.T) {
	if err := (&SPClient{}).initializeSPClient(nil); err == nil {
		t.Fatal("nil SAML configuration was accepted")
	}
	for name, host := range map[string]string{
		"relative":          "/platform",
		"userinfo":          "https://user:password@platform.example",
		"fragment":          "https://platform.example/#fragment",
		"query":             "https://platform.example/?tenant=one",
		"control character": "https://platform.example\r\nX-Test: yes",
		"missing hostname":  "https://:443",
	} {
		t.Run(name, func(t *testing.T) {
			config := validSAMLConfig(t)
			config.PlatformAPIHost = host
			if err := (&SPClient{}).initializeSPClient(&config); err == nil {
				t.Fatalf("unsafe platform API host %q was accepted", host)
			}
		})
	}
}

func TestInitializeSPClientRejectsInvalidOrMismatchedCredentialsWithoutActivation(t *testing.T) {
	firstKey, firstCert := generateSAMLKeyPair(t, minimumRSAKeyBits)
	_, secondCert := generateSAMLKeyPair(t, minimumRSAKeyBits)
	tweak := map[string]func(*model.ShibbolethConfig){
		"invalid certificate PEM": func(config *model.ShibbolethConfig) { config.SPSelfSignedCert = "not pem" },
		"wrong PEM type": func(config *model.ShibbolethConfig) {
			config.SPSelfSignedCert = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")}))
		},
		"mismatched key": func(config *model.ShibbolethConfig) {
			config.SPSelfSignedKey = firstKey
			config.SPSelfSignedCert = secondCert
		},
	}
	for name, mutate := range tweak {
		t.Run(name, func(t *testing.T) {
			config := validSAMLConfig(t)
			config.SPSelfSignedCert = firstCert
			mutate(&config)
			client := &SPClient{}
			if err := client.initializeSPClient(&config); err == nil {
				t.Fatal("invalid SAML credentials were accepted")
			}
			if client.config != nil || config.SamlServiceProvider != nil {
				t.Fatal("failed SAML configuration was activated")
			}
		})
	}
}

func TestInitializeSPClientRejectsWeakRSAKey(t *testing.T) {
	key, cert := generateSAMLKeyPair(t, 1024)
	config := validSAMLConfig(t)
	config.SPSelfSignedKey = key
	config.SPSelfSignedCert = cert
	if err := (&SPClient{}).initializeSPClient(&config); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("weak RSA key was not rejected: %v", err)
	}
}

func TestInitializeSPClientConstrainsMetadataDownload(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"non success status": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusBadGateway) },
		"oversized response": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", maxIDPMetadataSize+1)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			config := validSAMLConfig(t)
			config.IDPMetadataContent = ""
			config.IDPMetadataURL = server.URL
			if err := (&SPClient{}).initializeSPClient(&config); err == nil {
				t.Fatal("unsafe metadata response was accepted")
			}
		})
	}
}

func TestInitializeSPClientDownloadsValidMetadataWithQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("tenant") != "one" {
			http.Error(w, "missing tenant", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(testIDPMetadata))
	}))
	defer server.Close()
	config := validSAMLConfig(t)
	config.IDPMetadataContent = ""
	config.IDPMetadataURL = server.URL + "/metadata?tenant=one"
	if err := (&SPClient{}).initializeSPClient(&config); err != nil {
		t.Fatalf("download valid IDP metadata: %v", err)
	}
	if config.SamlServiceProvider == nil || config.SamlServiceProvider.ServiceProvider.IDPMetadata == nil {
		t.Fatal("downloaded IDP metadata was not activated")
	}
}

func TestDecodeIDPMetadataRejectsTrailingXML(t *testing.T) {
	for name, value := range map[string]string{
		"second document": testIDPMetadata + `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>`,
		"trailing text":   testIDPMetadata + "unexpected",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeIDPMetadata(strings.NewReader(value)); err == nil {
				t.Fatal("trailing IDP metadata content was accepted")
			}
		})
	}
	if _, err := decodeIDPMetadata(strings.NewReader(testIDPMetadata + " \n\t")); err != nil {
		t.Fatalf("trailing XML whitespace was rejected: %v", err)
	}
}

func TestMetadataHTTPClientEnforcesTimeoutTLSAndRedirectPolicy(t *testing.T) {
	client := (&SPClient{}).httpClient()
	if client.Timeout != 15*time.Second {
		t.Fatalf("unexpected metadata timeout %v", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("metadata client does not require TLS 1.2: %#v", client.Transport)
	}
	httpsRequest, _ := http.NewRequest(http.MethodGet, "https://idp.example/metadata", nil)
	httpRequest, _ := http.NewRequest(http.MethodGet, "http://idp.example/metadata", nil)
	if err := client.CheckRedirect(httpRequest, []*http.Request{httpsRequest}); err == nil {
		t.Fatal("HTTPS-to-HTTP metadata redirect was accepted")
	}
	redirects := []*http.Request{httpsRequest, httpsRequest, httpsRequest}
	if err := client.CheckRedirect(httpsRequest, redirects); err == nil {
		t.Fatal("metadata redirect limit was not enforced")
	}
}

func TestInitializeSPClientMetadataTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(testIDPMetadata))
	}))
	defer server.Close()
	config := validSAMLConfig(t)
	config.IDPMetadataContent = ""
	config.IDPMetadataURL = server.URL
	client := &SPClient{metadataHTTPClient: &http.Client{Timeout: 10 * time.Millisecond}}
	if err := client.initializeSPClient(&config); err == nil {
		t.Fatal("metadata timeout was ignored")
	}
}

func TestGetShibIdentitiesRejectsMissingUIDAndNormalizesValues(t *testing.T) {
	config := validSAMLConfig(t)
	client := &SPClient{config: &config}
	for name, data := range map[string]map[string][]string{
		"missing": {},
		"empty":   {"uid": {}},
		"blank":   {"uid": {"  "}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.getShibIdentities(data); err == nil {
				t.Fatal("missing UID was accepted")
			}
		})
	}
	accounts, err := client.getShibIdentities(map[string][]string{
		"uid":    {" user-1 "},
		"groups": {" ops ", "", "ops", "dev"},
	})
	if err != nil {
		t.Fatalf("map identities: %v", err)
	}
	if len(accounts) != 3 || accounts[0].UID != "user-1" || accounts[0].UserName != "user-1" {
		t.Fatalf("unexpected normalized accounts: %#v", accounts)
	}
}
