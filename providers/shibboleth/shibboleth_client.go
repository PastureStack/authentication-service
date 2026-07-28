package shibboleth

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PastureStack/authentication-service/model"
	"github.com/PastureStack/authentication-service/outbound"
	"github.com/crewjam/saml"
	log "github.com/sirupsen/logrus"
)

const (
	maxIDPMetadataSize = 4 << 20
	minimumRSAKeyBits  = 2048
)

func allowInsecureIDPMetadataTLS() bool {
	value := strings.EqualFold(os.Getenv("PASTURESTACK_AUTH_ALLOW_INSECURE_IDP_METADATA_TLS"), "true") ||
		strings.EqualFold(os.Getenv("CATTLE_AUTH_ALLOW_INSECURE_IDP_METADATA_TLS"), "true")
	if value {
		log.Warn("Insecure IDP metadata TLS is enabled; Shibboleth metadata certificate verification is disabled")
	}
	return value
}

// SPClient implements a client for shibboleth and the saml library
type SPClient struct {
	config             *model.ShibbolethConfig
	runtimeConfig      RuntimeConfig
	metadataHTTPClient *http.Client
	originPolicy       *outbound.OriginPolicy
}

// RuntimeConfig contains trusted process-level values that must never be
// populated from the public authentication configuration API.
type RuntimeConfig struct {
	IDPMetadataFilePath      string
	SPSelfSignedCertFilePath string
	SPSelfSignedKeyFilePath  string
	PlatformAPIHost          string
}

func (spclient *SPClient) initializeSPClient(configToSet *model.ShibbolethConfig) error {
	if configToSet == nil {
		return fmt.Errorf("SAML configuration is required")
	}

	config := *configToSet
	originPolicy, err := outbound.FromEnvironment()
	if err != nil {
		return err
	}
	spclient.originPolicy = originPolicy
	var idpURL string
	var privKey *rsa.PrivateKey
	var cert *x509.Certificate
	var ok bool

	/* After auth is setup, the admin can change the access mode/allowed principals via admin access control page. When the admin clicks on "Save",
	a POST to v1-auth/config is made, which includes the entire model.ShibbolethConfig. During this call, the key and metadata aren't passed by UI
	that's why we won't return an error here, instead we can just return nil */
	if config.IDPMetadataURL == "" {
		idpURL = ""
		if config.IDPMetadataContent == "" {
			if spclient.runtimeConfig.IDPMetadataFilePath == "" {
				log.Debug("SAML service provider is not active because IDP metadata is missing")
			}
		}
	} else {
		idpURL = config.IDPMetadataURL
	}

	if config.SPSelfSignedCert == "" {
		if spclient.runtimeConfig.SPSelfSignedCertFilePath != "" {
			certBytes, err := os.ReadFile(spclient.runtimeConfig.SPSelfSignedCertFilePath)
			if err != nil {
				return fmt.Errorf("read SAML service-provider certificate: %w", err)
			}
			config.SPSelfSignedCert = string(certBytes)
		} else {
			log.Debug("SAML service-provider certificate is not configured")
		}
	}

	if config.SPSelfSignedKey == "" {
		if spclient.runtimeConfig.SPSelfSignedKeyFilePath != "" {
			key, err := os.ReadFile(spclient.runtimeConfig.SPSelfSignedKeyFilePath)
			if err != nil {
				return fmt.Errorf("read SAML service-provider private key: %w", err)
			}
			config.SPSelfSignedKey = string(key)
		} else {
			log.Debug("SAML service-provider private key is not configured")
		}
	}

	if config.SPSelfSignedKey != "" {
		// used from ssh.ParseRawPrivateKey
		block, remainder := pem.Decode([]byte(config.SPSelfSignedKey))
		if block == nil {
			return fmt.Errorf("SAML service-provider private key is not valid PEM")
		}
		if len(bytes.TrimSpace(remainder)) != 0 {
			return fmt.Errorf("SAML service-provider private key contains trailing data")
		}
		if strings.Contains(strings.ToUpper(block.Headers["Proc-Type"]), "ENCRYPTED") || x509.IsEncryptedPEMBlock(block) {
			return fmt.Errorf("encrypted SAML service-provider private keys are not supported")
		}

		switch block.Type {
		case "RSA PRIVATE KEY":
			privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("error parsing PKCS1 RSA key: %v", err)
			}
		case "PRIVATE KEY":
			pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("error parsing PKCS8 RSA key: %v", err)
			}
			privKey, ok = pk.(*rsa.PrivateKey)
			if !ok {
				return fmt.Errorf("unable to get rsa key")
			}
		default:
			return fmt.Errorf("unsupported SAML service-provider private key type %q", block.Type)
		}
		if err := privKey.Validate(); err != nil {
			return fmt.Errorf("validate SAML service-provider private key: %w", err)
		}
		if privKey.N.BitLen() < minimumRSAKeyBits {
			return fmt.Errorf("SAML service-provider RSA key must be at least %d bits", minimumRSAKeyBits)
		}
	}

	if config.SPSelfSignedCert != "" {
		block, remainder := pem.Decode([]byte(config.SPSelfSignedCert))
		if block == nil {
			return fmt.Errorf("SAML service-provider certificate is not valid PEM")
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("unsupported SAML service-provider certificate PEM type %q", block.Type)
		}
		if len(bytes.TrimSpace(remainder)) != 0 {
			return fmt.Errorf("SAML service-provider certificate contains trailing data")
		}
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse SAML service-provider certificate: %w", err)
		}
	}
	if privKey != nil && cert != nil {
		certKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok || certKey.E != privKey.PublicKey.E || certKey.N.Cmp(privKey.PublicKey.N) != 0 {
			return fmt.Errorf("SAML service-provider certificate does not match the private key")
		}
	}

	actURL, err := parseAbsoluteHTTPURL(spclient.runtimeConfig.PlatformAPIHost, "platform API host")
	if err != nil {
		return err
	}
	if actURL.RawQuery != "" {
		return fmt.Errorf("platform API host must not contain query parameters")
	}
	actURL.Path = strings.TrimRight(actURL.Path, "/") + "/v1-auth"

	metadataURL := *actURL
	metadataURL.Path += "/saml/metadata"
	acsURL := *actURL
	acsURL.Path += "/saml/acs"

	sp := &saml.ServiceProvider{
		Key:         privKey,
		Certificate: cert,
		MetadataURL: metadataURL,
		AcsURL:      acsURL,
	}

	cookieStore := model.CookieSAMLClientState{
		ServiceProvider: sp,
	}

	if idpURL != "" {
		if _, err := parseAbsoluteHTTPURL(idpURL, "IDP metadata URL"); err != nil {
			return err
		}
		if !spclient.originPolicy.IsValidRedirectURL(idpURL) {
			return fmt.Errorf("IDP metadata origin is not authorized by %s", outbound.AllowedOriginsEnvironment)
		}
		resp, err := spclient.httpClient().Get(idpURL)
		if err != nil {
			return fmt.Errorf("download IDP metadata: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return fmt.Errorf("download IDP metadata: unexpected HTTP status %d", resp.StatusCode)
		}
		sp.IDPMetadata, err = decodeIDPMetadata(resp.Body)
		if err != nil {
			return err
		}
	} else if config.IDPMetadataContent != "" {
		sp.IDPMetadata, err = decodeIDPMetadata(strings.NewReader(config.IDPMetadataContent))
		if err != nil {
			return err
		}
	} else if spclient.runtimeConfig.IDPMetadataFilePath != "" {
		file, err := os.Open(spclient.runtimeConfig.IDPMetadataFilePath)
		if err != nil {
			return fmt.Errorf("open IDP metadata file: %w", err)
		}
		defer file.Close()
		sp.IDPMetadata, err = decodeIDPMetadata(file)
		if err != nil {
			return err
		}
	}
	if sp.IDPMetadata != nil {
		if err := spclient.validateMetadataDestinations(sp.IDPMetadata); err != nil {
			return err
		}
		if spclient.originPolicy != nil {
			sp.HTTPClient = spclient.httpClient()
		}
	}

	rsp := &model.PlatformSamlServiceProvider{
		ServiceProvider: *sp,
		ClientState:     cookieStore,
	}

	config.SamlServiceProvider = rsp
	*configToSet = config
	spclient.config = configToSet
	return nil
}

func (spclient *SPClient) validateMetadataDestinations(metadata *saml.EntityDescriptor) error {
	if metadata == nil || spclient.originPolicy == nil {
		return nil
	}
	for _, descriptor := range metadata.IDPSSODescriptors {
		for _, endpoint := range descriptor.ArtifactResolutionServices {
			if endpoint.Location == "" {
				continue
			}
			if _, err := parseAbsoluteHTTPURL(endpoint.Location, "IDP artifact resolution URL"); err != nil {
				return err
			}
			if !spclient.originPolicy.IsValidRedirectURL(endpoint.Location) {
				return fmt.Errorf("IDP artifact resolution origin is not authorized by %s", outbound.AllowedOriginsEnvironment)
			}
		}
	}
	return nil
}

func (spclient *SPClient) httpClient() *http.Client {
	if spclient.metadataHTTPClient != nil {
		return spclient.metadataHTTPClient
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: allowInsecureIDPMetadataTLS(), // #nosec G402 -- explicit break-glass option, warned above.
		MinVersion:         tls.VersionTLS12,
	}}
	return &http.Client{
		Transport: &outbound.PolicyTransport{Base: transport, Policy: spclient.originPolicy},
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("IDP metadata redirect limit exceeded")
			}
			if _, err := parseAbsoluteHTTPURL(req.URL.String(), "IDP metadata redirect URL"); err != nil {
				return err
			}
			if len(via) == 0 || !outbound.SameOrigin(via[0].URL, req.URL) {
				return fmt.Errorf("IDP metadata redirect changed the authorized origin")
			}
			if spclient.originPolicy == nil || !spclient.originPolicy.IsValidRedirectURL(req.URL.String()) {
				return fmt.Errorf("IDP metadata redirect target is not authorized")
			}
			return nil
		},
	}
}

func parseAbsoluteHTTPURL(rawValue string, fieldName string) (*url.URL, error) {
	if strings.ContainsAny(rawValue, "\r\n") {
		return nil, fmt.Errorf("%s contains control characters", fieldName)
	}
	parsed, err := url.Parse(strings.TrimSpace(rawValue))
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("%s must be an absolute HTTP or HTTPS URL", fieldName)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must not contain user information or a fragment", fieldName)
	}
	return parsed, nil
}

func decodeIDPMetadata(reader io.Reader) (*saml.EntityDescriptor, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxIDPMetadataSize+1))
	if err != nil {
		return nil, fmt.Errorf("read IDP metadata: %w", err)
	}
	if len(data) > maxIDPMetadataSize {
		return nil, fmt.Errorf("IDP metadata exceeds %d bytes", maxIDPMetadataSize)
	}
	metadata := &saml.EntityDescriptor{}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(metadata); err != nil {
		return nil, fmt.Errorf("decode IDP metadata XML: %w", err)
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode IDP metadata XML: %w", err)
		}
		if text, ok := token.(xml.CharData); ok && len(bytes.TrimSpace(text)) == 0 {
			continue
		}
		return nil, fmt.Errorf("IDP metadata contains trailing XML content")
	}
	return metadata, nil
}

func (spclient *SPClient) getShibIdentities(samlData map[string][]string) ([]Account, error) {
	//look for saml attributes set in the config
	if spclient == nil || spclient.config == nil {
		return nil, fmt.Errorf("SAML provider is not configured")
	}
	uidField := strings.TrimSpace(spclient.config.UIDField)
	if uidField == "" {
		return nil, fmt.Errorf("SAML UID attribute is not configured")
	}
	uid := firstNonEmpty(samlData[uidField])
	if uid == "" {
		return nil, fmt.Errorf("SAML assertion does not contain a non-empty UID attribute")
	}

	shibAcct := Account{
		UID:         uid,
		DisplayName: firstNonEmpty(samlData[spclient.config.DisplayNameField]),
		UserName:    firstNonEmpty(samlData[spclient.config.UserNameField]),
		IsGroup:     false,
	}
	if shibAcct.UserName == "" {
		shibAcct.UserName = uid
	}
	if shibAcct.DisplayName == "" {
		shibAcct.DisplayName = shibAcct.UserName
	}
	shibAccts := []Account{shibAcct}

	seenGroups := map[string]struct{}{}
	for _, rawGroup := range samlData[spclient.config.GroupsField] {
		group := strings.TrimSpace(rawGroup)
		if group == "" {
			continue
		}
		if _, found := seenGroups[group]; found {
			continue
		}
		seenGroups[group] = struct{}{}
		shibAccts = append(shibAccts, Account{UID: group, IsGroup: true, DisplayName: group})
	}

	return shibAccts, nil
}

func firstNonEmpty(values []string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
