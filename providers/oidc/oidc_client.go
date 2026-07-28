package oidc

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PastureStack/authentication-service/model"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rancher/go-rancher/v2"
)

const (
	maxDocumentSize = 2 << 20
	maxTokenSize    = 256 << 10
	requestTimeout  = 12 * time.Second
	clockSkew       = 90 * time.Second
)

type discoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	IDTokenSigningAlgorithmsSupported []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

type authorizationResponse struct {
	AuthorizationCode string `json:"authorizationCode"`
	CodeVerifier      string `json:"codeVerifier"`
	Nonce             string `json:"nonce"`
}

type tokenEndpointResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Client owns one immutable provider configuration and its bounded discovery
// and signing-key cache.
type Client struct {
	config     *model.OIDCConfig
	discovery  discoveryDocument
	httpClient *http.Client

	keyMutex  sync.Mutex
	keys      []jwk
	keysUntil time.Time
}

func (c *Client) initialize() error {
	if c.config == nil {
		return fmt.Errorf("OIDC configuration is missing")
	}

	normalizeConfig(c.config)
	if err := validateConfig(c.config); err != nil {
		return err
	}

	httpClient, err := newHTTPClient(c.config.CertificateAuthority)
	if err != nil {
		return err
	}
	c.httpClient = httpClient

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if err := c.fetchDiscovery(ctx); err != nil {
		return err
	}
	return nil
}

func normalizeConfig(config *model.OIDCConfig) {
	config.DisplayName = strings.TrimSpace(config.DisplayName)
	config.WellKnownURL = strings.TrimSpace(config.WellKnownURL)
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.Scopes = strings.Join(strings.Fields(config.Scopes), " ")
	config.UsernameClaim = strings.TrimSpace(config.UsernameClaim)
	config.DisplayNameClaim = strings.TrimSpace(config.DisplayNameClaim)
	config.EmailClaim = strings.TrimSpace(config.EmailClaim)
	config.GroupsClaim = strings.TrimSpace(config.GroupsClaim)
	config.CertificateAuthority = strings.TrimSpace(config.CertificateAuthority)

	if config.DisplayName == "" {
		config.DisplayName = "OpenID Connect"
	}
	if config.Scopes == "" {
		config.Scopes = "openid"
	}
	if config.UsernameClaim == "" {
		config.UsernameClaim = "preferred_username"
	}
	if config.DisplayNameClaim == "" {
		config.DisplayNameClaim = "name"
	}
	if config.EmailClaim == "" {
		config.EmailClaim = "email"
	}
}

func validateConfig(config *model.OIDCConfig) error {
	if config.WellKnownURL == "" {
		return fmt.Errorf("OIDC discovery URL is required")
	}
	if _, err := validateEndpoint(config.WellKnownURL); err != nil {
		return fmt.Errorf("invalid OIDC discovery URL: %v", err)
	}
	if config.ClientID == "" {
		return fmt.Errorf("OIDC client ID is required")
	}
	if config.ClientSecret == "" && !config.ClientSecretSet {
		return fmt.Errorf("OIDC client secret is required")
	}

	scopes := strings.Fields(config.Scopes)
	if !contains(scopes, "openid") {
		return fmt.Errorf("OIDC scopes must include openid")
	}
	if config.UsePKCE && !contains(scopes, "openid") {
		return fmt.Errorf("OIDC PKCE requires the openid scope")
	}
	return nil
}

func newHTTPClient(customCA string) (*http.Client, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if customCA != "" && !rootCAs.AppendCertsFromPEM([]byte(customCA)) {
		return nil, fmt.Errorf("OIDC certificate authority does not contain a valid PEM certificate")
	}

	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("OIDC endpoint redirected too many times")
		}
		if _, err := validateEndpoint(req.URL.String()); err != nil {
			return fmt.Errorf("unsafe OIDC redirect: %v", err)
		}
		if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("OIDC endpoint refused an HTTPS downgrade redirect")
		}
		return nil
	}
	return client, nil
}

func validateEndpoint(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if parsed.User != nil || parsed.Host == "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("URL must have a host and must not contain credentials or a fragment")
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if parsed.Scheme == "http" && (strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())) {
		return parsed, nil
	}
	return nil, fmt.Errorf("HTTPS is required except for loopback test endpoints")
}

func (c *Client) fetchDiscovery(ctx context.Context) error {
	var document discoveryDocument
	if err := c.getJSON(ctx, c.config.WellKnownURL, "", &document); err != nil {
		return fmt.Errorf("OIDC discovery failed: %v", err)
	}

	required := map[string]string{
		"issuer":                 document.Issuer,
		"authorization_endpoint": document.AuthorizationEndpoint,
		"token_endpoint":         document.TokenEndpoint,
		"userinfo_endpoint":      document.UserInfoEndpoint,
		"jwks_uri":               document.JWKSURI,
	}
	for name, endpoint := range required {
		if endpoint == "" {
			return fmt.Errorf("OIDC discovery response is missing %s", name)
		}
		if _, err := validateEndpoint(endpoint); err != nil {
			return fmt.Errorf("OIDC discovery %s is invalid: %v", name, err)
		}
	}
	issuer, err := validateEndpoint(document.Issuer)
	if err != nil || issuer.RawQuery != "" {
		return fmt.Errorf("OIDC discovery issuer must be an absolute HTTPS URL without a query or fragment")
	}
	if len(document.IDTokenSigningAlgorithmsSupported) == 0 {
		document.IDTokenSigningAlgorithmsSupported = []string{"RS256"}
	}
	if !hasSafeSigningAlgorithm(document.IDTokenSigningAlgorithmsSupported) {
		return fmt.Errorf("OIDC provider does not advertise a supported asymmetric ID-token signing algorithm")
	}
	if c.config.UsePKCE && len(document.CodeChallengeMethodsSupported) > 0 &&
		!contains(document.CodeChallengeMethodsSupported, "S256") {
		return fmt.Errorf("OIDC provider does not advertise PKCE S256 support")
	}
	if err := validateClientAuthMethods(document.TokenEndpointAuthMethodsSupported); err != nil {
		return err
	}
	c.discovery = document
	return nil
}

func (c *Client) authorizationURL() string {
	if c.discovery.AuthorizationEndpoint == "" {
		return ""
	}
	parsed, err := url.Parse(c.discovery.AuthorizationEndpoint)
	if err != nil {
		return ""
	}
	query := parsed.Query()
	query.Set("client_id", c.config.ClientID)
	query.Set("response_type", "code")
	query.Set("scope", c.config.Scopes)
	query.Set("redirect_uri", c.callbackURL())
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (c *Client) callbackURL() string {
	base := strings.TrimRight(strings.TrimSpace(c.config.PlatformAPIHost), "/")
	if base == "" {
		base = "http://localhost:8080"
	}
	return base + "/login/oidc-auth"
}

func (c *Client) generateToken(input map[string]string) (model.Token, int, error) {
	var response authorizationResponse
	if err := json.Unmarshal([]byte(input["code"]), &response); err != nil {
		return model.Token{}, http.StatusBadRequest, fmt.Errorf("OIDC authorization response is invalid")
	}
	response.AuthorizationCode = strings.TrimSpace(response.AuthorizationCode)
	response.CodeVerifier = strings.TrimSpace(response.CodeVerifier)
	response.Nonce = strings.TrimSpace(response.Nonce)
	if response.AuthorizationCode == "" || len(response.Nonce) < 32 {
		return model.Token{}, http.StatusBadRequest, fmt.Errorf("OIDC authorization code or nonce is missing")
	}
	if c.config.UsePKCE && !validCodeVerifier(response.CodeVerifier) {
		return model.Token{}, http.StatusBadRequest, fmt.Errorf("OIDC PKCE code verifier is invalid")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	tokenResponse, err := c.exchangeCode(ctx, response)
	if err != nil {
		return model.Token{}, http.StatusUnauthorized, err
	}

	claims, algorithm, err := c.verifyIDToken(ctx, tokenResponse.IDToken, response.Nonce)
	if err != nil {
		return model.Token{}, http.StatusUnauthorized, err
	}
	if err := validateAccessTokenHash(claims, tokenResponse.AccessToken, algorithm); err != nil {
		return model.Token{}, http.StatusUnauthorized, err
	}

	claimMap := map[string]interface{}(claims)
	userInfo, err := c.getUserInfoContext(ctx, tokenResponse.AccessToken)
	if err != nil {
		return model.Token{}, http.StatusUnauthorized, err
	}
	if claimString(userInfo, "sub") != claimString(claimMap, "sub") {
		return model.Token{}, http.StatusUnauthorized, fmt.Errorf("OIDC UserInfo subject does not match the ID token")
	}
	mergeProfileClaims(claimMap, userInfo)
	return c.tokenFromClaims(tokenResponse.AccessToken, claimMap)
}

func validCodeVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, char := range verifier {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("-._~", char) {
			continue
		}
		return false
	}
	return true
}

func (c *Client) exchangeCode(ctx context.Context, response authorizationResponse) (tokenEndpointResponse, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {response.AuthorizationCode},
		"redirect_uri": {c.callbackURL()},
		"client_id":    {c.config.ClientID},
	}
	if c.config.UsePKCE {
		form.Set("code_verifier", response.CodeVerifier)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenEndpointResponse{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	method := preferredClientAuthMethod(c.discovery.TokenEndpointAuthMethodsSupported)
	switch method {
	case "client_secret_basic":
		request.SetBasicAuth(c.config.ClientID, c.config.ClientSecret)
	case "client_secret_post":
		form.Set("client_secret", c.config.ClientSecret)
		request.Body = io.NopCloser(strings.NewReader(form.Encode()))
		request.ContentLength = int64(len(form.Encode()))
	default:
		return tokenEndpointResponse{}, fmt.Errorf("OIDC token endpoint has no supported confidential-client authentication method")
	}

	httpResponse, err := c.httpClient.Do(request)
	if err != nil {
		return tokenEndpointResponse{}, fmt.Errorf("OIDC token exchange failed: %v", err)
	}
	defer httpResponse.Body.Close()

	var tokenResponse tokenEndpointResponse
	if err := decodeJSON(httpResponse.Body, &tokenResponse); err != nil {
		return tokenEndpointResponse{}, fmt.Errorf("OIDC token endpoint returned invalid JSON: %v", err)
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		message := tokenResponse.Error
		if tokenResponse.ErrorDescription != "" {
			message += ": " + tokenResponse.ErrorDescription
		}
		if message == "" {
			message = http.StatusText(httpResponse.StatusCode)
		}
		return tokenEndpointResponse{}, fmt.Errorf("OIDC token exchange was rejected: %s", message)
	}
	if tokenResponse.AccessToken == "" || tokenResponse.IDToken == "" {
		return tokenEndpointResponse{}, fmt.Errorf("OIDC token response is missing access_token or id_token")
	}
	if len(tokenResponse.IDToken) > maxTokenSize || len(tokenResponse.AccessToken) > maxTokenSize {
		return tokenEndpointResponse{}, fmt.Errorf("OIDC token response exceeds the supported size")
	}
	if tokenResponse.TokenType != "" && !strings.EqualFold(tokenResponse.TokenType, "Bearer") {
		return tokenEndpointResponse{}, fmt.Errorf("OIDC token endpoint returned unsupported token type %q", tokenResponse.TokenType)
	}
	return tokenResponse, nil
}

func preferredClientAuthMethod(methods []string) string {
	if len(methods) == 0 || contains(methods, "client_secret_basic") {
		return "client_secret_basic"
	}
	if contains(methods, "client_secret_post") {
		return "client_secret_post"
	}
	return ""
}

func validateClientAuthMethods(methods []string) error {
	if preferredClientAuthMethod(methods) == "" {
		return fmt.Errorf("OIDC provider does not support client_secret_basic or client_secret_post")
	}
	return nil
}

func (c *Client) verifyIDToken(ctx context.Context, rawToken string, expectedNonce string) (jwt.MapClaims, string, error) {
	allowedAlgorithms := safeSigningAlgorithms(c.discovery.IDTokenSigningAlgorithmsSupported)
	var signingAlgorithm string

	parse := func() (jwt.MapClaims, *jwt.Token, error) {
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (interface{}, error) {
			signingAlgorithm = token.Method.Alg()
			if !contains(allowedAlgorithms, signingAlgorithm) {
				return nil, fmt.Errorf("OIDC ID token uses disallowed signing algorithm %q", signingAlgorithm)
			}
			keyID, _ := token.Header["kid"].(string)
			return c.signingKey(ctx, keyID, signingAlgorithm)
		},
			jwt.WithValidMethods(allowedAlgorithms),
			jwt.WithIssuer(c.discovery.Issuer),
			jwt.WithAudience(c.config.ClientID),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithLeeway(clockSkew),
		)
		return claims, token, err
	}

	claims, token, err := parse()
	if err != nil {
		c.invalidateSigningKeys()
		claims, token, err = parse()
	}
	if err != nil || token == nil || !token.Valid {
		return nil, "", fmt.Errorf("OIDC ID token validation failed: %v", err)
	}
	issuedAt, err := claims.GetIssuedAt()
	if err != nil || issuedAt == nil {
		return nil, "", fmt.Errorf("OIDC ID token is missing a valid iat claim")
	}

	claimMap := map[string]interface{}(claims)
	subject := claimString(claimMap, "sub")
	nonce := claimString(claimMap, "nonce")
	if subject == "" {
		return nil, "", fmt.Errorf("OIDC ID token is missing sub")
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(nonce), []byte(expectedNonce)) != 1 {
		return nil, "", fmt.Errorf("OIDC ID token nonce does not match the authorization transaction")
	}

	audience, err := claims.GetAudience()
	if err != nil {
		return nil, "", fmt.Errorf("OIDC ID token audience is invalid")
	}
	authorizedParty := claimString(claimMap, "azp")
	if (len(audience) > 1 || authorizedParty != "") && authorizedParty != c.config.ClientID {
		return nil, "", fmt.Errorf("OIDC ID token azp does not match the client ID")
	}
	return claims, signingAlgorithm, nil
}

func validateAccessTokenHash(claims jwt.MapClaims, accessToken string, algorithm string) error {
	expected := claimString(map[string]interface{}(claims), "at_hash")
	if expected == "" {
		return nil
	}

	var hash crypto.Hash
	switch algorithm {
	case "RS256", "PS256", "ES256":
		hash = crypto.SHA256
	case "RS384", "PS384", "ES384":
		hash = crypto.SHA384
	case "RS512", "PS512", "ES512":
		hash = crypto.SHA512
	default:
		return fmt.Errorf("OIDC at_hash cannot be validated for signing algorithm %q", algorithm)
	}

	var digest []byte
	switch hash {
	case crypto.SHA256:
		sum := sha256.Sum256([]byte(accessToken))
		digest = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384([]byte(accessToken))
		digest = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512([]byte(accessToken))
		digest = sum[:]
	}
	actual := base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return fmt.Errorf("OIDC ID token at_hash does not match the access token")
	}
	return nil
}

func (c *Client) tokenFromUserInfo(accessToken string) (model.Token, int, error) {
	claims, err := c.getUserInfo(accessToken)
	if err != nil {
		return model.Token{}, http.StatusUnauthorized, err
	}
	return c.tokenFromClaims(accessToken, claims)
}

func (c *Client) tokenFromClaims(accessToken string, claims map[string]interface{}) (model.Token, int, error) {
	identities, err := c.identitiesFromClaims(claims)
	if err != nil {
		return model.Token{}, http.StatusUnauthorized, err
	}

	token := model.Token{
		Resource: client.Resource{
			Type: "token",
		},
		Type:         TokenType,
		IdentityList: identities,
		AccessToken:  accessToken,
	}
	for _, identity := range identities {
		if identity.ExternalIdType == UserType {
			token.ExternalAccountID = identity.ExternalId
			break
		}
	}
	if token.ExternalAccountID == "" {
		return model.Token{}, http.StatusUnauthorized, fmt.Errorf("OIDC user identity was not produced")
	}
	return token, 0, nil
}

func (c *Client) getUserInfo(accessToken string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	return c.getUserInfoContext(ctx, accessToken)
}

func (c *Client) getUserInfoContext(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	var claims map[string]interface{}
	if err := c.getJSON(ctx, c.discovery.UserInfoEndpoint, accessToken, &claims); err != nil {
		return nil, fmt.Errorf("OIDC UserInfo request failed: %v", err)
	}
	if claimString(claims, "sub") == "" {
		return nil, fmt.Errorf("OIDC UserInfo response is missing sub")
	}
	return claims, nil
}

func (c *Client) identitiesFromClaims(claims map[string]interface{}) ([]client.Identity, error) {
	subject := claimString(claims, "sub")
	if subject == "" {
		return nil, fmt.Errorf("OIDC claims are missing sub")
	}

	username := stringValue(claimValue(claims, c.config.UsernameClaim))
	if username == "" {
		username = stringValue(claimValue(claims, c.config.EmailClaim))
	}
	if username == "" {
		username = subject
	}
	displayName := stringValue(claimValue(claims, c.config.DisplayNameClaim))
	if displayName == "" {
		displayName = username
	}

	externalSubject := c.discovery.Issuer + "|" + subject
	user := client.Identity{
		Resource: client.Resource{
			Id:   UserType + ":" + externalSubject,
			Type: "identity",
		},
		ExternalId:     externalSubject,
		ExternalIdType: UserType,
		Login:          username,
		Name:           displayName,
		ProfilePicture: stringValue(claimValue(claims, "picture")),
		ProfileUrl:     stringValue(claimValue(claims, "profile")),
		User:           true,
	}
	identities := []client.Identity{user}

	groups := stringValues(claimValue(claims, c.config.GroupsClaim))
	seen := map[string]bool{}
	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" || seen[group] {
			continue
		}
		seen[group] = true
		externalGroup := c.discovery.Issuer + "|" + group
		identities = append(identities, client.Identity{
			Resource: client.Resource{
				Id:   GroupType + ":" + externalGroup,
				Type: "identity",
			},
			ExternalId:     externalGroup,
			ExternalIdType: GroupType,
			Login:          group,
			Name:           group,
			User:           false,
		})
	}
	return identities, nil
}

func (c *Client) getJSON(ctx context.Context, endpoint string, bearerToken string, destination interface{}) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("endpoint returned HTTP %d", response.StatusCode)
	}
	return decodeJSON(response.Body, destination)
}

func decodeJSON(reader io.Reader, destination interface{}) error {
	decoder := json.NewDecoder(io.LimitReader(reader, maxDocumentSize+1))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("response contains more than one JSON value")
		}
		return err
	}
	return nil
}

func claimValue(claims map[string]interface{}, path string) interface{} {
	if path == "" {
		return nil
	}
	var current interface{} = claims
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current, ok = object[part]
		if !ok {
			return nil
		}
	}
	return current
}

func claimString(claims map[string]interface{}, name string) string {
	return stringValue(claimValue(claims, name))
}

func stringValue(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func stringValues(value interface{}) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []interface{}:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if value := stringValue(item); value != "" {
				values = append(values, value)
			}
		}
		return values
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

func mergeProfileClaims(destination map[string]interface{}, source map[string]interface{}) {
	for key, value := range source {
		switch key {
		case "iss", "aud", "exp", "iat", "nbf", "nonce", "azp", "at_hash", "c_hash":
			continue
		default:
			destination[key] = value
		}
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func hasSafeSigningAlgorithm(algorithms []string) bool {
	return len(safeSigningAlgorithms(algorithms)) > 0
}

func safeSigningAlgorithms(algorithms []string) []string {
	supported := map[string]bool{
		"RS256": true,
		"RS384": true,
		"RS512": true,
		"PS256": true,
		"PS384": true,
		"PS512": true,
		"ES256": true,
		"ES384": true,
		"ES512": true,
		"EdDSA": true,
	}
	result := make([]string, 0, len(algorithms))
	for _, algorithm := range algorithms {
		if supported[algorithm] {
			result = append(result, algorithm)
		}
	}
	return result
}
