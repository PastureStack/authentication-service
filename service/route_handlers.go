package service

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PastureStack/authentication-service/model"
	"github.com/PastureStack/authentication-service/server"
	"github.com/crewjam/saml"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/v2"
	log "github.com/sirupsen/logrus"
)

const (
	maxAuthRequestSize = 1 << 20
	redirectBackBase   = "redirectBackBase"
	redirectBackPath   = "redirectBackPath"
	postSamlTokenHTML  = "/v1-auth/saml/tokenhtml"
	defaultSAMLPath    = "/login/shibboleth-auth"
	samlStateIssuer    = "pasturestack-authentication-service"
	samlStateAudience  = "pasturestack-saml-relay-state"
	tpl                = `
<!DOCTYPE html>
<html>
  <head>
	<meta name="referrer" content="no-referrer" />
    <script nonce="{{.Nonce}}">
      window.onload = function() {
        document.getElementById('TokenHTMLResponseForm').submit();
      }
    </script>
  </head>
  <body>
    <form method="post" action="{{.URL}}" id="TokenHTMLResponseForm">
      <input type="hidden" name="token" value="{{.Token}}" />
      <input type="hidden" name="finalRedirectURL" value="{{.FinalRedirectURL}}" />
    </form>
  </body>
</html>`
)

var (
	errAuthRequestTooLarge = errors.New("authentication request is too large")
	samlPostFormTemplate   = template.Must(template.New("saml-post-form").Parse(tpl))
	validatePlatformToken  = server.ValidatePlatformToken
)

// CreateToken is a handler for route /token and returns the jwt token after authenticating the user
func CreateToken(w http.ResponseWriter, r *http.Request) {
	body, err := readAuthRequestBody(r)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errAuthRequestTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		ReturnHTTPError(w, r, status, err.Error())
		return
	}
	var jsonInput map[string]string
	if err := json.Unmarshal(body, &jsonInput); err != nil {
		ReturnHTTPError(w, r, http.StatusBadRequest, "Invalid authentication request")
		return
	}

	securityCode := jsonInput["code"]
	accessToken := jsonInput["accessToken"]

	if securityCode != "" {
		log.Debugf("CreateToken called with securityCode")
		//getToken
		token, status, err := server.CreateToken(jsonInput)
		if err != nil {
			log.Errorf("GetToken failed with error: %v", err)
			if status == 0 {
				status = http.StatusInternalServerError
			}
			ReturnHTTPError(w, r, status, fmt.Sprintf("%v", err))
			return
		}
		api.GetApiContext(r).Write(&token)
	} else if accessToken != "" {
		log.Debug("RefreshToken called with an access token")
		//getToken
		token, status, err := server.RefreshToken(jsonInput)
		if err != nil {
			log.Errorf("GetToken failed with error: %v", err)
			if status == 0 {
				status = http.StatusInternalServerError
			}
			ReturnHTTPError(w, r, status, fmt.Sprintf("%v", err))
			return
		}
		api.GetApiContext(r).Write(&token)
	} else {
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
		return
	}
}

// GetIdentities is a handler for route /me/identities and returns group memberships and details of the user
func GetIdentities(w http.ResponseWriter, r *http.Request) {
	apiContext := api.GetApiContext(r)
	authHeader := r.Header.Get("Authorization")

	if authHeader != "" {
		// header value format will be "Bearer <token>"
		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.Debug("GetIdentities rejected a malformed Authorization header")
			ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
			return
		}
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")
		identities, err := server.GetIdentities(accessToken)

		if err == nil {
			resp := client.IdentityCollection{}
			resp.Data = identities
			apiContext.Write(&resp)
		} else {
			//failed to get the user identities
			log.Debugf("GetIdentities Failed with error %v", err)
			ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, failed to get identities")
			return
		}
	} else {
		log.Debug("No Authorization header found")
		ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
		return
	}
}

// SearchIdentities is a handler for route /identities and filters (id + type or name) and returns the search results using the passed filters
func SearchIdentities(w http.ResponseWriter, r *http.Request) {
	apiContext := api.GetApiContext(r)
	authHeader := r.Header.Get("Authorization")

	if authHeader != "" {
		// header value format will be "Bearer <token>"
		if !strings.HasPrefix(authHeader, "Bearer") {
			log.Debug("SearchIdentities rejected a malformed Authorization header")
			ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
			return
		}
		accessToken := strings.TrimPrefix(authHeader, "Bearer")
		accessToken = strings.TrimSpace(accessToken)
		//see which filters are passed, if none then error 400
		externalID := r.URL.Query().Get("externalId")
		externalIDType := r.URL.Query().Get("externalIdType")
		name := r.URL.Query().Get("name")

		if externalID != "" && externalIDType != "" {
			log.Debug("Searching for one external identity")
			//search by id and type
			identity, err := server.GetIdentity(externalID, externalIDType, accessToken)
			if err == nil {
				log.Debug("External identity search returned one result")
				apiContext.Write(&identity)
			} else {
				//failed to search the identities
				log.Errorf("SearchIdentities Failed with error %v", err)
				ReturnHTTPError(w, r, http.StatusInternalServerError, "Internal Server Error")
				return
			}
		} else if name != "" {
			log.Debug("Searching identities by name")
			//Must call ldap SearchIdentities with exactMatch=true
			identities, err := server.SearchIdentities(name, true, accessToken)
			if err == nil {
				log.Debugf("Identity search returned %d results", len(identities))
				resp := client.IdentityCollection{}
				resp.Data = identities

				apiContext.Write(&resp)
			} else {
				//failed to search the identities
				log.Errorf("SearchIdentities Failed with error %v", err)
				ReturnHTTPError(w, r, http.StatusInternalServerError, "Internal Server Error")
				return
			}
		} else {
			ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
			return
		}
	} else {
		log.Debug("No Authorization header found")
		ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
		return
	}
}

// UpdateConfig handles POST /config, loads the provider, and saves the configuration to the control-plane database.
func UpdateConfig(w http.ResponseWriter, r *http.Request) {
	apiContext := api.GetApiContext(r)
	bytes, err := readAuthRequestBody(r)
	if err != nil {
		log.Errorf("UpdateConfig failed with error: %v", err)
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
		return
	}
	var authConfig model.AuthConfig

	err = json.Unmarshal(bytes, &authConfig)
	if err != nil {
		log.Errorf("UpdateConfig unmarshal failed with error: %v", err)
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
		return
	}

	if authConfig.Provider == "" {
		log.Errorf("UpdateConfig: Provider is a required field")
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content, Provider is a required field")
		return
	}

	err = server.UpdateConfig(authConfig)
	if err != nil {
		log.Errorf("UpdateConfig failed with error: %v", err)
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
		return
	}
	log.Debugf("Updated config, listing the config back")

	//list the config and return in response
	config, err := server.GetConfig("", true)
	if err == nil {
		apiContext.Write(&config)
	} else {
		//failed to get the config
		log.Debugf("GetConfig failed with error %v", err)
		ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to list the config")
		return
	}
}

// GetConfig is a handler for GET /config, lists the provider config
func GetConfig(w http.ResponseWriter, r *http.Request) {
	apiContext := api.GetApiContext(r)
	authHeader := r.Header.Get("Authorization")
	var accessToken string
	// header value format will be "Bearer <token>"
	if authHeader != "" {
		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.Warn("GetConfig rejected a malformed Authorization header")
			ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
			return
		}
		accessToken = strings.TrimPrefix(authHeader, "Bearer ")
	}

	config, err := server.GetConfig(accessToken, true)
	if err == nil {
		apiContext.Write(&config)
	} else {
		//failed to get the config
		log.Debugf("GetConfig failed with error %v", err)
		ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to get the auth config")
		return
	}
}

// Reload handles POST /reloadconfig, reloads configuration from the control-plane database, and initializes the provider.
func Reload(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Reload called")
	_, err := server.Reload(false)
	if err != nil {
		//failed to reload the config from DB
		log.Debugf("Reload failed with error %v", err)
		ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to reload the auth config")
		return
	}
}

func addErrorToRedirect(redirectURL string, code string) string {
	//add code query param to redirect
	redirectURLInst, err := url.Parse(redirectURL)
	if err == nil {
		v := redirectURLInst.Query()
		v.Add("errCode", code)
		redirectURLInst.RawQuery = v.Encode()
		redirectURL = redirectURLInst.String()
	} else {
		log.Errorf("Error parsing the URL %v  ,error is: %v", redirectURL, err)
		redirectURL = redirectURL + "?errCode=" + code
	}
	return redirectURL
}

// GetRedirectURL gets the redirect URL
func GetRedirectURL(w http.ResponseWriter, r *http.Request) {
	redirectResponse, err := server.GetRedirectURL()
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(redirectResponse)
	} else {
		//failed to get the redirectURL
		log.Debugf("GetRedirectUrl failed with error %v", err)
		ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to get the redirect URL")
		return
	}
}

// PrepareRedirectURL validates a proposed redirect-based provider without
// replacing the active authentication method.
func PrepareRedirectURL(w http.ResponseWriter, r *http.Request) {
	body, err := readAuthRequestBody(r)
	if err != nil {
		ReturnHTTPError(w, r, http.StatusBadRequest, fmt.Sprintf("%v", err))
		return
	}
	var authConfig model.AuthConfig
	if err := json.Unmarshal(body, &authConfig); err != nil {
		ReturnHTTPError(w, r, http.StatusBadRequest, "Invalid authentication configuration")
		return
	}
	response, err := server.PrepareProvider(authConfig)
	if err != nil {
		ReturnHTTPError(w, r, http.StatusUnprocessableEntity, fmt.Sprintf("%v", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// DoSamlLogout redirects to Saml Logout
func DoSamlLogout(w http.ResponseWriter, r *http.Request) {
	if server.SamlServiceProvider != nil {
		if server.SamlServiceProvider.ServiceProvider.IDPMetadata != nil {
			entityID := server.SamlServiceProvider.ServiceProvider.IDPMetadata.EntityID
			entityURL, _ := url.Parse(entityID)
			redirectURL := entityURL.Scheme + "://" + entityURL.Host + "/idp/profile/Logout"
			log.Debugf("redirecting the user to %v", redirectURL)
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		log.Info("No Logout URL - Saml/Shibboleth IDPMetadata not found")
	} else {
		log.Info("No Logout URL - Saml/Shibboleth provider is not configured")
	}
}

// TestLogin is a test API to check login with code before saving settings to db
func TestLogin(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")
	cookies := r.Cookies()
	var token string
	for _, c := range cookies {
		if c.Name == "token" {
			token = c.Value
		}
	}

	var accessToken string
	// header value format will be "Bearer <token>"
	if authHeader != "" {
		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.Warn("TestLogin rejected a malformed Authorization header")
			ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
			return
		}
		accessToken = strings.TrimPrefix(authHeader, "Bearer ")
	}

	bytes, err := readAuthRequestBody(r)
	if err != nil {
		log.Errorf("TestLogin failed with error: %v", err)
		ReturnHTTPError(w, r, http.StatusBadRequest, fmt.Sprintf("%v", err))
		return
	}
	var testAuthConfig model.TestAuthConfig

	err = json.Unmarshal(bytes, &testAuthConfig)
	if err != nil {
		log.Errorf("TestLogin unmarshal failed with error: %v", err)
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
		return
	}

	if testAuthConfig.AuthConfig.Provider == "" {
		log.Errorf("UpdateConfig: Provider is a required field")
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad request, Provider is a required field")
		return
	}

	testToken, status, err := server.TestLogin(testAuthConfig, accessToken, token)
	if err != nil {
		log.Errorf("TestLogin GetProvider failed with error: %v", err)
		if status == 0 {
			status = http.StatusInternalServerError
		}
		ReturnHTTPError(w, r, status, fmt.Sprintf("%v", err))
		return
	}
	api.GetApiContext(r).Write(&testToken)
}

func readAuthRequestBody(r *http.Request) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, fmt.Errorf("authentication request body is required")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAuthRequestSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read the authentication request")
	}
	if len(body) > maxAuthRequestSize {
		return nil, errAuthRequestTooLarge
	}
	return body, nil
}

// HandleSamlLogin is the endpoint for /saml/login endpoint
func HandleSamlLogin(w http.ResponseWriter, r *http.Request) {
	s := server.SamlServiceProvider
	if s == nil || s.ClientState == nil || s.ServiceProvider.IDPMetadata == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	redirectBackBaseValue := r.URL.Query().Get(redirectBackBase)
	if redirectBackBaseValue == "" {
		redirectBackBaseValue = server.GetPlatformAPIHost()
	}

	if !isWhitelisted(redirectBackBaseValue, s.RedirectWhitelist) {
		log.Errorf("Cannot redirect outside whitelisted domains and the platform API host")
		redirectBackPathValue := r.URL.Query().Get(redirectBackPath)
		redirectURL := samlRedirectURL(server.GetPlatformAPIHost(), redirectBackPathValue)
		redirectURL = addErrorToRedirect(redirectURL, "422")
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	serviceProvider := s.ServiceProvider
	if r.URL.Path == serviceProvider.AcsURL.Path {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	binding := saml.HTTPRedirectBinding
	bindingLocation := serviceProvider.GetSSOBindingLocation(binding)
	if bindingLocation == "" {
		binding = saml.HTTPPostBinding
		bindingLocation = serviceProvider.GetSSOBindingLocation(binding)
	}
	if bindingLocation == "" {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	req, err := serviceProvider.MakeAuthenticationRequest(bindingLocation, binding, saml.HTTPPostBinding)
	if err != nil {
		log.Errorf("Cannot create SAML authentication request: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// relayState is limited to 80 bytes but also must be integrety protected.
	// this means that we cannot use a JWT because it is way to long. Instead
	// we set a cookie that corresponds to the state
	randomState, err := randomBytes(42)
	if err != nil {
		log.Errorf("Cannot generate SAML RelayState: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	relayState := base64.RawURLEncoding.EncodeToString(randomState)

	secretBlock, err := samlStateSigningSecret(serviceProvider.Key)
	if err != nil {
		log.Errorf("Cannot derive SAML RelayState signing key: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	state := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": samlStateIssuer,
		"aud": samlStateAudience,
		"iat": now.Unix(),
		"nbf": now.Add(-5 * time.Second).Unix(),
		"exp": now.Add(saml.MaxIssueDelay).Unix(),
		"jti": relayState,
		"id":  req.ID,
		"uri": r.URL.RequestURI(),
	})
	signedState, err := state.SignedString(secretBlock)
	if err != nil {
		log.Errorf("Cannot sign SAML RelayState: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	s.ClientState.SetState(w, r, relayState, signedState)

	if binding == saml.HTTPRedirectBinding {
		redirectURL, err := req.Redirect(relayState, &serviceProvider)
		if err != nil {
			log.Errorf("Cannot build signed SAML redirect: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Location", redirectURL.String())
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusFound)
		return
	}
	if binding == saml.HTTPPostBinding {
		w.Header().Set("Content-Security-Policy", ""+
			"default-src; "+
			"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
			"reflected-xss block; referrer no-referrer;")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>`))
		_, _ = w.Write(req.Post(relayState))
		_, _ = w.Write([]byte(`</body></html>`))
		return
	}
}

// ServeHTTP is the handler for /saml/metadata and /saml/acs endpoints
func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	samlProvider := server.SamlServiceProvider
	if samlProvider == nil || samlProvider.ClientState == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	serviceProvider := samlProvider.ServiceProvider
	if r.URL.Path == serviceProvider.MetadataURL.Path {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		buf, err := xml.MarshalIndent(serviceProvider.Metadata(), "", "  ")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(buf)
		return
	}

	if r.URL.Path == serviceProvider.AcsURL.Path {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestSize)
		if err := r.ParseForm(); err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		requestIDs := getPossibleRequestIDs(r, samlProvider)
		if len(requestIDs) != 1 {
			log.Warn("SAML response did not match a pending service-provider request")
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		assertion, err := serviceProvider.ParseResponse(r, requestIDs)
		if err != nil {
			log.Warn("SAML response signature or assertion validation failed")
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		HandleSamlAssertion(w, r, assertion, samlProvider)
		return
	}

	http.NotFoundHandler().ServeHTTP(w, r)
}

func getPossibleRequestIDs(r *http.Request, s *model.PlatformSamlServiceProvider) []string {
	claims, _, err := validatedSamlState(r, s)
	if err != nil {
		return nil
	}
	id, ok := stringClaim(claims, "id")
	if !ok || strings.TrimSpace(id) == "" {
		return nil
	}
	return []string{id}
}

func samlStateSigningSecret(key crypto.Signer) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("SAML service-provider signing key is missing")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal SAML service-provider signing key: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("PastureStack SAML RelayState v1\x00"))
	_, _ = hash.Write(der)
	return hash.Sum(nil), nil
}

func randomBytes(n int) ([]byte, error) {
	if n < 1 || n > 4096 {
		return nil, fmt.Errorf("invalid random byte count")
	}
	rv := make([]byte, n)
	if _, err := io.ReadFull(saml.RandReader, rv); err != nil {
		return nil, fmt.Errorf("read secure random bytes: %w", err)
	}
	return rv, nil
}

func GetRedirectParams(w http.ResponseWriter, r *http.Request, serviceProvider *model.PlatformSamlServiceProvider) (redirectBackBaseValue string,
	redirectBackPathValue string, err error) {
	redirectBackBaseValue = server.GetPlatformAPIHost()
	redirectBackPathValue = defaultSAMLPath
	claims, relayState, err := validatedSamlState(r, serviceProvider)
	if err != nil {
		return redirectBackBaseValue, redirectBackPathValue, err
	}
	redirectURI, ok := stringClaim(claims, "uri")
	if !ok {
		return redirectBackBaseValue, redirectBackPathValue, fmt.Errorf("SAML state URI is missing")
	}
	requestURI, err := url.ParseRequestURI(redirectURI)
	if err != nil || requestURI.IsAbs() || requestURI.Host != "" || !strings.HasPrefix(requestURI.Path, "/") {
		return redirectBackBaseValue, redirectBackPathValue, fmt.Errorf("SAML state URI is invalid")
	}
	values := requestURI.Query()
	if len(values[redirectBackBase]) > 1 || len(values[redirectBackPath]) > 1 {
		return redirectBackBaseValue, redirectBackPathValue, fmt.Errorf("SAML state has duplicate redirect parameters")
	}
	if value := strings.TrimSpace(values.Get(redirectBackBase)); value != "" {
		redirectBackBaseValue = value
	}
	if value := strings.TrimSpace(values.Get(redirectBackPath)); value != "" {
		if err := validateRedirectPath(value); err != nil {
			return redirectBackBaseValue, redirectBackPathValue, err
		}
		redirectBackPathValue = value
	}
	if err := serviceProvider.ClientState.DeleteState(w, r, relayState); err != nil {
		return redirectBackBaseValue, redirectBackPathValue, fmt.Errorf("consume SAML state: %w", err)
	}
	return redirectBackBaseValue, redirectBackPathValue, nil
}

func validatedSamlState(r *http.Request, serviceProvider *model.PlatformSamlServiceProvider) (jwt.MapClaims, string, error) {
	if r == nil || serviceProvider == nil || serviceProvider.ClientState == nil {
		return nil, "", fmt.Errorf("SAML service provider is not configured")
	}
	if r.Form == nil {
		if err := r.ParseForm(); err != nil {
			return nil, "", fmt.Errorf("parse SAML callback form: %w", err)
		}
	}
	relayState := strings.TrimSpace(r.Form.Get("RelayState"))
	if relayState == "" {
		return nil, "", fmt.Errorf("SAML RelayState is required")
	}
	stateValue := serviceProvider.ClientState.GetState(r, relayState)
	if stateValue == "" {
		return nil, "", fmt.Errorf("SAML RelayState does not match a pending request")
	}
	secretBlock, err := samlStateSigningSecret(serviceProvider.ServiceProvider.Key)
	if err != nil {
		return nil, "", err
	}
	claims, err := parseSamlState(stateValue, secretBlock)
	if err != nil {
		return nil, "", fmt.Errorf("validate SAML RelayState: %w", err)
	}
	stateID, ok := stringClaim(claims, "jti")
	if !ok || stateID != relayState {
		return nil, "", fmt.Errorf("SAML RelayState identifier does not match its cookie")
	}
	return claims, relayState, nil
}

func validateRedirectPath(value string) error {
	if strings.ContainsAny(value, "\r\n") || strings.HasPrefix(value, "//") {
		return fmt.Errorf("redirect path is invalid")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") {
		return fmt.Errorf("redirect path must be an absolute path on the selected host")
	}
	return nil
}

func parseSamlState(value string, secretBlock []byte) (jwt.MapClaims, error) {
	if len(secretBlock) < sha256.Size {
		return nil, fmt.Errorf("SAML state signing key is invalid")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(samlStateIssuer),
		jwt.WithAudience(samlStateAudience),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(5*time.Second),
	)
	token, err := parser.ParseWithClaims(value, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		return secretBlock, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("state token is not valid")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims == nil {
		return nil, fmt.Errorf("state token claims are invalid")
	}
	return claims, nil
}

func stringClaim(claims jwt.MapClaims, key string) (string, bool) {
	value, found := claims[key]
	if !found {
		return "", false
	}
	valueString, ok := value.(string)
	return valueString, ok
}

// HandleSamlAssertion processes/handles the assertion obtained by the POST to /saml/acs from IdP
func HandleSamlAssertion(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion, serviceProvider *model.PlatformSamlServiceProvider) {
	if assertion == nil || serviceProvider == nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	redirectBackBaseValue, redirectBackPathValue, err := GetRedirectParams(w, r, serviceProvider)
	if err != nil {
		log.Warnf("SAML RelayState validation failed: %v", err)
		redirectURL := addErrorToRedirect(samlRedirectURL(server.GetPlatformAPIHost(), defaultSAMLPath), "403")
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	if !isWhitelisted(redirectBackBaseValue, serviceProvider.RedirectWhitelist) {
		log.Warn("SAML redirect target is not allowed")
		redirectURL := samlRedirectURL(server.GetPlatformAPIHost(), redirectBackPathValue)
		redirectURL = addErrorToRedirect(redirectURL, "422")
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}
	redirectURL := samlRedirectURL(redirectBackBaseValue, redirectBackPathValue)

	samlData := make(map[string][]string)

	for _, attributeStatement := range assertion.AttributeStatements {
		for _, attr := range attributeStatement.Attributes {
			attrName := attr.FriendlyName
			if attrName == "" {
				attrName = attr.Name
			}
			for _, value := range attr.Values {
				samlData[attrName] = append(samlData[attrName], value.Value)
			}
		}
	}

	platformAPI := server.GetPlatformAPIHost()
	//get the SAML data, create a jwt token and POST to /v1/token with code = "jwt token"
	mapB, err := json.Marshal(samlData)
	if err != nil {
		redirectURL = addErrorToRedirect(redirectURL, "500")
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	inputJSON := make(map[string]string)
	inputJSON["code"] = string(mapB)
	outputJSON := make(map[string]interface{})

	tokenURL := platformAPI + "/v1/token"
	if server.PlatformClient == nil {
		redirectURL = addErrorToRedirect(redirectURL, "503")
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}
	err = server.PlatformClient.Post(tokenURL, inputJSON, &outputJSON)
	if err != nil {
		// Failed to get a token from the control plane.
		log.Warn("SAML assertion could not be exchanged for a platform token")
		var apiErr *client.ApiError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized {
			//add error=401 query param to redirect
			redirectURL = addErrorToRedirect(redirectURL, "401")
		} else if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden {
			redirectURL = addErrorToRedirect(redirectURL, "403")
		} else {
			redirectURL = addErrorToRedirect(redirectURL, "500")
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	jwtValue, ok := outputJSON["jwt"].(string)
	if !ok || strings.TrimSpace(jwtValue) == "" {
		log.Error("SAML token exchange returned no signed token")
		redirectURL = addErrorToRedirect(redirectURL, "500")
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	/* token is created at this point. If the redirectBackBase is not same as the current URL's domain, then we cannot set the token as cookie
	yet. So we will first send a 200 POST to /v1-auth/saml/tokenhtml, which will contain token cookie and redirectBackBase in HTML body,
	and JS which will submit form on load to redirect URL. The handler for v1-auth/saml/tokenhtml will then set the token as cookie
	*/

	query, err := parseHTTPRedirectURL(redirectBackBaseValue)
	if err != nil {
		log.Warnf("SAML redirect target is invalid: %v", err)
		redirectURL = addErrorToRedirect(redirectURL, "500")
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	if !sameRequestOrigin(r, query) {
		handoffURL := *query
		handoffURL.Path = strings.TrimRight(handoffURL.Path, "/") + postSamlTokenHTML
		handoffURL.RawQuery = ""
		handoffURL.Fragment = ""
		newRedirectURL := handoffURL.String()
		nonceBytes, err := randomBytes(18)
		if err != nil {
			redirectURL = addErrorToRedirect(redirectURL, "500")
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; form-action "+query.Scheme+"://"+query.Host+"; base-uri 'none'; frame-ancestors 'none'")

		data := struct {
			URL              string
			Token            string
			FinalRedirectURL string
			Nonce            string
		}{
			URL:              newRedirectURL,
			Token:            jwtValue,
			FinalRedirectURL: redirectURL,
			Nonce:            nonce,
		}

		rv := bytes.Buffer{}
		if err := samlPostFormTemplate.Execute(&rv, data); err != nil {
			redirectURL = addErrorToRedirect(redirectURL, "500")
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}

		_, _ = w.Write(rv.Bytes())
		return
	}

	// else, if redirectBackBase is same as the current URL, continue and set this token as cookie
	tokenCookie := &http.Cookie{
		Name:     "token",
		Value:    jwtValue,
		Secure:   requestIsHTTPS(r),
		HttpOnly: true,
		MaxAge:   0,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, tokenCookie)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func PostSamlTokenHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if !validSAMLHandoffOrigin(r) {
		log.Warn("Rejected SAML token handoff from an unexpected origin")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestSize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.Form.Get("token"))
	finalRedirectURL := strings.TrimSpace(r.Form.Get("finalRedirectURL"))
	if token == "" || finalRedirectURL == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := validatePlatformToken(token); err != nil {
		log.Warn("Rejected SAML token handoff with an invalid token")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	samlProvider := server.SamlServiceProvider
	if samlProvider == nil || !isAllowedRedirectURL(finalRedirectURL, samlProvider.RedirectWhitelist) {
		log.Warn("Rejected SAML token handoff with an invalid redirect target")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	tokenCookie := &http.Cookie{
		Name:     "token",
		Value:    token,
		Secure:   requestIsHTTPS(r),
		HttpOnly: true,
		MaxAge:   0,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, tokenCookie)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, finalRedirectURL, http.StatusFound)
}

func isWhitelisted(redirectBackBaseValue string, redirectWhitelist string) bool {
	redirectURL, err := parseHTTPRedirectURL(redirectBackBaseValue)
	if err != nil {
		return false
	}
	platformURL, err := parseHTTPRedirectURL(server.GetPlatformAPIHost())
	if err == nil && sameOriginURLs(redirectURL, platformURL) {
		return true
	}
	targetHost := strings.ToLower(strings.TrimSuffix(redirectURL.Host, "."))
	targetHostname := strings.ToLower(strings.TrimSuffix(redirectURL.Hostname(), "."))
	for _, rawEntry := range strings.Split(redirectWhitelist, ",") {
		entry := strings.TrimSpace(rawEntry)
		if entry == "" || strings.ContainsAny(entry, "\r\n") || strings.Contains(entry, "*") {
			continue
		}
		if strings.Contains(entry, "://") {
			allowedURL, err := parseHTTPRedirectURL(entry)
			if err == nil && sameOriginURLs(redirectURL, allowedURL) {
				return true
			}
			continue
		}
		normalized := strings.ToLower(strings.TrimSuffix(entry, "."))
		if normalized == targetHost || (normalized == targetHostname && hasDefaultOrImplicitPort(redirectURL)) {
			return true
		}
	}
	return false
}

func parseHTTPRedirectURL(value string) (*url.URL, error) {
	if strings.ContainsAny(value, "\r\n") {
		return nil, fmt.Errorf("redirect URL contains control characters")
	}
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("redirect URL must be an absolute HTTP or HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("redirect base must not contain user information, query parameters, or a fragment")
	}
	return parsed, nil
}

func isAllowedRedirectURL(value string, redirectWhitelist string) bool {
	if strings.ContainsAny(value, "\r\n") {
		return false
	}
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return false
	}
	base := &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}
	return isWhitelisted(base.String(), redirectWhitelist)
}

func requestIsHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil || strings.EqualFold(r.URL.Scheme, "https") {
		return true
	}
	forwardedProto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	return strings.EqualFold(forwardedProto, "https")
}

func sameRequestOrigin(r *http.Request, target *url.URL) bool {
	if r == nil || target == nil || strings.TrimSpace(r.Host) == "" {
		return false
	}
	scheme := "http"
	if requestIsHTTPS(r) {
		scheme = "https"
	}
	current, err := url.Parse(scheme + "://" + r.Host)
	return err == nil && sameOriginURLs(current, target)
}

func sameOriginURLs(left *url.URL, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(strings.TrimSuffix(left.Hostname(), "."), strings.TrimSuffix(right.Hostname(), ".")) &&
		effectivePort(left) == effectivePort(right)
}

func effectivePort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if strings.EqualFold(value.Scheme, "https") {
		return "443"
	}
	return "80"
}

func hasDefaultOrImplicitPort(value *url.URL) bool {
	if value == nil || value.Port() == "" {
		return value != nil
	}
	return (strings.EqualFold(value.Scheme, "https") && value.Port() == "443") ||
		(strings.EqualFold(value.Scheme, "http") && value.Port() == "80")
}

func validSAMLHandoffOrigin(r *http.Request) bool {
	if r == nil {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" || origin == "null" {
		return false
	}
	originURL, err := parseHTTPRedirectURL(origin)
	if err != nil || (originURL.Path != "" && originURL.Path != "/") {
		return false
	}
	platformURL, err := parseHTTPRedirectURL(server.GetPlatformAPIHost())
	return err == nil && sameOriginURLs(originURL, platformURL)
}

func samlRedirectURL(base string, path string) string {
	if err := validateRedirectPath(path); err != nil {
		path = defaultSAMLPath
	}
	baseURL, err := parseHTTPRedirectURL(base)
	if err != nil {
		baseURL, err = parseHTTPRedirectURL(server.GetPlatformAPIHost())
	}
	if err != nil {
		baseURL = &url.URL{Scheme: "http", Host: "localhost:8080"}
	}
	return strings.TrimRight(baseURL.String(), "/") + path
}
