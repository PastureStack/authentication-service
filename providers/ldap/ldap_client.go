package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/PastureStack/authentication-service/model"
	"github.com/go-ldap/ldap/v3"
	"github.com/pkg/errors"
	"github.com/rancher/go-rancher/v2"
	log "github.com/sirupsen/logrus"
)

// LClient is the ldap client
type LClient struct {
	Config            *model.LdapConfig
	ConstantsConfig   *ConstantsConfig
	SearchConfig      *SearchConfig
	AccessMode        string
	AllowedIdentities string
	Enabled           bool
}

type SearchConfig struct {
	Server               string
	Port                 int64
	BindDN               string
	BindPassword         string
	UserSearchAttributes []string
	GroupSeachAttributes []string
}

type ConstantsConfig struct {
	UserScope            string
	GroupScope           string
	Scopes               []string
	MemberOfAttribute    string
	ObjectClassAttribute string
	LdapJwt              string
	CAPool               *x509.CertPool
}

var nilIdentity = client.Identity{Resource: client.Resource{
	Type: "identity",
}}
var nilToken = model.Token{Resource: client.Resource{
	Type: "token",
}}

func (l *LClient) InitializeSearchConfig() *SearchConfig {
	c := l.ConstantsConfig
	return &SearchConfig{
		Server:       l.Config.Server,
		Port:         l.Config.Port,
		BindDN:       l.Config.ServiceAccountUsername,
		BindPassword: l.Config.ServiceAccountPassword,
		UserSearchAttributes: []string{c.MemberOfAttribute,
			c.ObjectClassAttribute,
			l.Config.UserObjectClass,
			l.Config.UserLoginField,
			l.Config.UserNameField,
			l.Config.UserSearchField,
			l.Config.UserEnabledAttribute},
		GroupSeachAttributes: []string{c.MemberOfAttribute,
			c.ObjectClassAttribute,
			l.Config.GroupObjectClass,
			l.Config.UserLoginField,
			l.Config.GroupNameField,
			l.Config.GroupSearchField},
	}
}

func (l *LClient) newConn() (*ldap.Conn, error) {
	if l == nil || l.Config == nil || l.SearchConfig == nil || l.ConstantsConfig == nil {
		return nil, fmt.Errorf("LDAP client is not configured")
	}
	searchConfig := l.SearchConfig
	return dialLDAPConnection(l.Config, searchConfig.Server, searchConfig.Port, l.ConstantsConfig.CAPool)
}

func dialLDAPConnection(config *model.LdapConfig, server string, port int64, caPool *x509.CertPool) (*ldap.Conn, error) {
	if config == nil || strings.TrimSpace(server) == "" || port < 1 || port > 65535 {
		return nil, fmt.Errorf("LDAP server and port are invalid")
	}
	if config.ConnectionTimeout <= 0 {
		return nil, fmt.Errorf("LDAP connection timeout must be greater than zero")
	}
	timeout := time.Duration(config.ConnectionTimeout) * time.Millisecond
	dialer := &net.Dialer{Timeout: timeout}
	scheme := "ldap"
	options := []ldap.DialOpt{ldap.DialWithDialer(dialer)}
	if config.TLS {
		scheme = "ldaps"
		options = append(options, ldap.DialWithTLSConfig(&tls.Config{
			RootCAs:    caPool,
			ServerName: server,
			MinVersion: tls.VersionTLS12,
		}))
	}
	address := scheme + "://" + net.JoinHostPort(server, strconv.FormatInt(port, 10))
	connection, err := ldap.DialURL(address, options...)
	if err != nil {
		return nil, fmt.Errorf("create LDAP connection: %w", err)
	}
	connection.SetTimeout(timeout)
	return connection, nil
}

func splitLDAPCredentials(code string) (string, string, error) {
	parts := strings.SplitN(code, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		return "", "", fmt.Errorf("LDAP username and password are required")
	}
	if parts[1] == "" {
		return "", "", fmt.Errorf("LDAP password is required")
	}
	return parts[0], parts[1], nil
}

// GenerateToken generates token
func (l *LClient) GenerateToken(jsonInput map[string]string) (model.Token, int, error) {
	log.Info("Now generating Ldap token")
	if l == nil || l.Config == nil || l.SearchConfig == nil || l.ConstantsConfig == nil {
		return nilToken, http.StatusServiceUnavailable, fmt.Errorf("LDAP client is not configured")
	}
	searchConfig := l.SearchConfig

	//getLdapToken:ADTokenCreator
	//getIdentities: ADIdentityProvider
	var status int

	username, password, err := splitLDAPCredentials(jsonInput["code"])
	if err != nil {
		return nilToken, 401, err
	}
	externalID := getUserExternalID(username, l.Config.LoginDomain)
	if !l.Enabled && l.SearchConfig.BindPassword == "" {
		return nilToken, 401, fmt.Errorf("LDAP service-account password is required")
	}

	lConn, err := l.newConn()
	if err != nil {
		return nilToken, status, err
	}
	defer lConn.Close()

	if !l.Enabled {
		log.Debug("Bind service account username password")
		sausername := getUserExternalID(l.SearchConfig.BindDN, l.Config.LoginDomain)
		err = lConn.Bind(sausername, l.SearchConfig.BindPassword)

		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				status = 401
			}
			return nilToken, status, fmt.Errorf("Error in ldap bind of service account: %v", err)
		}
	}

	log.Debug("Binding username password")
	err = lConn.Bind(externalID, password)

	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			status = 401
		}
		return nilToken, status, fmt.Errorf("Error in ldap bind: %v", err)
	}
	originalLogin := username
	samName := username
	if strings.Contains(username, `\`) {
		samName = strings.SplitN(username, `\`, 2)[1]
	}
	query := "(" + l.Config.UserLoginField + "=" + ldap.EscapeFilter(samName) + ")"
	if l.AccessMode == "required" {
		groupFilter, err := l.getAllowedIdentitiesFilter()
		if err != nil {
			return nilToken, status, err
		}
		if len(groupFilter) > 1 {
			groupQuery := "(&" + query + groupFilter + ")"
			query = groupQuery
		}
		log.Debug("Running the required-access LDAP user query")
		search := ldap.NewSearchRequest(l.Config.Domain,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			query,
			searchConfig.UserSearchAttributes, nil)
		result, err := lConn.Search(search)
		if err != nil {
			return nilToken, status, err
		}

		l.logResult(result, "GenerateToken")
		if len(result.Entries) < 1 {
			return nilToken, http.StatusForbidden, errors.New("Cannot locate user information")
		} else if len(result.Entries) > 1 {
			return nilToken, http.StatusForbidden, errors.New("More than one result")
		}

	}

	log.Debug("Running the LDAP user query")
	search := ldap.NewSearchRequest(l.Config.Domain,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		query,
		searchConfig.UserSearchAttributes, nil)

	return l.userRecord(search, lConn, "GenerateToken", originalLogin)
}

func (l *LClient) getIdentitiesFromSearchResult(result *ldap.SearchResult) ([]client.Identity, error) {
	// getIdentities(SearchResult result): ADIdentityProvider
	if result == nil || len(result.Entries) == 0 || result.Entries[0] == nil {
		return nil, fmt.Errorf("LDAP user search returned no entries")
	}
	c := l.ConstantsConfig
	entry := result.Entries[0]
	if !l.hasPermission(entry.Attributes, l.Config) {
		return []client.Identity{}, fmt.Errorf("Permission denied")
	}

	identityList := []client.Identity{}
	memberOf := entry.GetAttributeValues(c.MemberOfAttribute)
	user := &client.Identity{}

	log.Debugf("LDAP user belongs to %d groups", len(memberOf))

	// isType
	isType := false
	objectClass := entry.GetAttributeValues(c.ObjectClassAttribute)
	for _, obj := range objectClass {
		if strings.EqualFold(string(obj), l.Config.UserObjectClass) {
			isType = true
		}
	}
	if !isType {
		return []client.Identity{}, nil
	}

	user, err := l.attributesToIdentity(entry.Attributes, result.Entries[0].DN, c.UserScope)
	if err != nil {
		return []client.Identity{}, err
	}
	if user != nil {
		identityList = append(identityList, *user)
	}

	if len(memberOf) != 0 {
		lConn, err := l.newConn()
		if err != nil {
			return []client.Identity{}, fmt.Errorf("Error in getIdentitiesFromSearchResult: %v", err)
		}
		defer lConn.Close()
		for i := 0; i < len(memberOf); i += 50 {
			batch := memberOf[i:min(i+50, len(memberOf))]
			identityListBatch, err := l.GetGroupIdentity(batch, lConn)
			if err != nil {
				return []client.Identity{}, err
			}
			identityList = append(identityList, identityListBatch...)
		}
	}
	return identityList, nil
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func (l *LClient) GetGroupIdentity(groupDN []string, lConn *ldap.Conn) ([]client.Identity, error) {
	c := l.ConstantsConfig
	// Bind before query
	// If service acc bind fails, and auth is on, return identity formed using DN
	serviceAccountUsername := getUserExternalID(l.Config.ServiceAccountUsername, l.Config.LoginDomain)
	err := lConn.Bind(serviceAccountUsername, l.Config.ServiceAccountPassword)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) && l.Enabled {
			identityList := []client.Identity{}
			for _, distinguishedName := range groupDN {
				identity := &client.Identity{
					Resource: client.Resource{
						Type: "identity",
					},
					ExternalIdType: c.GroupScope,
					ExternalId:     distinguishedName,
					Name:           distinguishedName,
					Login:          distinguishedName,
					User:           false,
				}
				identity.Resource.Id = c.GroupScope + ":" + distinguishedName
				identityList = append(identityList, *identity)
			}
			return identityList, nil
		}
		return []client.Identity{}, fmt.Errorf("Error in ldap bind: %v", err)
	}

	filter := "(" + c.ObjectClassAttribute + "=" + l.Config.GroupObjectClass + ")"
	query := "(|"
	for _, attrib := range groupDN {
		query += "(distinguishedName=" + ldap.EscapeFilter(attrib) + ")"
	}
	query += ")"
	query = "(&" + filter + query + ")"
	log.Debugf("Querying %d LDAP group memberships", len(groupDN))
	searchDomain := l.Config.Domain
	if l.Config.GroupSearchDomain != "" {
		searchDomain = l.Config.GroupSearchDomain
	}
	search := ldap.NewSearchRequest(searchDomain,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		query,
		l.SearchConfig.GroupSeachAttributes, nil)

	result, err := lConn.Search(search)
	if err != nil {
		return []client.Identity{}, fmt.Errorf("LDAP group search failed: %w", err)
	}

	l.logResult(result, "GetGroupIdentity")

	identityList := []client.Identity{}
	for _, e := range result.Entries {
		identity, err := l.attributesToIdentity(e.Attributes, e.DN, c.GroupScope)
		if err != nil {
			log.Warnf("Could not create an LDAP group identity: %v", err)
			continue
		}
		if identity == nil {
			log.Warn("LDAP group search returned an empty identity")
			continue
		}
		if !reflect.DeepEqual(identity, nilIdentity) {
			identityList = append(identityList, *identity)
		}
	}
	return identityList, nil
}

func getList(identitiesStr string, separator string) []string {
	allowedIdentities := strings.Split(identitiesStr, separator)
	for index, str := range allowedIdentities {
		allowedIdentities[index] = strings.TrimSpace(str)
	}

	return allowedIdentities
}

func (l *LClient) savedIdentities(allowedIdentities []string) ([]client.Identity, error) {
	identityList := []client.Identity{}
	if len(allowedIdentities) == 0 {
		return identityList, nil
	}

	for _, id := range allowedIdentities {
		split := strings.SplitN(id, ":", 2)
		if len(split) != 2 || strings.TrimSpace(split[0]) == "" || strings.TrimSpace(split[1]) == "" {
			log.Warn("Ignoring malformed saved LDAP identity")
			continue
		}
		identity, err := l.GetIdentity(split[1], split[0])
		if err != nil {
			log.Warnf("Could not resolve a saved LDAP identity: %v", err)
			continue
		}
		if !reflect.DeepEqual(identity, nilIdentity) {
			identityList = append(identityList, identity)
		}
	}

	return identityList, nil
}

func (l *LClient) getAllowedIdentitiesFilter() (string, error) {
	c := l.ConstantsConfig
	grpFilterArr := []string{}
	memberOf := "(memberof="
	dn := "(distinguishedName="
	identitySize := 0
	identitiesStr := l.AllowedIdentities

	// fromHashSeparatedString()
	allowedIdentities := getList(identitiesStr, GetIdentitySeparator())

	// getAllowedIdentitiesFilter(l)
	identities, err := l.savedIdentities(allowedIdentities)
	if err != nil {
		return "", err
	}
	for _, identity := range identities {
		identitySize++
		if strings.EqualFold(c.GroupScope, identity.ExternalIdType) {
			grpFilterArr = append(grpFilterArr, memberOf)
		} else {
			grpFilterArr = append(grpFilterArr, dn)
		}
		grpFilterArr = append(grpFilterArr, ldap.EscapeFilter(identity.ExternalId))
		grpFilterArr = append(grpFilterArr, ")")
	}
	groupFilter := strings.Join(grpFilterArr, "")

	if identitySize > 0 {
		outer := "(|" + groupFilter + ")"
		return outer, nil
	}

	return groupFilter, nil
}

// GetIdentity gets identities
func (l *LClient) GetIdentity(distinguishedName string, scope string) (client.Identity, error) {
	//getIdentity(String distinguishedName, String scope): LDAPIdentityProvider
	c := l.ConstantsConfig
	var filter string
	searchConfig := l.SearchConfig
	var search *ldap.SearchRequest
	if c == nil || !validLDAPScope(c.Scopes, scope) {
		return nilIdentity, fmt.Errorf("Invalid scope")
	}

	// getObject()
	var attributes []*ldap.AttributeTypeAndValue
	var attribs []*ldap.EntryAttribute
	object, err := ldap.ParseDN(distinguishedName)
	if err != nil {
		return nilIdentity, err
	}
	for _, rdns := range object.RDNs {
		for _, attr := range rdns.Attributes {
			attributes = append(attributes, attr)
			entryAttr := ldap.NewEntryAttribute(attr.Type, []string{attr.Value})
			attribs = append(attribs, entryAttr)
		}
	}

	if !isType(attribs, scope) && !l.hasPermission(attribs, l.Config) {
		log.Warn("LDAP identity was rejected by its object type or permission attributes")
		return nilIdentity, nil
	}

	if strings.EqualFold(c.UserScope, scope) {
		filter = "(" + c.ObjectClassAttribute + "=" + l.Config.UserObjectClass + ")"
	} else {
		filter = "(" + c.ObjectClassAttribute + "=" + l.Config.GroupObjectClass + ")"
	}

	log.Debug("Querying one LDAP identity")
	lConn, err := l.newConn()
	if err != nil {
		return nilIdentity, fmt.Errorf("Error %v creating connection", err)
	}
	// Bind before query
	// If service acc bind fails, and auth is on, return identity formed using DN
	serviceAccountUsername := getUserExternalID(l.Config.ServiceAccountUsername, l.Config.LoginDomain)
	err = lConn.Bind(serviceAccountUsername, l.Config.ServiceAccountPassword)
	defer lConn.Close()
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) && l.Enabled {
			user := strings.EqualFold(c.UserScope, scope)
			identity := &client.Identity{
				Resource: client.Resource{
					Type: "identity",
				},
				ExternalIdType: scope,
				ExternalId:     distinguishedName,
				Name:           distinguishedName,
				Login:          distinguishedName,
				User:           user,
			}
			identity.Resource.Id = scope + ":" + distinguishedName
			return *identity, nil
		}
		return nilIdentity, fmt.Errorf("Error in ldap bind: %v", err)
	}

	if strings.EqualFold(c.UserScope, scope) {
		search = ldap.NewSearchRequest(distinguishedName,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			filter,
			searchConfig.UserSearchAttributes, nil)
	} else {
		search = ldap.NewSearchRequest(distinguishedName,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			filter,
			searchConfig.GroupSeachAttributes, nil)
	}

	result, err := lConn.Search(search)
	if err != nil {
		return nilIdentity, fmt.Errorf("LDAP identity search failed: %w", err)
	}

	l.logResult(result, "GetIdentity")
	if len(result.Entries) < 1 {
		return nilIdentity, fmt.Errorf("No identities can be retrieved")
	} else if len(result.Entries) > 1 {
		return nilIdentity, fmt.Errorf("More than one result found")
	}

	entry := result.Entries[0]
	entryAttributes := entry.Attributes
	if !l.hasPermission(entry.Attributes, l.Config) {
		return nilIdentity, fmt.Errorf("Permission denied")
	}

	identity, err := l.attributesToIdentity(entryAttributes, distinguishedName, scope)
	if err != nil {
		return nilIdentity, err
	}
	if identity == nil {
		return nilIdentity, fmt.Errorf("User Identity not returned for LDAP")
	}
	return *identity, nil
}

func (l *LClient) attributesToIdentity(attribs []*ldap.EntryAttribute, dnStr string, scope string) (*client.Identity, error) {
	if l == nil || l.Config == nil || l.ConstantsConfig == nil || !validLDAPScope(l.ConstantsConfig.Scopes, scope) {
		return nil, fmt.Errorf("invalid LDAP identity configuration or scope")
	}
	var externalIDType, accountName, externalID, login string
	user := false

	externalID = dnStr
	externalIDType = scope

	if isType(attribs, l.Config.UserObjectClass) {
		for _, attr := range attribs {
			if strings.EqualFold(attr.Name, l.Config.UserNameField) {
				if len(attr.Values) != 0 {
					accountName = attr.Values[0]
				} else {
					accountName = externalID
				}
			}
			if strings.EqualFold(attr.Name, l.Config.UserLoginField) {
				if len(attr.Values) > 0 {
					login = strings.TrimSpace(attr.Values[0])
				}
			}
		}
		user = true
	} else if isType(attribs, l.Config.GroupObjectClass) {
		for _, attr := range attribs {
			if strings.EqualFold(attr.Name, l.Config.GroupNameField) {
				if len(attr.Values) != 0 {
					accountName = attr.Values[0]
				} else {
					accountName = externalID
				}
			}
			if strings.EqualFold(attr.Name, l.Config.UserLoginField) {
				if len(attr.Values) > 0 && attr.Values[0] != "" {
					login = attr.Values[0]
				}
			}
		}
	} else {
		return nil, fmt.Errorf("LDAP entry has no supported object class")
	}
	if strings.TrimSpace(accountName) == "" {
		accountName = externalID
	}
	if strings.TrimSpace(login) == "" {
		login = accountName
	}

	identity := &client.Identity{
		Resource: client.Resource{
			Type: "identity",
		},
		ExternalIdType: externalIDType,
		ExternalId:     externalID,
		Name:           accountName,
		Login:          login,
		User:           user,
	}
	identity.Resource.Id = externalIDType + ":" + externalID
	return identity, nil
}

func validLDAPScope(scopes []string, scope string) bool {
	for _, candidate := range scopes {
		if strings.EqualFold(candidate, scope) {
			return true
		}
	}
	return false
}

func isType(search []*ldap.EntryAttribute, varType string) bool {
	for _, attrib := range search {
		if attrib.Name == "objectClass" {
			for _, val := range attrib.Values {
				if strings.EqualFold(val, varType) {
					return true
				}
			}
		}
	}
	log.Debugf("Failed to determine if object is type: %s", varType)
	return false
}

func GetIdentitySeparator() string {
	return "#"
}

// GetUserIdentity returns the "user" from the list of identities
func GetUserIdentity(identities []client.Identity, userType string) (client.Identity, bool) {
	for _, identity := range identities {
		if identity.ExternalIdType == userType {
			return identity, true
		}
	}
	return client.Identity{}, false
}

// SearchIdentities returns the identity by name
func (l *LClient) SearchIdentities(name string, exactMatch bool) ([]client.Identity, error) {
	c := l.ConstantsConfig
	identities := []client.Identity{}
	for _, scope := range c.Scopes {
		identityList, err := l.searchIdentities(name, scope, exactMatch)
		if err != nil {
			return []client.Identity{}, err
		}
		identities = append(identities, identityList...)
	}
	return identities, nil
}

func (l *LClient) searchIdentities(name string, scope string, exactMatch bool) ([]client.Identity, error) {
	c := l.ConstantsConfig
	name = ldap.EscapeFilter(name)
	if strings.EqualFold(c.UserScope, scope) {
		return l.searchUser(name, exactMatch)
	} else if strings.EqualFold(c.GroupScope, scope) {
		return l.searchGroup(name, exactMatch)
	} else {
		return nil, fmt.Errorf("Invalid scope")
	}
}

func (l *LClient) searchUser(name string, exactMatch bool) ([]client.Identity, error) {
	c := l.ConstantsConfig
	var query string
	if exactMatch {
		query = "(&(" + l.Config.UserSearchField + "=" + name + ")(" + c.ObjectClassAttribute + "=" +
			l.Config.UserObjectClass + "))"
	} else {
		query = "(&(" + l.Config.UserSearchField + "=*" + name + "*)(" + c.ObjectClassAttribute + "=" +
			l.Config.UserObjectClass + "))"
	}
	log.Debug("Searching LDAP users")
	return l.searchLdap(query, c.UserScope)
}

func (l *LClient) searchGroup(name string, exactMatch bool) ([]client.Identity, error) {
	c := l.ConstantsConfig
	var query string
	if exactMatch {
		query = "(&(" + l.Config.GroupSearchField + "=" + name + ")(" + c.ObjectClassAttribute + "=" +
			l.Config.GroupObjectClass + "))"
	} else {
		query = "(&(" + l.Config.GroupSearchField + "=*" + name + "*)(" + c.ObjectClassAttribute + "=" +
			l.Config.GroupObjectClass + "))"
	}
	log.Debug("Searching LDAP groups")
	return l.searchLdap(query, c.GroupScope)
}

func (l *LClient) searchLdap(query string, scope string) ([]client.Identity, error) {
	c := l.ConstantsConfig
	searchConfig := l.SearchConfig
	identities := []client.Identity{}
	var search *ldap.SearchRequest

	searchDomain := l.Config.Domain
	if strings.EqualFold(c.UserScope, scope) {
		search = ldap.NewSearchRequest(searchDomain,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			query,
			searchConfig.UserSearchAttributes, nil)
	} else {
		if l.Config.GroupSearchDomain != "" {
			searchDomain = l.Config.GroupSearchDomain
		}
		search = ldap.NewSearchRequest(searchDomain,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			query,
			searchConfig.GroupSeachAttributes, nil)
	}

	lConn, err := l.newConn()
	if err != nil {
		return []client.Identity{}, fmt.Errorf("Error %v creating connection", err)
	}
	defer lConn.Close()
	// Bind before query
	serviceAccountUsername := getUserExternalID(l.Config.ServiceAccountUsername, l.Config.LoginDomain)
	err = lConn.Bind(serviceAccountUsername, l.Config.ServiceAccountPassword)
	if err != nil {
		return nil, fmt.Errorf("Error %v in ldap bind", err)
	}
	results, err := lConn.Search(search)
	if err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			return identities, nil
		}
		return []client.Identity{}, fmt.Errorf("LDAP identity search failed: %w", err)
	}
	if results == nil {
		return identities, nil
	}

	for i := 0; i < len(results.Entries); i++ {
		entry := results.Entries[i]
		identity, err := l.attributesToIdentity(entry.Attributes, results.Entries[i].DN, scope)
		if err != nil {
			return []client.Identity{}, err
		}
		identities = append(identities, *identity)
	}

	return identities, nil
}

func (l *LClient) TestLogin(testAuthConfig *model.TestAuthConfig, accessToken string, originalLogin string) (int, error) {
	var lConn *ldap.Conn
	var err error
	var status int
	status = 500

	if testAuthConfig == nil {
		return http.StatusBadRequest, fmt.Errorf("LDAP test configuration is required")
	}
	if l == nil || l.ConstantsConfig == nil {
		return http.StatusServiceUnavailable, fmt.Errorf("LDAP client is not configured")
	}
	username, password, err := splitLDAPCredentials(testAuthConfig.Code)
	if err != nil {
		return 401, err
	}

	if username == "" {
		username = originalLogin
	}

	externalID := getUserExternalID(username, testAuthConfig.AuthConfig.LdapConfig.LoginDomain)

	ldapServer := testAuthConfig.AuthConfig.LdapConfig.Server
	ldapPort := testAuthConfig.AuthConfig.LdapConfig.Port
	log.Debug("TestLogin: Now creating Ldap connection")
	lConn, err = dialLDAPConnection(&testAuthConfig.AuthConfig.LdapConfig, ldapServer, ldapPort, l.ConstantsConfig.CAPool)
	if err != nil {
		return status, err
	}
	defer lConn.Close()

	if testAuthConfig.AuthConfig.LdapConfig.ServiceAccountPassword == "" {
		status = 401
		return status, fmt.Errorf("Failed to login, service account password not provided")
	}

	log.Debug("TestLogin: Binding service account username password")
	sausername := getUserExternalID(testAuthConfig.AuthConfig.LdapConfig.ServiceAccountUsername, testAuthConfig.AuthConfig.LdapConfig.LoginDomain)
	err = lConn.Bind(sausername, testAuthConfig.AuthConfig.LdapConfig.ServiceAccountPassword)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			status = 401
		}
		return status, fmt.Errorf("Error in ldap bind for service account: %v", err)
	}

	log.Debug("TestLogin: Binding username password")
	err = lConn.Bind(externalID, password)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			status = 401
		}
		return status, fmt.Errorf("Error in ldap bind: %v", err)
	}

	samName := username
	if strings.Contains(username, `\`) {
		samName = strings.SplitN(username, `\`, 2)[1]
	}
	query := "(" + testAuthConfig.AuthConfig.LdapConfig.UserLoginField + "=" + ldap.EscapeFilter(samName) + ")"
	log.Debug("Testing the LDAP user query")

	testUserSearchAttributes := []string{l.ConstantsConfig.MemberOfAttribute, l.ConstantsConfig.ObjectClassAttribute,
		testAuthConfig.AuthConfig.LdapConfig.UserObjectClass, testAuthConfig.AuthConfig.LdapConfig.UserLoginField,
		testAuthConfig.AuthConfig.LdapConfig.UserNameField, testAuthConfig.AuthConfig.LdapConfig.UserSearchField,
		testAuthConfig.AuthConfig.LdapConfig.UserEnabledAttribute}

	search := ldap.NewSearchRequest(testAuthConfig.AuthConfig.LdapConfig.Domain,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		query, testUserSearchAttributes, nil)

	result, err := lConn.Search(search)
	if err != nil {
		return status, fmt.Errorf("Error searching the user information with new server settings: %v", err)
	}

	l.logResult(result, "TestLogin")
	if len(result.Entries) < 1 {
		return status, fmt.Errorf("Authentication succeeded, but cannot locate the user information with new server schema settings")
	} else if len(result.Entries) > 1 {
		return status, fmt.Errorf("Multiple users found for the username with new server settings")
	}

	entry := result.Entries[0]
	if !l.hasPermission(entry.Attributes, &testAuthConfig.AuthConfig.LdapConfig) {
		return status, fmt.Errorf("Authentication succeeded, but user is probably disabled in the new server settings")
	}

	userIdentity, err := l.attributesToIdentity(entry.Attributes, entry.DN, l.ConstantsConfig.UserScope)
	if err != nil {
		return status, fmt.Errorf("Authentication succeeded, but error reading the user information with new server schema settings: %v", err)
	}

	if userIdentity == nil {
		return status, fmt.Errorf("Authentication succeeded, but cannot search user information with new server settings")
	}

	if userIdentity.ExternalId != accessToken {
		return status, fmt.Errorf("Authentication succeeded, but the user returned has a different Distinguished Name than you are currently logged in to. Changing the underlying directory tree is not supported")
	}

	return status, nil
}

func getUserExternalID(username string, loginDomain string) string {
	if strings.Contains(username, "\\") {
		return username
	} else if loginDomain != "" {
		return loginDomain + "\\" + username
	}
	return username
}

func (l *LClient) hasPermission(attributes []*ldap.EntryAttribute, config *model.LdapConfig) bool {
	var permission int64
	if !isType(attributes, config.UserObjectClass) {
		return true
	}
	for _, attr := range attributes {
		if attr.Name == config.UserEnabledAttribute {
			if len(attr.Values) > 0 && attr.Values[0] != "" {
				intAttr, err := strconv.ParseInt(attr.Values[0], 10, 64)
				if err != nil {
					log.Errorf("Failed to get USER_ENABLED_ATTRIBUTE, error: %v", err)
					return false
				}
				permission = intAttr
			} else {
				return true
			}
		}
	}
	permission = permission & config.UserDisabledBitMask
	return permission != config.UserDisabledBitMask
}

func (l *LClient) RefreshToken(json map[string]string) (model.Token, int, error) {
	c := l.ConstantsConfig
	searchConfig := l.SearchConfig
	query := "(" + c.ObjectClassAttribute + "=" + l.Config.UserObjectClass + ")"

	search := ldap.NewSearchRequest(json["accessToken"],
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		query,
		searchConfig.UserSearchAttributes, nil)

	var status int
	lConn, err := l.newConn()
	if err != nil {
		return nilToken, status, fmt.Errorf("Error %v creating connection", err)
	}
	defer lConn.Close()
	// Bind before query
	serviceAccountUsername := getUserExternalID(l.Config.ServiceAccountUsername, l.Config.LoginDomain)
	err = lConn.Bind(serviceAccountUsername, l.Config.ServiceAccountPassword)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			status = 401
		}
		return nilToken, status, fmt.Errorf("Error %v in ldap bind", err)
	}
	return l.userRecord(search, lConn, "RefreshToken", "")
}

func (l *LClient) userRecord(search *ldap.SearchRequest, lConn *ldap.Conn, name string, originalLogin string) (model.Token, int, error) {
	var status int
	c := l.ConstantsConfig
	result, err := lConn.Search(search)
	if err != nil {
		return nilToken, status, err
	}

	method := "userRecord+" + name
	l.logResult(result, method)

	if len(result.Entries) < 1 {
		return nilToken, 401, fmt.Errorf("LDAP authentication succeeded but no user record was found")
	} else if len(result.Entries) > 1 {
		return nilToken, 403, fmt.Errorf("LDAP authentication returned more than one user record")
	}

	identityList, err := l.getIdentitiesFromSearchResult(result)
	if err != nil {
		return nilToken, status, err
	}

	var token = model.Token{Resource: client.Resource{
		Type: "token",
	}}
	token.IdentityList = identityList
	token.Type = c.LdapJwt
	userIdentity, ok := GetUserIdentity(identityList, c.UserScope)
	if !ok {
		return nilToken, status, fmt.Errorf("User identity not found for Ldap")
	}
	token.ExternalAccountID = userIdentity.ExternalId
	token.AccessToken = userIdentity.ExternalId
	token.OriginalLogin = originalLogin
	return token, status, nil
}

func (l *LClient) logResult(result *ldap.SearchResult, name string) {
	if log.GetLevel() != log.DebugLevel || result == nil {
		return
	}
	log.Debugf("LDAP operation %s returned %d entries", name, len(result.Entries))
}
