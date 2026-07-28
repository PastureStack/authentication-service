package ldap

import (
	"bytes"
	"crypto/x509"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PastureStack/authentication-service/model"
	ldapv3 "github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
)

func testLDAPClient() *LClient {
	config := &model.LdapConfig{
		UserObjectClass:  "person",
		GroupObjectClass: "group",
		UserNameField:    "displayName",
		UserLoginField:   "uid",
		GroupNameField:   "name",
	}
	return &LClient{
		Config: config,
		ConstantsConfig: &ConstantsConfig{
			UserScope:            "user",
			GroupScope:           "group",
			Scopes:               []string{"user", "group"},
			ObjectClassAttribute: "objectClass",
		},
		SearchConfig: &SearchConfig{},
	}
}

func TestSplitLDAPCredentialsRejectsMalformedInput(t *testing.T) {
	for _, value := range []string{"", "alice", ":password", "alice:"} {
		if _, _, err := splitLDAPCredentials(value); err == nil {
			t.Fatalf("malformed credentials %q were accepted", value)
		}
	}
	username, password, err := splitLDAPCredentials("alice:password:with:colons")
	if err != nil || username != "alice" || password != "password:with:colons" {
		t.Fatalf("valid credentials were not split safely: %q %q %v", username, password, err)
	}
}

func TestLDAPHelpersRejectMalformedCollectionsWithoutPanicking(t *testing.T) {
	client := testLDAPClient()
	if identities, err := client.savedIdentities([]string{"", "malformed", "user:"}); err != nil || len(identities) != 0 {
		t.Fatalf("malformed saved identities were not ignored safely: %#v %v", identities, err)
	}
	if _, err := client.getIdentitiesFromSearchResult(nil); err == nil {
		t.Fatal("nil LDAP search result was accepted")
	}
	if _, err := client.getIdentitiesFromSearchResult(&ldapv3.SearchResult{}); err == nil {
		t.Fatal("empty LDAP search result was accepted")
	}
	client.ConstantsConfig.Scopes = nil
	if _, err := client.GetIdentity("uid=alice,dc=example", "user"); err == nil {
		t.Fatal("missing LDAP scopes were accepted")
	}
}

func TestAttributesToIdentityHandlesEmptyValuesAndFallbacks(t *testing.T) {
	client := testLDAPClient()
	attributes := []*ldapv3.EntryAttribute{
		ldapv3.NewEntryAttribute("objectClass", []string{"person"}),
		ldapv3.NewEntryAttribute("displayName", nil),
		ldapv3.NewEntryAttribute("uid", nil),
	}
	identity, err := client.attributesToIdentity(attributes, "uid=alice,dc=example", "user")
	if err != nil {
		t.Fatalf("convert LDAP identity: %v", err)
	}
	if identity.Name != "uid=alice,dc=example" || identity.Login != identity.Name || !identity.User {
		t.Fatalf("unexpected fallback identity: %#v", identity)
	}
}

func TestLogResultDoesNotReadAttributeValues(t *testing.T) {
	previous := log.GetLevel()
	previousOutput := log.StandardLogger().Out
	var output bytes.Buffer
	log.SetLevel(log.DebugLevel)
	log.SetOutput(&output)
	defer func() {
		log.SetLevel(previous)
		log.SetOutput(previousOutput)
	}()
	result := &ldapv3.SearchResult{Entries: []*ldapv3.Entry{{
		DN:         "uid=alice,dc=example",
		Attributes: []*ldapv3.EntryAttribute{ldapv3.NewEntryAttribute("empty", nil)},
	}}}
	testLDAPClient().logResult(result, "test")
	if strings.Contains(output.String(), "alice") || strings.Contains(output.String(), "uid=") {
		t.Fatalf("LDAP result log exposed identity data: %q", output.String())
	}
}

func TestDialLDAPConnectionRejectsUnsafeConfigurationBeforeDial(t *testing.T) {
	config := &model.LdapConfig{ConnectionTimeout: 0}
	if _, err := dialLDAPConnection(config, "localhost", 389, x509.NewCertPool()); err == nil {
		t.Fatal("unbounded LDAP connection timeout was accepted")
	}
	config.ConnectionTimeout = 100
	if _, err := dialLDAPConnection(config, "", 389, nil); err == nil {
		t.Fatal("empty LDAP server was accepted")
	}
	if _, err := dialLDAPConnection(config, "localhost", 70000, nil); err == nil {
		t.Fatal("invalid LDAP port was accepted")
	}
}

func TestLDAPEntryPointsRejectMissingConfigurationBeforeNetworkAccess(t *testing.T) {
	var missing *LClient
	if _, status, err := missing.GenerateToken(map[string]string{"code": "alice:password"}); err == nil || status != 503 {
		t.Fatalf("missing LDAP client status=%d err=%v", status, err)
	}

	client := testLDAPClient()
	client.Enabled = false
	client.Config.LoginDomain = "EXAMPLE"
	if _, status, err := client.GenerateToken(map[string]string{"code": "alice:password"}); err == nil || status != 401 {
		t.Fatalf("missing service-account password status=%d err=%v", status, err)
	}
	if status, err := client.TestLogin(nil, "", ""); err == nil || status != 400 {
		t.Fatalf("nil test configuration status=%d err=%v", status, err)
	}
	if status, err := client.TestLogin(&model.TestAuthConfig{Code: "malformed"}, "", ""); err == nil || status != 401 {
		t.Fatalf("malformed test credentials status=%d err=%v", status, err)
	}
}

func TestDialLDAPConnectionUsesPerConnectionDialer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()

	host, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	port, err := strconv.ParseInt(rawPort, 10, 64)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	connection, err := dialLDAPConnection(&model.LdapConfig{ConnectionTimeout: 1000}, host, port, nil)
	if err != nil {
		t.Fatalf("dial local LDAP endpoint: %v", err)
	}
	_ = connection.Close()
	select {
	case peer := <-accepted:
		_ = peer.Close()
	case <-time.After(time.Second):
		t.Fatal("LDAP dial did not reach the configured endpoint")
	}
}
