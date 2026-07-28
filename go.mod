module github.com/PastureStack/authentication-service

go 1.26.0

toolchain go1.26.5

require (
	github.com/crewjam/saml v0.5.1
	github.com/go-ldap/ldap/v3 v3.4.14
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/gorilla/mux v1.8.1
	github.com/pkg/errors v0.9.1
	github.com/rancher/go-rancher v0.0.0-20170518165705-cc9af4572762
	github.com/sirupsen/logrus v1.9.4
	github.com/tomnomnom/linkheader v0.0.0-20250811210735-e5fe3b51442e
	github.com/urfave/cli v1.22.17
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/beevik/etree v1.7.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/context v1.1.2 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/russellhaering/goxmldsig v1.6.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// The upstream control API client predates Go Modules.  Keep the reviewed,
// license-preserving source snapshot local so its exact bytes are reproducible.
replace github.com/rancher/go-rancher => ./third_party/control-api-client
