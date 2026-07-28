package main

import (
	"fmt"
	"github.com/PastureStack/authentication-service/providers"
	"github.com/PastureStack/authentication-service/server"
	"github.com/PastureStack/authentication-service/service"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"net/http"
	"os"
)

var VERSION = "dev"

func beforeApp(c *cli.Context) error {
	if c.GlobalBool("verbose") {
		log.SetLevel(log.DebugLevel)
	}
	return nil
}

func main() {
	app := cli.NewApp()
	app.Name = "pasturestack-authentication-service"
	app.Version = VERSION
	app.Usage = "Authentication service supporting external identity providers"
	app.Author = "PastureStack community"
	app.Email = ""
	app.Before = beforeApp
	app.Action = StartService
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "locale",
			Value:  "en-US",
			Usage:  "Operator message locale: en-US or zh-TW",
			EnvVar: "PASTURESTACK_LOCALE",
		},
		cli.StringFlag{
			Name: "rsa-public-key-file",
			Usage: fmt.Sprintf(
				"Specify the path to the file containing RSA public key",
			),
		},
		cli.StringFlag{
			Name: "rsa-private-key-file",
			Usage: fmt.Sprintf(
				"Specify the path to the file containing RSA private key",
			),
		},
		cli.StringFlag{
			Name: "rsa-public-key-contents",
			Usage: fmt.Sprintf(
				"An alternative to  rsa-public-key-file. Specify the contents of the key.",
			),
			EnvVar: "RSA_PUBLIC_KEY_CONTENTS",
		},
		cli.StringFlag{
			Name: "rsa-private-key-contents",
			Usage: fmt.Sprintf(
				"An alternative to rsa-private-key-file. Specify the contents of the key.",
			),
			EnvVar: "RSA_PRIVATE_KEY_CONTENTS",
		},
		cli.StringFlag{
			Name: "platform-url,cattle-url",
			Usage: fmt.Sprintf(
				"Specify the control-platform endpoint URL",
			),
			EnvVar: "PLATFORM_URL,CATTLE_URL",
		},
		cli.StringFlag{
			Name: "platform-access-key,cattle-access-key",
			Usage: fmt.Sprintf(
				"Specify the control-platform access key",
			),
			EnvVar: "PLATFORM_ACCESS_KEY,CATTLE_ACCESS_KEY",
		},
		cli.StringFlag{
			Name: "platform-secret-key,cattle-secret-key",
			Usage: fmt.Sprintf(
				"Specify the control-platform secret key",
			),
			EnvVar: "PLATFORM_SECRET_KEY,CATTLE_SECRET_KEY",
		},
		cli.BoolFlag{
			Name: "debug",
			Usage: fmt.Sprintf(
				"Set true to get debug logs",
			),
		},
		cli.StringFlag{
			Name:  "listen",
			Value: ":8090",
			Usage: fmt.Sprintf(
				"Address to listen to (TCP)",
			),
		},
		cli.StringFlag{
			Name: "self-signed-key-file",
			Usage: fmt.Sprintf(
				"Specify the path to the file containing a self signed certificate's key",
			),
		},
		cli.StringFlag{
			Name: "self-signed-cert-file",
			Usage: fmt.Sprintf(
				"Specify the path to the file containing a self signed certificate",
			),
		},
		cli.StringFlag{
			Name: "idp-metadata-file",
			Usage: fmt.Sprintf(
				"Specify the path to the file containing SAML/Shibboleth IDP Metadata file",
			),
		},
		cli.StringFlag{
			Name: "auth-config-file",
			Usage: fmt.Sprintf(
				"Auth config key",
			),
		},
	}

	app.Run(os.Args)
}

func StartService(c *cli.Context) {
	locale := c.GlobalString("locale")
	if locale != "en-US" && locale != "zh-TW" {
		log.Fatalf("unsupported locale %q; use en-US or zh-TW", locale)
	}

	server.SetEnv(c)
	providers.RegisterProviders()

	if c.GlobalBool("debug") {
		log.SetLevel(log.DebugLevel)
	}

	textFormatter := &log.TextFormatter{
		FullTimestamp: true,
	}
	log.SetFormatter(textFormatter)

	log.Info(operatorMessage(locale, "start"))

	err := server.UpgradeCase()
	if err != nil {
		log.Fatalf("Failed on upgrade case: %v", err)
	}

	_, err = server.Reload(false)

	if err != nil {
		log.Fatalf("Failed to reload the auth provider from db on start: %v", err)
	}

	router := service.NewRouter()

	log.Info("Listening on ", c.GlobalString("listen"))
	log.Fatal(http.ListenAndServe(c.GlobalString("listen"), router))

}

func operatorMessage(locale, key string) string {
	messages := map[string]map[string]string{
		"en-US": {"start": "Starting PastureStack authentication service"},
		"zh-TW": {"start": "正在啟動 PastureStack 身分驗證服務"},
	}
	return messages[locale][key]
}
