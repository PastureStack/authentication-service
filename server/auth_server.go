package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PastureStack/authentication-service/model"
	"github.com/PastureStack/authentication-service/providers"
	"github.com/PastureStack/authentication-service/util"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	"github.com/rancher/go-rancher/v2"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	accessModeSetting                         = "api.auth.access.mode"
	allowedIdentitiesSetting                  = "api.auth.allowed.identities"
	userTypeSetting                           = "api.auth.user.type"
	providerSetting                           = "api.auth.provider.configured"
	providerNameSetting                       = "api.auth.provider.name.configured"
	externalProviderSetting                   = "api.auth.external.provider.configured"
	securitySetting                           = "api.security.enabled"
	apiHostSetting                            = "api.host"
	identitySeparatorSetting                  = "api.auth.external.provider.identity.separator"
	authServiceLogSetting                     = "auth.service.log.level"
	authServiceConfigUpdateTimestamp          = "auth.service.config.update.timestamp"
	noIdentityLookupSupportedSetting          = "api.auth.external.provider.no.identity.lookup"
	apiAuthShibbolethRedirectWhitelistSetting = "api.auth.shibboleth.redirect.whitelist"
	localRecoveryEnabledSetting               = "api.auth.local.recovery.enabled"
	localRecoveryVerifiedAtSetting            = "api.auth.local.recovery.verified.at"
	localRecoveryMFAReadySetting              = "api.auth.local.recovery.mfa.ready"
	localRecoveryVerificationMaxAge           = 5 * time.Minute
)

var (
	provider           providers.IdentityProvider
	privateKey         *rsa.PrivateKey
	publicKey          *rsa.PublicKey
	authConfigInMemory model.AuthConfig
	// PlatformClient is the client configured for the compatible control-platform API.
	PlatformClient                                                               *client.RancherClient
	publicKeyFile, publicKeyFileContents, privateKeyFile, privateKeyFileContents string
	selfSignedKeyFile, selfSignedCertFile                                        string
	//IDPMetadataFile is the path to the metadata file of the Shibboleth IDP
	IDPMetadataFile string
	//SamlServiceProvider is the handle to the SamlServiceProvider configured by the router
	SamlServiceProvider *model.PlatformSamlServiceProvider
	refreshReqChannel   *chan int
	authConfigFile      string
	key                 []byte
	PlatformURL         string
)

type AESSecret struct {
	Nonce      []byte
	CipherText []byte
}

// SetEnv sets the parameters necessary
func SetEnv(c *cli.Context) {

	publicKeyFile = c.GlobalString("rsa-public-key-file")
	publicKeyFileContents = c.GlobalString("rsa-public-key-contents")

	if publicKeyFile != "" && publicKeyFileContents != "" {
		log.Fatal("Can't specify both rsa-public-key-file and rsa-public-key-contents")
		return
	}

	if publicKeyFile != "" {
		publicKey = util.ParsePublicKey(publicKeyFile)
	} else if publicKeyFileContents != "" {
		publicKey = util.ParsePublicKeyContents(publicKeyFileContents)
	} else {
		log.Fatal("Please provide either rsa-public-key-file or rsa-public-key-contents, halting")
		return
	}

	privateKeyFile = c.GlobalString("rsa-private-key-file")
	privateKeyFileContents = c.GlobalString("rsa-private-key-contents")

	if privateKeyFile != "" && privateKeyFileContents != "" {
		log.Fatal("Can't specify both rsa-private-key-file and rsa-private-key-contents")
		return
	}

	if privateKeyFile != "" {
		privateKey = util.ParsePrivateKey(privateKeyFile)
	} else if privateKeyFileContents != "" {
		privateKey = util.ParsePrivateKeyContents(privateKeyFileContents)
	} else {
		log.Fatal("Please provide either rsa-private-key-file or rsa-private-key-contents, halting")
		return
	}

	platformURL := c.GlobalString("platform-url")
	if len(platformURL) == 0 {
		log.Fatalf("PLATFORM_URL is not set")
	}
	PlatformURL = platformURL

	platformAPIKey := c.GlobalString("platform-access-key")
	if len(platformAPIKey) == 0 {
		log.Fatalf("PLATFORM_ACCESS_KEY is not set")
	}

	platformSecretKey := c.GlobalString("platform-secret-key")
	if len(platformSecretKey) == 0 {
		log.Fatalf("PLATFORM_SECRET_KEY is not set")
	}

	selfSignedKeyFile = c.GlobalString("self-signed-key-file")
	selfSignedCertFile = c.GlobalString("self-signed-cert-file")
	IDPMetadataFile = c.GlobalString("idp-metadata-file")
	authConfigFile = c.GlobalString("auth-config-file")

	// Configure the compatible control-platform client.
	var err error
	PlatformClient, err = newPlatformClient(platformURL, platformAPIKey, platformSecretKey)
	if err != nil {
		log.Fatalf("Failed to configure platform client: %v", err)
	}

	err = testPlatformConnect()
	if err != nil {
		log.Errorf("Failed to connect to platform client: %v", err)
	}

	err = UpgradeSettings()
	if err != nil {
		log.Fatalf("Failed to upgrade the existing auth settings in db to new: %v", err)
	}

	key, err = readPrivateKey()
	if err != nil {
		log.Fatalf("Failed to read key with error: %v", err)
	}

	refChan := make(chan int, 1)
	refreshReqChannel = &refChan
}

func newPlatformClient(platformURL string, platformAccessKey string, platformSecretKey string) (*client.RancherClient, error) {
	apiClient, err := client.NewRancherClient(&client.ClientOpts{
		Url:       platformURL,
		AccessKey: platformAccessKey,
		SecretKey: platformSecretKey,
	})

	if err != nil {
		return nil, err
	}

	return apiClient, nil
}

func testPlatformConnect() error {
	opts := &client.ListOpts{}
	_, err := PlatformClient.ContainerEvent.List(opts)
	return err
}

func initProviderWithConfig(authConfig *model.AuthConfig) (providers.IdentityProvider, error) {
	newProvider, err := providers.GetProvider(authConfig.Provider)
	if err != nil {
		return nil, err
	}
	if newProvider == nil {
		return nil, fmt.Errorf("Could not get the %s auth provider", authConfig.Provider)
	}
	err = newProvider.LoadConfig(authConfig)
	if err != nil {
		log.Debugf("Error Loading the provider config %v", err)
		return nil, err
	}
	return newProvider, nil
}

func prepareProviderConfig(authConfig *model.AuthConfig) error {
	if authConfig.Provider == "shibbolethconfig" {
		authConfig.ShibbolethConfig.IDPMetadataFilePath = IDPMetadataFile
		authConfig.ShibbolethConfig.SPSelfSignedCertFilePath = selfSignedCertFile
		authConfig.ShibbolethConfig.SPSelfSignedKeyFilePath = selfSignedKeyFile
		authConfig.ShibbolethConfig.PlatformAPIHost = GetPlatformAPIHost()
	}
	if authConfig.Provider == "oidcconfig" {
		authConfig.OIDCConfig.PlatformAPIHost = GetPlatformAPIHost()
		if authConfig.OIDCConfig.ClientSecret == "" && authConfig.OIDCConfig.ClientSecretSet {
			settings, err := readSettings("oidc")
			if err != nil {
				return errors.Wrap(err, "failed to read the existing OIDC client secret")
			}
			authConfig.OIDCConfig.ClientSecret = settings["api.auth.oidc.client.secret"]
			if authConfig.OIDCConfig.ClientSecret == "" {
				return fmt.Errorf("the previously saved OIDC client secret could not be found")
			}
		}
	}
	return nil
}

// This code is adapted from rancher secrets-api https://github.com/rancher/secrets-api/blob/master/pkg/aesutils/key.go#L36
func readPrivateKey() ([]byte, error) {
	keyData, err := ioutil.ReadFile(authConfigFile)
	if err != nil {
		log.Errorf("Returning error, authConfigFile %s not found", authConfigFile)
		return []byte{}, err
	}

	log.Debugf("Loaded auth config key file %s", authConfigFile)
	return keyData, nil
}

// InitBlock adapted from secrets-api https://github.com/rancher/secrets-api/blob/master/pkg/aesutils/aesgcm.go#L34
func initBlock() (cipher.Block, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if block == nil {
		return nil, fmt.Errorf("Uninitialized Cipher Block")
	}

	return block, nil
}

// GetEncryptedText adapted from secrets-api https://github.com/rancher/secrets-api/blob/master/pkg/aesutils/aesgcm.go#L53
func encryptConfig(key []byte, clearText []byte) (string, error) {
	secret := &AESSecret{}
	cipherBlock, err := initBlock()
	if err != nil {
		return "", err
	}

	nonce, err := randomNonce(12)
	if err != nil {
		return "", err
	}

	secret.Nonce = nonce

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	secret.CipherText = gcm.Seal(nil, secret.Nonce, clearText, nil)

	jsonSecret, err := json.Marshal(secret)
	if err != nil {
		return "", err
	}

	return string(jsonSecret), nil
}

// GetClearText adapted from secrets-api https://github.com/rancher/secrets-api/blob/master/pkg/aesutils/aesgcm.go#L86
func decryptConfig(key []byte, secretBlob string) ([]byte, error) {
	secret := &AESSecret{}

	err := json.Unmarshal([]byte(secretBlob), secret)
	if err != nil {
		return []byte{}, err
	}

	cipherBlock, err := initBlock()
	if err != nil {
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return []byte{}, err
	}

	plainText, err := gcm.Open(nil, secret.Nonce, secret.CipherText, nil)
	if err != nil {
		return []byte{}, err
	}

	return plainText, nil
}

// adapted from secrets-api https://github.com/rancher/secrets-api/blob/master/pkg/aesutils/aesgcm.go#L112
func randomNonce(byteLength int) ([]byte, error) {
	key := make([]byte, byteLength)

	_, err := rand.Read(key)
	if err != nil {
		return []byte{}, err
	}

	return key, nil
}

func readSettings(provider string) (map[string]string, error) {
	var dbSettings = make(map[string]map[string]string)
	var nilSettings = make(map[string]string)
	filters := make(map[string]interface{})
	filters["key"] = "auth.config"
	authColl, err := PlatformClient.GenericObject.List(&client.ListOpts{
		Filters: filters,
	})
	if err != nil {
		log.Errorf("Error getting the go %v , error: %v", key, err)
		return nil, err
	}

	if len(authColl.Data) == 0 {
		log.Info("No config stored")
		return nilSettings, nil
	}

	authConfigRes := authColl.Data[0]
	authConfig := authConfigRes.ResourceData["data"]
	encryptedConfig, ok := authConfig.(string)
	if !ok || strings.TrimSpace(encryptedConfig) == "" {
		return nilSettings, fmt.Errorf("stored authentication configuration is invalid")
	}
	byteSettings, err := decryptConfig(key, encryptedConfig)
	if err != nil {
		return nilSettings, err
	}
	if err := json.Unmarshal(byteSettings, &dbSettings); err != nil {
		return nilSettings, err
	}
	providerSettings, found := dbSettings[provider]
	if !found {
		log.Debugf("No stored settings found for provider %s", provider)
		return nilSettings, nil
	}
	log.Debugf("Loaded %d stored settings for provider %s", len(providerSettings), provider)
	return providerSettings, nil
}

func readCommonSettings(settings []string) (map[string]string, error) {
	var dbSettings = make(map[string]string)
	if PlatformClient == nil {
		return dbSettings, fmt.Errorf("platform API client is not configured")
	}

	for _, key := range settings {
		setting, err := PlatformClient.Setting.ById(key)
		if err != nil {
			log.Errorf("Error reading the setting %v , error: %v", key, err)
			return dbSettings, err
		}
		if setting == nil {
			log.Warnf("Setting %v is missing, using empty value", key)
			dbSettings[key] = ""
			continue
		}
		dbSettings[key] = setting.ActiveValue
	}

	return dbSettings, nil
}

func updateSettings(saveConfig map[string]map[string]string, secretSettings []string, providerName string, enabled bool) error {
	clearText, err := json.Marshal(saveConfig)
	if err != nil {
		return err
	}

	encrConf, err := encryptConfig(key, clearText)
	if err != nil {
		return err
	}

	resourceData := map[string]interface{}{
		"data": encrConf,
	}
	// Save entire encryped conf in GO
	filters := make(map[string]interface{})
	filters["key"] = "auth.config"
	authColl, err := PlatformClient.GenericObject.List(&client.ListOpts{
		Filters: filters,
	})
	if err != nil {
		log.Errorf("Error getting the go %v , error: %v", key, err)
		return err
	}

	if len(authColl.Data) == 0 {
		_, err := PlatformClient.GenericObject.Create(&client.GenericObject{
			Name:         "auth.config",
			Key:          "auth.config",
			ResourceData: resourceData,
			Kind:         "authConfig",
		})
		if err != nil {
			log.Errorf("Error creating the go, error: %v", err)
			return err
		}
	} else {
		// Get the previously saved data, decrypt and append
		authConfig := make(map[string]map[string]string)
		prevConfig := authColl.Data[0].ResourceData["data"]
		byteSettings, err := decryptConfig(key, prevConfig.(string))
		err = json.Unmarshal(byteSettings, &authConfig)
		if err != nil {
			return err
		}

		// authConfig now was prevConfig
		// saveConfig is to be saved, so authConfig should get added values from saveConfig

		if enabled {
			// If saveConfig (updated config) does not have secret settings, but authConfig(previous config does), restore the secret settings
			// This is when auth is enabled but access mode is changed
			prevProviderSettings, prevProviderPresent := authConfig[providerName]
			updatedProviderSettings, updatedProviderPresent := saveConfig[providerName]
			if prevProviderPresent && updatedProviderPresent {
				for _, s := range secretSettings {
					_, prevPresent := prevProviderSettings[s]
					_, updatedPresent := updatedProviderSettings[s]
					if prevPresent && !updatedPresent {
						saveConfig[providerName][s] = authConfig[providerName][s]
					}
				}
			}
		}

		for key, val := range saveConfig {
			authConfig[key] = val
		}

		clearText, err := json.Marshal(authConfig)
		if err != nil {
			return err
		}

		encrConf, err := encryptConfig(key, clearText)
		if err != nil {
			return err
		}

		resourceData := map[string]interface{}{
			"data": encrConf,
		}
		_, err = PlatformClient.GenericObject.Update(&authColl.Data[0], &client.GenericObject{
			ResourceData: resourceData,
		})
		if err != nil {
			log.Errorf("Error updating the go, error: %v", err)
			return err
		}
	}
	return nil
}

func updateCommonSettings(settings map[string]string) error {
	for key, value := range settings {
		if value != "" {
			log.Debugf("Updating platform setting %v", key)
			setting, err := PlatformClient.Setting.ById(key)
			if err != nil {
				log.Errorf("Error getting the setting %v , error: %v", key, err)
				return err
			}

			setting, err = PlatformClient.Setting.Update(setting, &client.Setting{
				Value: value,
			})
			if err != nil {
				log.Errorf("Error updating the setting %v: %v", key, err)
				return err
			}
		}
	}
	return nil
}

func getAllowedIDString(allowedIdentities []client.Identity, separator string) string {
	if len(allowedIdentities) > 0 {
		var idArray []string
		for _, identity := range allowedIdentities {
			identityID := identity.ExternalIdType + ":" + identity.ExternalId
			idArray = append(idArray, identityID)
		}
		return strings.Join(idArray, separator)
	}
	return ""
}

func getAllowedIdentities(idString string, accessToken string, separator string) []client.Identity {
	var identities []client.Identity
	if idString != "" {
		externalIDList := strings.Split(idString, separator)
		for _, id := range externalIDList {
			var identity client.Identity
			var err error
			parts := strings.SplitN(id, ":", 2)

			if len(parts) < 2 {
				log.Debugf("Malformed Id, skipping this allowed identity %v", id)
				continue
			}

			if provider != nil && accessToken != "" {
				//get identities from the provider
				identity, err = provider.GetIdentity(parts[1], parts[0], accessToken)
				if err == nil {
					identities = append(identities, identity)
					continue
				}
			}

			identity = client.Identity{Resource: client.Resource{
				Type: "identity",
			}}
			identity.ExternalId = parts[1]
			identity.Resource.Id = id
			identity.ExternalIdType = parts[0]
			identities = append(identities, identity)
		}
	}

	return identities
}

// UpdateConfig updates the config in DB
func UpdateConfig(authConfig model.AuthConfig) error {
	if authConfig.Enabled && strings.EqualFold(authConfig.Provider, "oidcconfig") {
		settings, err := readCommonSettings([]string{
			localRecoveryEnabledSetting,
			localRecoveryVerifiedAtSetting,
			localRecoveryMFAReadySetting,
		})
		if err != nil {
			return errors.Wrap(err, "UpdateConfig: Could not verify local administrator recovery")
		}
		if !localRecoveryReady(settings, time.Now()) {
			return fmt.Errorf("verify an active local system-administrator account within five minutes before activating OpenID Connect")
		}
	}
	if err := prepareProviderConfig(&authConfig); err != nil {
		return err
	}

	newProvider, err := initProviderWithConfig(&authConfig)
	if err != nil {
		log.Errorf("UpdateConfig: Cannot update the config, error initializing the provider %v", err)
		return err
	}
	//store the config to db
	log.Infof("newProvider %v", newProvider.GetName())

	providerSettings := newProvider.GetSettings()

	genObjConfig := make(map[string]map[string]string)
	genObjConfig[newProvider.GetName()] = providerSettings
	err = updateSettings(genObjConfig, newProvider.GetProviderSecretSettings(), newProvider.GetName(), authConfig.Enabled)
	if err != nil {
		log.Errorf("UpdateConfig: Error Storing the provider settings %v", err)
		return err
	}

	//add the generic settings
	commonSettings := make(map[string]string)
	commonSettings[accessModeSetting] = authConfig.AccessMode
	commonSettings[userTypeSetting] = newProvider.GetUserType()
	commonSettings[identitySeparatorSetting] = newProvider.GetIdentitySeparator()
	commonSettings[allowedIdentitiesSetting] = getAllowedIDString(authConfig.AllowedIdentities, newProvider.GetIdentitySeparator())
	commonSettings[providerNameSetting] = authConfig.Provider
	commonSettings[providerSetting] = authConfig.Provider
	commonSettings[externalProviderSetting] = "true"
	commonSettings[noIdentityLookupSupportedSetting] = strconv.FormatBool(!newProvider.IsIdentityLookupSupported())
	err = updateCommonSettings(commonSettings)
	if err != nil {
		return errors.Wrap(err, "UpdateConfig: Error Storing the common settings")
	}

	//set the security setting last specifically
	commonSettings = make(map[string]string)
	commonSettings[securitySetting] = strconv.FormatBool(authConfig.Enabled)
	commonSettings[authServiceConfigUpdateTimestamp] = time.Now().String()
	err = updateCommonSettings(commonSettings)
	if err != nil {
		return errors.Wrap(err, "UpdateConfig: Error Storing the provider securitySetting")
	}

	//switch the in-memory provider
	if provider == nil {
		if authConfig.Provider == "shibbolethconfig" {
			SamlServiceProvider = authConfig.ShibbolethConfig.SamlServiceProvider
		}
		provider = newProvider
		authConfigInMemory = authConfig
	} else {
		//reload the in-memory provider
		log.Infof("Calling reload")
		skipped, err := Reload(true)
		for skipped {
			if err != nil {
				log.Errorf("Failed to reload the auth provider from db on updateConfig: %v", err)
				return err
			}
			time.Sleep(30 * time.Millisecond)
			skipped, err = Reload(true)
		}
		if err != nil {
			log.Errorf("Failed to reload the auth provider from db on updateConfig: %v", err)
			return err
		}
	}

	return nil
}

func localRecoveryReady(settings map[string]string, now time.Time) bool {
	if !strings.EqualFold(settings[localRecoveryEnabledSetting], "true") {
		return false
	}
	if !strings.EqualFold(settings[localRecoveryMFAReadySetting], "true") {
		return false
	}
	verifiedAt, err := strconv.ParseInt(
		strings.TrimSpace(settings[localRecoveryVerifiedAtSetting]), 10, 64)
	if err != nil || verifiedAt <= 0 {
		return false
	}
	age := now.UnixMilli() - verifiedAt
	return age >= -time.Minute.Milliseconds() &&
		age <= localRecoveryVerificationMaxAge.Milliseconds()
}

// UpgradeSettings upgrades the existing provider specific auth settings to the new generic settings used by this service
func UpgradeSettings() error {
	//read the current provider
	var settings []string
	settings = append(settings, providerSetting)
	dbSettings, err := readCommonSettings(settings)
	if err != nil {
		log.Errorf("UpgradeSettings: Error reading existing DB settings %v", err)
		return err
	}

	providerNameInDb := dbSettings[providerSetting]
	if providerNameInDb != "" {
		if providers.IsProviderSupported(providerNameInDb) {
			//upgrade to new settings and set external provider as true
			newProvider, err := providers.GetProvider(providerNameInDb)
			if err != nil {
				return err
			}
			if newProvider == nil {
				return fmt.Errorf("UpgradeSettings: Cannot upgrade the setup, could not get the %s auth provider", providerNameInDb)
			}

			legacySettingsMap := newProvider.GetLegacySettings()
			var legacySettings []string
			legacySettings = append(legacySettings, legacySettingsMap["accessModeSetting"])
			legacySettings = append(legacySettings, legacySettingsMap["allowedIdentitiesSetting"])

			dbLegacySettings, err := readCommonSettings(legacySettings)
			if err != nil {
				log.Errorf("UpgradeSettings: Error reading existing DB legacy settings %v", err)
				return err
			}

			//add the new settings
			commonSettings := map[string]string{}
			commonSettings[accessModeSetting] = dbLegacySettings[legacySettingsMap["accessModeSetting"]]
			commonSettings[userTypeSetting] = newProvider.GetUserType()
			commonSettings[identitySeparatorSetting] = newProvider.GetIdentitySeparator()
			commonSettings[allowedIdentitiesSetting] = dbLegacySettings[legacySettingsMap["allowedIdentitiesSetting"]]
			commonSettings[providerNameSetting] = providerNameInDb
			commonSettings[externalProviderSetting] = "true"
			commonSettings[noIdentityLookupSupportedSetting] = strconv.FormatBool(!newProvider.IsIdentityLookupSupported())

			err = updateCommonSettings(commonSettings)
			if err != nil {
				log.Errorf("UpgradeSettings: Error Storing the new external provider settings %v", err)
				return err
			}
		}
	}
	return nil
}

func UpgradeCase() error {
	var settings []string
	genObjConfig := make(map[string]map[string]string)
	config := model.AuthConfig{Resource: client.Resource{
		Type: "config",
	}}

	// check if GenericObject with key="auth.config" exists
	filters := make(map[string]interface{})
	filters["key"] = "auth.config"
	authColl, err := PlatformClient.GenericObject.List(&client.ListOpts{
		Filters: filters,
	})
	if err != nil {
		log.Errorf("Error getting the go 'auth.config', error: %v", err)
		return err
	}

	if len(authColl.Data) > 0 {
		log.Info("Config stored")
		return nil
	}

	//add the common settings
	settings = append(settings, accessModeSetting)
	settings = append(settings, allowedIdentitiesSetting)
	settings = append(settings, securitySetting)
	settings = append(settings, providerSetting)
	settings = append(settings, providerNameSetting)

	dbSettings, err := readCommonSettings(settings)
	if err != nil {
		return errors.Wrap(err, "UpgradeCase: Error reading DB settings")
	}

	// Get all provider specific settings from setting table for previously configured auth control
	for _, val := range providers.Providers {
		p, err := providers.GetProvider(val)
		if err != nil {
			return err
		}
		if p == nil {
			return errors.Wrapf(err, "UpgradeCase: Could not get the %s auth provider", val)
		}
		pSettings, err := readCommonSettings(p.GetProviderSettingList(false))
		if err != nil {
			return errors.Wrap(err, "UpgradeCase: Error reading DB settings for previous auth providers")
		}
		genObjConfig[p.GetName()] = pSettings
	}

	config.AccessMode = dbSettings[accessModeSetting]
	enabled, err := strconv.ParseBool(dbSettings[securitySetting])
	if err == nil {
		config.Enabled = enabled
	} else {
		config.Enabled = false
	}

	if enabled {
		// GO doesn't exist, so first load the config struct, then get providerSettings for enabled provider
		providerNameInDb := dbSettings[providerNameSetting]
		if !providers.IsProviderSupported(providerNameInDb) {
			log.Debug("Auth provider not supported by authentication-service")
			return nil
		}
		config.Provider = providerNameInDb
		newProvider, err := providers.GetProvider(providerNameInDb)
		if err != nil {
			return err
		}

		if newProvider == nil {
			return errors.Wrapf(err, "UpgradeCase: Could not get the %s auth provider", config.Provider)
		}

		config.AllowedIdentities = getAllowedIdentities(dbSettings[allowedIdentitiesSetting], "", newProvider.GetIdentitySeparator())
		providerSettings, err := readCommonSettings(newProvider.GetProviderSettingList(false))
		if err != nil {
			return errors.Wrap(err, "UpgradeCase: Error reading provider DB settings")
		}
		newProvider.AddProviderConfig(&config, providerSettings)

		provider, err = initProviderWithConfig(&config)
		if err != nil {
			return errors.Wrap(err, "UpgradeCase: Cannot update the config, error initializing the provider")
		}

		providerSettings = provider.GetSettings()
		genObjConfig[provider.GetName()] = providerSettings
		return updateSettings(genObjConfig, provider.GetProviderSecretSettings(), provider.GetName(), enabled)
	}
	return nil
}

// GetConfig gets the config from DB, gathers the list of settings to read from DB
func GetConfig(accessToken string, listOnly bool) (model.AuthConfig, error) {
	var config model.AuthConfig
	var settings []string
	var allowedSettings = make(map[string]bool)
	var secretSettings []string

	config = model.AuthConfig{Resource: client.Resource{
		Type: "config",
	}}

	//add the generic settings
	settings = append(settings, accessModeSetting)
	settings = append(settings, allowedIdentitiesSetting)
	settings = append(settings, securitySetting)
	settings = append(settings, providerSetting)
	settings = append(settings, providerNameSetting)
	settings = append(settings, authServiceLogSetting)

	dbSettings, err := readCommonSettings(settings)
	if err != nil {
		log.Errorf("GetConfig: Error reading DB settings %v", err)
		return config, err
	}

	if dbSettings[authServiceLogSetting] != "" {
		switch strings.ToLower(dbSettings[authServiceLogSetting]) {
		case "trace":
			log.SetLevel(log.DebugLevel)
		case "debug":
			log.SetLevel(log.DebugLevel)
		case "info":
			log.SetLevel(log.InfoLevel)
		case "warn":
			log.SetLevel(log.WarnLevel)
		case "error":
			log.SetLevel(log.ErrorLevel)
		case "fatal":
			log.SetLevel(log.FatalLevel)
		case "panic":
			log.SetLevel(log.PanicLevel)
		}
	}

	config.AccessMode = dbSettings[accessModeSetting]

	enabled, err := strconv.ParseBool(dbSettings[securitySetting])
	if err == nil {
		config.Enabled = enabled
	} else {
		config.Enabled = false
	}

	config.Provider = resolveConfiguredProvider(
		dbSettings[providerSetting],
		dbSettings[providerNameSetting],
	)

	if config.Provider != "" {
		if providers.IsProviderSupported(config.Provider) {
			//add the provider specific config
			newProvider, err := providers.GetProvider(config.Provider)
			if err != nil {
				return config, err
			}
			if newProvider == nil {
				log.Errorf("GetConfig: Could not get the %s auth provider", config.Provider)
				return config, nil
			}
			config.AllowedIdentities = getAllowedIdentities(dbSettings[allowedIdentitiesSetting], accessToken, newProvider.GetIdentitySeparator())
			settingNames := newProvider.GetProviderSettingList(listOnly)
			providerSettings, err := readSettings(newProvider.GetName())
			// Filter out provider specific secret settings if listOnly=true
			if listOnly {
				for _, s := range settingNames {
					allowedSettings[s] = true
				}
				for k := range providerSettings {
					if !allowedSettings[k] {
						secretSettings = append(secretSettings, k)
					}
				}
				for _, k := range secretSettings {
					delete(providerSettings, k)
				}
			}
			if err != nil {
				log.Errorf("GetConfig: Error reading provider DB settings %v", err)
				return config, nil
			}
			newProvider.AddProviderConfig(&config, providerSettings)
		}
	}
	return config, nil
}

// resolveConfiguredProvider treats the active platform provider as canonical.
// providerNameSetting is retained only as a compatibility fallback for legacy
// databases that did not populate providerSetting. This prevents a remembered
// external provider from being reloaded after the platform has returned to
// local authentication.
func resolveConfiguredProvider(activeProvider string, rememberedProvider string) string {
	if activeProvider != "" {
		return activeProvider
	}
	return rememberedProvider
}

// Reload will reload the config from DB and reinit the provider
func Reload(fromUpdate bool) (bool, error) {
	//put msg on channel, so that any other request can wait
	select {
	case *refreshReqChannel <- 1:
		log.Debugf("Reload config is called fromUpdate %v", fromUpdate)
		//read config from db
		authConfig, err := GetConfig("", false)
		if err != nil {
			<-*refreshReqChannel
			return false, err
		}

		//check if the auth is enabled, if yes then load the provider.
		if authConfig.Provider == "" {
			log.Info("No Auth provider configured")
			provider = nil
			SamlServiceProvider = nil
			authConfigInMemory = authConfig
			<-*refreshReqChannel
			return false, nil
		}
		if !providers.IsProviderSupported(authConfig.Provider) {
			log.Debug("Auth provider not supported by authentication-service")
			provider = nil
			SamlServiceProvider = nil
			authConfigInMemory = authConfig
			<-*refreshReqChannel
			return false, nil
		}

		if err := prepareProviderConfig(&authConfig); err != nil {
			<-*refreshReqChannel
			return false, err
		}

		log.Infof("Auth provider configured %v", authConfig.Provider)

		newProvider, err := initProviderWithConfig(&authConfig)
		if err != nil {
			log.Errorf("Error initializing the provider %v", err)
			<-*refreshReqChannel
			return false, err
		}
		if authConfig.Provider == "shibbolethconfig" {
			SamlServiceProvider = authConfig.ShibbolethConfig.SamlServiceProvider
			settings := []string{}
			settings = append(settings, apiAuthShibbolethRedirectWhitelistSetting)
			dbSettings, err := readCommonSettings(settings)
			if err != nil {
				log.Errorf("Error reading apiAuthShibbolethRedirectWhitelistSetting from db during Reload %v", err)
				return false, err
			}
			SamlServiceProvider.RedirectWhitelist = dbSettings[apiAuthShibbolethRedirectWhitelistSetting]
		}
		provider = newProvider
		authConfigInMemory = authConfig
		<-*refreshReqChannel
		return false, nil
	default:
		log.Debugf("Reload config is already in process, skipping, called from UpdateConfig: %v", fromUpdate)
		return true, nil
	}
}

// CreateToken will authenticate with provider and create a jwt token
func CreateToken(json map[string]string) (model.Token, int, error) {
	if provider != nil {
		token, status, err := provider.GenerateToken(json)
		if err != nil {
			return model.Token{}, status, err
		}

		payload := make(map[string]interface{})
		payload["access_token"] = token.AccessToken
		payload["authentication_methods"] = token.AuthenticationMethods
		payload["authentication_context"] = token.AuthenticationContext
		payload["authenticated_at"] = token.AuthenticatedAt
		payload["authentication_issuer"] = token.AuthenticationIssuer

		jwt, err := util.CreateTokenWithPayload(payload, privateKey)
		if err != nil {
			return model.Token{}, 0, err
		}
		token.JwtToken = jwt

		return token, 0, nil
	}
	return model.Token{}, 0, fmt.Errorf("No auth provider configured")
}

// ValidatePlatformToken verifies that a browser handoff contains a token
// signed by this service and not another RS256 token type, such as an
// administrator identity proof.
func ValidatePlatformToken(value string) error {
	if publicKey == nil {
		return fmt.Errorf("platform token validation key is not configured")
	}
	token, err := jwt.Parse(value, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil || !token.Valid {
		return fmt.Errorf("platform token signature is invalid")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("platform token claims are invalid")
	}
	if _, found := claims["access_token"].(string); !found {
		return fmt.Errorf("platform token type is invalid")
	}
	return nil
}

// RefreshToken will refresh a jwt token
func RefreshToken(json map[string]string) (model.Token, int, error) {
	if provider != nil {
		token, status, err := provider.RefreshToken(json)
		if err != nil {
			return model.Token{}, status, err
		}

		payload := make(map[string]interface{})
		payload["access_token"] = token.AccessToken

		jwt, err := util.CreateTokenWithPayload(payload, privateKey)
		if err != nil {
			return model.Token{}, 0, err
		}
		token.JwtToken = jwt
		return token, 0, nil
	}
	return model.Token{}, 0, fmt.Errorf("No auth provider configured")
}

func identitiesToIDList(identities []client.Identity) []string {
	var idList []string
	for _, identity := range identities {
		idList = append(idList, identity.Resource.Id)
	}
	return idList
}

// GetIdentities will list all identities for token
func GetIdentities(accessToken string) ([]client.Identity, error) {
	if provider != nil {
		return provider.GetIdentities(accessToken)
	}
	return []client.Identity{}, fmt.Errorf("No auth provider configured")
}

// GetIdentity will list all identities for given filters
func GetIdentity(externalID string, externalIDType string, accessToken string) (client.Identity, error) {
	if provider != nil {
		return provider.GetIdentity(externalID, externalIDType, accessToken)
	}
	return client.Identity{}, fmt.Errorf("No auth provider configured")
}

// SearchIdentities will list all identities for given filters
func SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error) {
	if provider != nil {
		return provider.SearchIdentities(name, exactMatch, accessToken)
	}
	return []client.Identity{}, fmt.Errorf("No auth provider configured")
}

// GetPlatformAPIHost reads the api.host setting
func GetPlatformAPIHost() string {
	var settings []string

	//add the setting
	settings = append(settings, apiHostSetting)
	dbSettings, err := readCommonSettings(settings)
	if err != nil {
		log.Errorf("GetPlatformAPIHost: error reading database setting %v", err)
		return "http://localhost:8080"
	}
	apiHost := dbSettings[apiHostSetting]
	if apiHost == "" {
		apiHost = "http://localhost:8080"
	}

	log.Debugf("GetPlatformAPIHost() returning %v", apiHost)

	return apiHost
}

// GetRedirectURL returns the redirect URL for the provider if applicable
func GetRedirectURL() (map[string]string, error) {
	response := make(map[string]string)
	if provider != nil {
		redirect := provider.GetRedirectURL()
		response["redirectUrl"] = URLEncoded(redirect)
		response["provider"] = provider.GetName()
		if authConfigInMemory.Provider == "oidcconfig" {
			response["pkceEnabled"] = strconv.FormatBool(authConfigInMemory.OIDCConfig.UsePKCE)
			response["providerDisplayName"] = authConfigInMemory.OIDCConfig.DisplayName
			response["callbackUrl"] = strings.TrimRight(authConfigInMemory.OIDCConfig.PlatformAPIHost, "/") + "/login/oidc-auth"
		}
		log.Debug("GetRedirectURL returned a provider redirect")
		return response, nil
	}
	return response, fmt.Errorf("No auth provider configured")
}

// PrepareProvider validates a proposed provider configuration and returns its
// authorization URL without changing the active provider or global security
// setting.
func PrepareProvider(authConfig model.AuthConfig) (map[string]string, error) {
	if authConfig.Provider == "" || !providers.IsProviderSupported(authConfig.Provider) {
		return nil, fmt.Errorf("unsupported authentication provider %q", authConfig.Provider)
	}
	if err := prepareProviderConfig(&authConfig); err != nil {
		return nil, err
	}
	newProvider, err := initProviderWithConfig(&authConfig)
	if err != nil {
		return nil, err
	}
	redirect := newProvider.GetRedirectURL()
	if redirect == "" {
		return nil, fmt.Errorf("provider %q does not supply an authorization URL", authConfig.Provider)
	}

	response := map[string]string{
		"redirectUrl": URLEncoded(redirect),
		"provider":    newProvider.GetName(),
	}
	if authConfig.Provider == "oidcconfig" {
		response["pkceEnabled"] = strconv.FormatBool(authConfig.OIDCConfig.UsePKCE)
		response["providerDisplayName"] = authConfig.OIDCConfig.DisplayName
		response["callbackUrl"] = strings.TrimRight(authConfig.OIDCConfig.PlatformAPIHost, "/") + "/login/oidc-auth"
	}
	return response, nil
}

// URLEncoded escape url query
func URLEncoded(str string) string {
	u, err := url.Parse(str)
	if err != nil {
		log.Errorf("Error encoding the url: %s , error: %v", str, err)
		return str
	}

	u.RawQuery = u.Query().Encode()
	return u.String()
}

// GetSamlRedirectURL returns the redirect URL for SAML login flow
func GetSamlRedirectURL(redirectBackBase string, redirectBackPath string) string {
	redirectURL := ""
	if provider != nil && provider.GetName() == "shibboleth" {
		platformAPI := GetPlatformAPIHost()
		redirectURL = redirectBackBase + redirectBackPath
		if redirectURL == "" {
			//default to api.host setting
			redirectURL = platformAPI + redirectBackPath
		}
		log.Debug("Built a SAML redirect URL")
	}
	return redirectURL
}

func TestLogin(testAuthConfig model.TestAuthConfig, accessToken string, token string) (model.Token, int, error) {
	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}
	var originalLogin string

	t := &model.V2Token{}
	authConfig := testAuthConfig.AuthConfig
	if err := prepareProviderConfig(&authConfig); err != nil {
		return model.Token{}, 0, err
	}
	testAuthConfig.AuthConfig = authConfig
	newProvider, err := initProviderWithConfig(&authConfig)
	if err != nil {
		log.Errorf("GetProvider: Error initializing the provider %v", err)
		return model.Token{}, 0, err
	}

	if token != "" {
		u, err := url.Parse(PlatformURL)
		if err != nil {
			return model.Token{}, 0, fmt.Errorf("Error %v in parsing URL for getting token", err)
		}
		getURL := strings.Split(PlatformURL, u.Path)[0] + "/v2-beta/token"

		req, err := http.NewRequest("GET", getURL, nil)
		if err != nil {
			return model.Token{}, 0, fmt.Errorf("Error %v in getting token", err)
		}
		req.Header.Set("Cookie", "token="+token)

		resp, err := httpClient.Do(req)
		if err != nil {
			log.Errorf("Received error from get token call: %v", err)
			return model.Token{}, 0, err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return model.Token{}, 0, fmt.Errorf("Error %v in reading response body in getting token", err)
		}
		err = json.Unmarshal(body, &t)
		if err != nil {
			return model.Token{}, 0, fmt.Errorf("Error %v in testlogin", err)
		}
		if len(t.Data) != 1 {
			return model.Token{}, 0, fmt.Errorf("Error in getting token data")
		}
		originalLogin = t.Data[0].OriginalLogin
	}

	log.Infof("newProvider %v", newProvider.GetName())
	if tokenProvider, ok := newProvider.(providers.TokenTestingProvider); ok {
		testToken, status, err := tokenProvider.TestToken(&testAuthConfig, accessToken, originalLogin)
		if err != nil {
			return model.Token{}, status, err
		}
		// A provider test proves that the proposed configuration can complete
		// a real sign-in. It must not create a browser session or expose the
		// provider access token; the normal /token path creates the platform
		// session only after the administrator explicitly enables the config.
		testToken.AccessToken = ""
		testToken.JwtToken = ""
		identityProof, err := createIdentityProof(testToken, authConfig.Provider, newProvider.GetUserType())
		if err != nil {
			return model.Token{}, 0, errors.Wrap(err, "failed to create the verified identity proof")
		}
		testToken.IdentityProof = identityProof
		return testToken, 0, nil
	}
	status, err := newProvider.TestLogin(&testAuthConfig, accessToken, originalLogin)
	if err != nil {
		log.Errorf("GetProvider: Error in login %v", err)
		return model.Token{}, status, err
	}
	return model.Token{}, 0, nil
}

func createIdentityProof(token model.Token, providerName string, userType string) (string, error) {
	var user *client.Identity
	for i := range token.IdentityList {
		if strings.EqualFold(token.IdentityList[i].ExternalIdType, userType) {
			user = &token.IdentityList[i]
			break
		}
	}
	if user == nil || strings.TrimSpace(user.ExternalId) == "" || strings.TrimSpace(user.ExternalIdType) == "" {
		return "", fmt.Errorf("the provider test did not return a user identity")
	}

	randomID, err := randomNonce(32)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	payload := map[string]interface{}{
		"purpose":          "auth-identity-proof",
		"provider":         providerName,
		"external_id":      user.ExternalId,
		"external_id_type": user.ExternalIdType,
		"name":             user.Name,
		"login":            user.Login,
		"iat":              now.Unix(),
		"exp":              now.Add(5 * time.Minute).Unix(),
		"jti":              base64.RawURLEncoding.EncodeToString(randomID),
	}
	return util.CreateTokenWithPayload(payload, privateKey)
}
