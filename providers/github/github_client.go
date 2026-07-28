package github

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PastureStack/authentication-service/model"
	"github.com/PastureStack/authentication-service/outbound"
	log "github.com/sirupsen/logrus"
	"github.com/tomnomnom/linkheader"
)

const (
	gheAPI                = "/api/v3"
	githubAccessToken     = Name + "access_token"
	githubAPI             = "https://api.github.com"
	githubDefaultHostName = "https://github.com"
	maxGithubResponseSize = 4 << 20
	githubRequestTimeout  = 15 * time.Second
)

var (
	githubIdentityIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	githubLoginPattern      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253}[A-Za-z0-9_])?$`)
)

// GClient implements a httpclient for github
type GClient struct {
	httpClient   *http.Client
	config       *model.GithubConfig
	originPolicy *outbound.OriginPolicy
	webBase      *url.URL
	apiBase      *url.URL
}

func (g *GClient) configure(configToSet *model.GithubConfig) error {
	if configToSet == nil {
		return fmt.Errorf("GitHub configuration is required")
	}
	config := *configToSet
	config.Hostname = strings.TrimSpace(config.Hostname)
	config.Scheme = strings.TrimSpace(config.Scheme)

	webBase, err := url.Parse(githubDefaultHostName)
	if err != nil {
		return err
	}
	apiBase, err := url.Parse(githubAPI)
	if err != nil {
		return err
	}
	policy, err := outbound.FromEnvironment(githubDefaultHostName, githubAPI)
	if err != nil {
		return err
	}

	if config.Hostname != "" {
		scheme := strings.ToLower(strings.TrimSuffix(config.Scheme, "://"))
		if scheme != "https" && scheme != "http" {
			return fmt.Errorf("GitHub Enterprise scheme must be http:// or https://")
		}
		candidate, err := url.Parse(scheme + "://" + config.Hostname)
		if err != nil || candidate.Host == "" || candidate.Hostname() == "" || candidate.User != nil ||
			(candidate.EscapedPath() != "" && candidate.EscapedPath() != "/") || candidate.RawQuery != "" || candidate.Fragment != "" {
			return fmt.Errorf("GitHub Enterprise hostname must contain only a host and optional port")
		}
		if !policy.IsValidRedirectURL(candidate.String()) {
			return fmt.Errorf("GitHub Enterprise origin is not authorized by %s", outbound.AllowedOriginsEnvironment)
		}
		webBase = candidate
		apiBase = cloneURL(candidate)
		apiBase.Path = gheAPI
		config.Scheme = scheme + "://"
		config.Hostname = candidate.Host
	}

	g.config = &config
	g.webBase = webBase
	g.apiBase = apiBase
	g.originPolicy = policy
	g.httpClient = newGitHubHTTPClient(policy)
	*configToSet = config
	return nil
}

func newGitHubHTTPClient(policy *outbound.OriginPolicy) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport: &outbound.PolicyTransport{Base: transport, Policy: policy},
		Timeout:   githubRequestTimeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("GitHub redirect limit exceeded")
			}
			if len(via) == 0 || !outbound.SameOrigin(via[0].URL, request.URL) {
				return fmt.Errorf("GitHub redirect changed the authorized origin")
			}
			if policy == nil || !policy.IsValidRedirectURL(request.URL.String()) {
				return fmt.Errorf("GitHub redirect target is not authorized")
			}
			return nil
		},
	}
}

func cloneURL(source *url.URL) *url.URL {
	if source == nil {
		return nil
	}
	copy := *source
	return &copy
}

func (g *GClient) apiEndpoint(pathSegments ...string) (string, error) {
	if g.apiBase == nil {
		return "", fmt.Errorf("GitHub API origin is not configured")
	}
	endpoint := cloneURL(g.apiBase)
	endpoint.Path = strings.TrimRight(endpoint.Path, "/")
	for _, segment := range pathSegments {
		endpoint.Path += "/" + url.PathEscape(segment)
	}
	return endpoint.String(), nil
}

func validateGitHubIdentityID(value string) (string, error) {
	if !githubIdentityIDPattern.MatchString(value) {
		return "", fmt.Errorf("GitHub identity ID must be a positive decimal integer")
	}
	return value, nil
}

func validateGitHubLogin(value string) (string, error) {
	if !githubLoginPattern.MatchString(value) {
		return "", fmt.Errorf("GitHub login contains unsupported characters")
	}
	return value, nil
}

func (g *GClient) getAccessToken(code string) (string, error) {
	form := url.Values{}
	form.Add("client_id", g.config.ClientID)
	form.Add("client_secret", g.config.ClientSecret)
	form.Add("code", code)

	url := g.getURL("TOKEN")

	resp, err := g.postToGithub(url, form)
	if err != nil {
		log.Errorf("Github getAccessToken: GET url %v received error from github, err: %v", url, err)
		return "", err
	}
	defer resp.Body.Close()

	// Decode the response
	var respMap map[string]interface{}
	b, err := readGithubResponse(resp.Body)
	if err != nil {
		log.Errorf("Github getAccessToken: received error reading response body, err: %v", err)
		return "", err
	}

	if err := json.Unmarshal(b, &respMap); err != nil {
		log.Errorf("Github getAccessToken: received error unmarshalling response body, err: %v", err)
		return "", err
	}

	if respMap["error"] != nil {
		log.Error("GitHub rejected the OAuth token request")
		return "", fmt.Errorf("GitHub rejected the OAuth token request")
	}

	acessToken, ok := respMap["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("GitHub token response is missing an access token")
	}
	return acessToken, nil
}

func (g *GClient) getGithubUser(githubAccessToken string) (Account, error) {

	url := g.getURL("USER_INFO")
	resp, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getGithubUser: GET url %v received error from github, err: %v", url, err)
		return Account{}, err
	}
	defer resp.Body.Close()
	var githubAcct Account

	b, err := readGithubResponse(resp.Body)
	if err != nil {
		log.Errorf("Github getGithubUser: error reading response, err: %v", err)
		return Account{}, err
	}

	if err := json.Unmarshal(b, &githubAcct); err != nil {
		log.Errorf("Github getGithubUser: error unmarshalling response, err: %v", err)
		return Account{}, err
	}

	return githubAcct, nil
}

func (g *GClient) getGithubOrgs(githubAccessToken string) ([]Account, error) {
	var orgs []Account
	url := g.getURL("ORG_INFO")
	responses, err := g.paginateGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getGithubOrgs: GET url %v received error from github, err: %v", url, err)
		return orgs, err
	}

	for _, response := range responses {
		defer response.Body.Close()
		var orgObjs []Account
		b, err := readGithubResponse(response.Body)
		if err != nil {
			log.Errorf("Github getGithubOrgs: error reading the response from github, err: %v", err)
			return orgs, err
		}
		if err := json.Unmarshal(b, &orgObjs); err != nil {
			log.Errorf("Github getGithubOrgs: received error unmarshalling org array, err: %v", err)
			return orgs, err
		}
		for _, orgObj := range orgObjs {
			orgs = append(orgs, orgObj)
		}
	}

	return orgs, nil
}

func (g *GClient) getGithubTeams(githubAccessToken string) ([]Account, error) {
	var teams []Account
	url := g.getURL("TEAMS")
	responses, err := g.paginateGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getGithubTeams: GET url %v received error from github, err: %v", url, err)
		return teams, err
	}
	for _, response := range responses {
		defer response.Body.Close()
		teamObjs, err := g.getTeamInfo(response)

		if err != nil {
			log.Errorf("Github getGithubTeams: received error unmarshalling teams array, err: %v", err)
			return teams, err
		}
		for _, teamObj := range teamObjs {
			teams = append(teams, teamObj)
		}

	}
	return teams, nil
}

func (g *GClient) getTeamInfo(response *http.Response) ([]Account, error) {
	var teams []Account
	b, err := readGithubResponse(response.Body)
	if err != nil {
		log.Errorf("Github getTeamInfo: error reading the response from github, err: %v", err)
		return teams, err
	}
	var teamObjs []Team
	if err := json.Unmarshal(b, &teamObjs); err != nil {
		log.Errorf("Github getTeamInfo: received error unmarshalling team array, err: %v", err)
		return teams, err
	}
	url := g.getURL("TEAM_PROFILE")
	for _, team := range teamObjs {
		teamAcct := Account{}
		team.toGithubAccount(url, &teamAcct)
		teams = append(teams, teamAcct)
	}

	return teams, nil
}

func (g *GClient) getTeamByID(id string, githubAccessToken string) (Account, error) {
	var teamAcct Account
	id, err := validateGitHubIdentityID(id)
	if err != nil {
		return teamAcct, err
	}
	url, err := g.apiEndpoint("teams", id)
	if err != nil {
		return teamAcct, err
	}
	response, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getTeamByID: GET url %v received error from github, err: %v", url, err)
		return teamAcct, err
	}
	defer response.Body.Close()
	b, err := readGithubResponse(response.Body)
	if err != nil {
		log.Errorf("Github getTeamByID: error reading the response from github, err: %v", err)
		return teamAcct, err
	}
	var teamObj Team
	if err := json.Unmarshal(b, &teamObj); err != nil {
		log.Errorf("Github getTeamByID: received error unmarshalling team array, err: %v", err)
		return teamAcct, err
	}
	url = g.getURL("TEAM_PROFILE")
	teamObj.toGithubAccount(url, &teamAcct)

	return teamAcct, nil
}

func (g *GClient) paginateGithub(githubAccessToken string, url string) ([]*http.Response, error) {
	var responses []*http.Response

	response, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		return responses, err
	}
	responses = append(responses, response)
	nextURL := g.nextGithubPage(response)
	for nextURL != "" {
		response, err = g.getFromGithub(githubAccessToken, nextURL)
		if err != nil {
			for _, previous := range responses {
				previous.Body.Close()
			}
			return nil, err
		}
		responses = append(responses, response)
		nextURL = g.nextGithubPage(response)
	}

	return responses, nil
}

func (g *GClient) nextGithubPage(response *http.Response) string {
	header := response.Header.Get("link")

	if header != "" {
		links := linkheader.Parse(header)
		for _, link := range links {
			if link.Rel == "next" {
				return link.URL
			}
		}
	}

	return ""
}

func (g *GClient) getGithubUserByName(username string, githubAccessToken string) (Account, error) {
	username, err := validateGitHubLogin(username)
	if err != nil {
		return Account{}, err
	}

	_, err = g.getGithubOrgByName(username, githubAccessToken)
	if err == nil {
		return Account{}, fmt.Errorf("There is a org by this name, not looking fo the user entity by name %v", username)
	}

	url, err := g.apiEndpoint("users", username)
	if err != nil {
		return Account{}, err
	}

	resp, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getGithubUserByName: GET url %v received error from github, err: %v", url, err)
		return Account{}, err
	}
	defer resp.Body.Close()
	var githubAcct Account

	b, err := readGithubResponse(resp.Body)
	if err != nil {
		log.Errorf("Github getGithubUserByName: error reading response, err: %v", err)
		return Account{}, err
	}

	if err := json.Unmarshal(b, &githubAcct); err != nil {
		log.Errorf("Github getGithubUserByName: error unmarshalling response, err: %v", err)
		return Account{}, err
	}

	return githubAcct, nil
}

func (g *GClient) getGithubOrgByName(org string, githubAccessToken string) (Account, error) {
	org, err := validateGitHubLogin(org)
	if err != nil {
		return Account{}, err
	}
	url, err := g.apiEndpoint("orgs", org)
	if err != nil {
		return Account{}, err
	}

	resp, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getGithubOrgByName: GET url %v received error from github, err: %v", url, err)
		return Account{}, err
	}
	defer resp.Body.Close()
	var githubAcct Account

	b, err := readGithubResponse(resp.Body)
	if err != nil {
		log.Errorf("Github getGithubOrgByName: error reading response, err: %v", err)
		return Account{}, err
	}

	if err := json.Unmarshal(b, &githubAcct); err != nil {
		log.Errorf("Github getGithubOrgByName: error unmarshalling response, err: %v", err)
		return Account{}, err
	}

	return githubAcct, nil
}

func (g *GClient) getUserOrgByID(id string, githubAccessToken string) (Account, error) {
	id, err := validateGitHubIdentityID(id)
	if err != nil {
		return Account{}, err
	}
	url, err := g.apiEndpoint("user", id)
	if err != nil {
		return Account{}, err
	}

	resp, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		log.Errorf("Github getUserOrgById: GET url %v received error from github, err: %v", url, err)
		return Account{}, err
	}
	defer resp.Body.Close()
	var githubAcct Account

	b, err := readGithubResponse(resp.Body)
	if err != nil {
		log.Errorf("Github getUserOrgById: error reading response, err: %v", err)
		return Account{}, err
	}

	if err := json.Unmarshal(b, &githubAcct); err != nil {
		log.Errorf("Github getUserOrgById: error unmarshalling response, err: %v", err)
		return Account{}, err
	}

	return githubAcct, nil
}

/* TODO non-exact search
func (g *GithubClient) searchGithub(githubAccessToken string, url string) []map[string]interface{} {
	log.Debugf("url %v",url)
	resp, err := g.getFromGithub(githubAccessToken, url)
}


    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> searchGithub(String url) {
        try {
            HttpResponse res = getFromGithub(githubTokenUtils.getAccessToken(), url);
            //TODO:Finish implementing search.
            Map<String, Object> jsonData = jsonMapper.readValue(res.getEntity().getContent());
            return (List<Map<String, Object>>) jsonData.get("items");
        } catch (IOException e) {
            //TODO: Proper Error Handling.
            return new ArrayList<>();
        }
    }

*/

func (g *GClient) postToGithub(url string, form url.Values) (*http.Response, error) {
	if !g.isAuthorizedWebURL(url) {
		return nil, fmt.Errorf("GitHub token endpoint is outside the authorized web origin")
	}
	req, err := http.NewRequest("POST", url, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("could not create GitHub token request: %w", err)
	}
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		log.Errorf("Received error from github: %v", err)
		return resp, err
	}
	// Check the status code
	switch resp.StatusCode {
	case 200:
	case 201:
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("GitHub request failed with HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

func (g *GClient) getFromGithub(githubAccessToken string, url string) (*http.Response, error) {
	if !g.isAuthorizedAPIURL(url) {
		return nil, fmt.Errorf("GitHub API endpoint is outside the authorized API origin")
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create GitHub API request: %w", err)
	}
	req.Header.Add("Authorization", "token "+githubAccessToken)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36)")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		log.Errorf("Received error from github: %v", err)
		return resp, err
	}
	// Check the status code
	switch resp.StatusCode {
	case 200:
	case 201:
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("GitHub request failed with HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

func (g *GClient) isAuthorizedWebURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	return err == nil && g.webBase != nil && g.originPolicy != nil &&
		outbound.SameOrigin(parsed, g.webBase) && g.originPolicy.IsValidRedirectURL(rawURL)
}

func (g *GClient) isAuthorizedAPIURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || g.apiBase == nil || g.originPolicy == nil ||
		!outbound.SameOrigin(parsed, g.apiBase) || !g.originPolicy.IsValidRedirectURL(rawURL) {
		return false
	}
	basePath := strings.TrimRight(g.apiBase.EscapedPath(), "/")
	requestPath := parsed.EscapedPath()
	return basePath == "" || requestPath == basePath || strings.HasPrefix(requestPath, basePath+"/")
}

func readGithubResponse(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxGithubResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxGithubResponseSize {
		return nil, fmt.Errorf("GitHub response exceeds the supported size")
	}
	return data, nil
}

func (g *GClient) getURL(endpoint string) string {
	if g.webBase == nil || g.apiBase == nil {
		return ""
	}
	hostName := strings.TrimRight(g.webBase.String(), "/")
	apiEndpoint := strings.TrimRight(g.apiBase.String(), "/")
	var toReturn string

	switch endpoint {
	case "API":
		toReturn = apiEndpoint
	case "TOKEN":
		toReturn = hostName + "/login/oauth/access_token"
	case "USERS":
		toReturn = apiEndpoint + "/users/"
	case "ORGS":
		toReturn = apiEndpoint + "/orgs/"
	case "USER_INFO":
		toReturn = apiEndpoint + "/user"
	case "ORG_INFO":
		toReturn = apiEndpoint + "/user/orgs?per_page=1"
	case "USER_PICTURE":
		toReturn = "https://avatars.githubusercontent.com/u/" + endpoint + "?v=3&s=72"
	case "USER_SEARCH":
		toReturn = apiEndpoint + "/search/users?q="
	case "TEAM":
		toReturn = apiEndpoint + "/teams/"
	case "TEAMS":
		toReturn = apiEndpoint + "/user/teams?per_page=100"
	case "TEAM_PROFILE":
		toReturn = hostName + "/orgs/%s/teams/%s"
	default:
		toReturn = apiEndpoint
	}

	return toReturn
}
