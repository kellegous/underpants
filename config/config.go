package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// OAuthInfo is the part of the configuration info that contains information
// about the oauth provider.
type OAuthInfo struct {
	Provider string `json:"provider"`

	ClientID     string `json:"client-id"`
	ClientSecret string `json:"client-secret"`

	// Google provider properties
	Domain string `json:"domain"`

	// Okta provider properties
	BaseURL string `json:"base-url"`
}

// RouteInfo is the part of the configuration info that contains information
// about an individual route.
type RouteInfo struct {
	// The hostname (excluding port) for the public facing hostname.
	From string

	// The base authority (i.e. http://backend.example.com:8080) for the backend. Backends
	// can be referenced through either http:// or https:// base urls. If you provide a
	// non-root (i.e. http://example.com/foo/bar/) URL, the path will be merged with the
	// request path as per RFC 3986 Section 5.2.
	To string

	toURL *url.URL

	// A list of groups which may access this route.  If groups are configured,
	// users who are not a member of one of these groups will be denied access.
	// A special group, `*`, may be specified which allows any authenticated
	// user.
	AllowedGroups []string `json:"allowed-groups"`
}

// ToURL ...
func (r *RouteInfo) ToURL() *url.URL {
	return r.toURL
}

// Info is a configuration object that is loaded directly from the json config file.
type Info struct {
	// The host (with the port specification) that will be acting as the hub.
	Host string

	// OAuth related settings
	Oauth OAuthInfo

	// Whether or not to add a set of security headers to all HTTP responses:
	//
	//    Strict-Transport-Security -- if certs are present, enforce HTTPS
	//    Cache-Control: private, no-cache -- prevent downstream caching
	//    Pragma: no-cache -- prevent HTTP/1.0 downstream caching
	//    X-Frame-Options: SAMEORIGIN -- prevent clickjacking
	//
	// Enable this if it your applications are OK with it and you want additional
	// security.
	AddSecurityHeaders bool `json:"use-strict-security-headers"`

	// TLS certificiate files to enable https on the hub and endpoints. TLS is highly
	// recommended and it is global. You cannot run some routes over HTTP and others over
	// HTTPS. If you need to do this, you should use two instances of underpants (one on
	// port 80 and the other on 443).
	Certs []struct {
		Crt string
		Key string
	}

	// Specify the Scheme of public internet facing traffic. While this will generally be 1:1 with
	// the presences of Certs, using underpants behind another proxy that does SSL termination
	// such as an AWS Elastic Load Balancer, would mean no certs, but use https scheme.
	UseHttps bool `json:"use-https"`

	// A mapping of group names to lists of user email addresses that are members
	// of that group.  If this section is present, then the default behaviour for
	// a route is to deny all users not in a group on its allowed-groups list.
	Groups map[string][]string

	// The mappings from hostname to backend server.
	Routes []*RouteInfo
}

// HasCerts is used to dermine if the instance is running over HTTP or HTTPS, this indicates whether
// any certificates were included in the configuration.
func (i *Info) HasCerts() bool {
	return len(i.Certs) > 0
}

// HasGroups is used to determine if the instance is configured for more granular group-based access
// control lists.
func (i *Info) HasGroups() bool {
	return len(i.Groups) > 0
}

// Scheme is a convience method for getting the relevant scheme based on whether certificates were
// included in the configuration.
func (i *Info) Scheme() string {
	if i.UseHttps {
		return "https"
	}
	if len(i.Certs) > 0 {
		return "https"
	}
	return "http"
}

// initRoute initializes a RouteInfo by parsing and validating its contents.
func initRoute(r *RouteInfo) error {
	toURL, err := url.Parse(r.To)
	if err != nil {
		return err
	}

	r.toURL = toURL
	return nil
}

// If ENV var is set, overwrite the target passed in
func initFromEnvVar(varName string, target *string) {
	envVal := os.Getenv(varName)
	if envVal != "" {
		*target = envVal
	}
}

func initInfo(n *Info) error {
	// Allow overwriting oauth config from env vars
	initFromEnvVar("OAUTH_PROVIDER", &n.Oauth.Provider)
	initFromEnvVar("OAUTH_DOMAIN", &n.Oauth.Domain)
	initFromEnvVar("OAUTH_BASE_URL", &n.Oauth.BaseURL)
	initFromEnvVar("OAUTH_CLIENT_ID", &n.Oauth.ClientID)
	initFromEnvVar("OAUTH_CLIENT_SECRET", &n.Oauth.ClientSecret)

	if n.Oauth.BaseURL != "" {
		n.Oauth.BaseURL = strings.TrimRight(n.Oauth.BaseURL, "/")
	}

	if n.Oauth.ClientID == "" {
		return errors.New("oauth.client-id is required")
	}

	if n.Oauth.ClientSecret == "" {
		return errors.New("oauth.client-secret is required")
	}

	for _, route := range n.Routes {
		if err := initRoute(route); err != nil {
			return fmt.Errorf("Route %s has invalid To URL: %s",
				route.From,
				err)
		}
	}

	return nil
}

// ReadFile loads the configuraiton info from the given file.
func (i *Info) ReadFile(filename string) error {
	*i = Info{}

	r, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer r.Close()

	if err := json.NewDecoder(r).Decode(i); err != nil {
		return err
	}

	return initInfo(i)
}
