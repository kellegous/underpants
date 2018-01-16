package okta

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/kellegous/underpants/config"
)

func TestAuthURL(t *testing.T) {
	ctx := &config.Context{
		Info: &config.Info{
			Oauth: config.OAuthInfo{
				ClientID:     "client_id",
				ClientSecret: "client_secret",
				BaseURL:      "https://oktapreview.com",
			},
			Host: "foo.com",
		},
		Port: 9090,
	}

	r := &http.Request{
		Host: "boo.com:9090",
		URL: &url.URL{
			Path: "/",
		},
	}

	authURL, err := url.Parse(
		Provider.GetAuthURL(ctx, r))
	if err != nil {
		t.Fatal(err)
	}

	vals := authURL.Query()
	toVerify := map[string][]string{
		"client_id":    {"client_id"},
		"redirect_uri": {"http://foo.com:9090/__auth__/"},
		"scope": {
			strings.Join([]string{
				"openid",
				"profile",
				"email",
			}, " "),
		},
		"state": {"http://boo.com:9090/"},
	}

	for param, exp := range toVerify {
		if reflect.DeepEqual(vals[param], exp) {
			continue
		}

		t.Fatalf("expected param %s of %v but got %v",
			param,
			exp,
			vals[param])
	}

	if authURL.Host != "oktapreview.com" {
		t.Fatalf("expected url to have host of oktapreview.com got %s",
			authURL.Host)
	}

	if authURL.Path != "/oauth2/v1/authorize" {
		t.Fatalf("expected url to have path of /oauth2/v1/authorize got %s",
			authURL.Path)
	}
}
