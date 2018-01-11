package google

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/kellegous/underpants/config"
)

func TestAuthURLWithoutDomain(t *testing.T) {
	ctx := &config.Context{
		Info: &config.Info{
			Oauth: config.OAuthInfo{
				ClientID:     "client_id",
				ClientSecret: "client_secret",
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

	u, err := Provider.GetAuthURL(ctx, r)
	if err != nil {
		t.Fatal(err)
	}

	authURL, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}

	vals := authURL.Query()
	toVerify := map[string][]string{
		"client_id":    {"client_id"},
		"redirect_uri": {"http://foo.com:9090/__auth__/"},
		"scope": {
			strings.Join([]string{
				"https://www.googleapis.com/auth/userinfo.profile",
				"https://www.googleapis.com/auth/userinfo.email",
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
}

func TestAuthURLWith(t *testing.T) {
	ctx := &config.Context{
		Info: &config.Info{
			Oauth: config.OAuthInfo{
				ClientID:     "client_id",
				ClientSecret: "client_secret",
				Domain:       "k.com",
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

	u, err := Provider.GetAuthURL(ctx, r)
	if err != nil {
		t.Fatal(err)
	}

	authURL, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}

	vals := authURL.Query()
	toVerify := map[string][]string{
		"hd": {"k.com"},
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
}
