package google

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/playdots/underpants/config"
	"github.com/playdots/underpants/user"
)

func TestAuthURLWithoutDomain(t *testing.T) {
	ctx := &config.Context{
		Info: &config.Info{
			Oauth: config.OAuthInfo{
				ClientID:     "client_id",
				ClientSecret: "client_secret",
			},
			Host: "foo.com:9090",
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

	authURL, err := url.Parse(
		Provider.GetAuthURL(ctx, r))
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

func TestValidateDomain(t *testing.T) {
	ctx := &config.Context{
		Info: &config.Info{
			Oauth: config.OAuthInfo{
				ClientID:     "client_id",
				ClientSecret: "client_secret",
				Domain:       "valid-domain.com",
			},
		},
	}

	user1 := &user.Info{
		Name:    "name",
		Email:   "user@valid-domain.com",
	}

	user2 := &user.Info{
		Name:    "name",
		Email:   "user@invalid-domain.com",
	}

	if _, err := ValidateDomain(ctx, user1); err != nil {
		t.Fatal(err)
	}

	if _, err := ValidateDomain(ctx, user2); err == nil {
		t.Fatalf("expected %s to fail validation", user2.Email)
	}
}

func TestValidateDomainNotConfigured(t *testing.T) {
	ctx := &config.Context{
		Info: &config.Info{
			Oauth: config.OAuthInfo{
				ClientID:     "client_id",
				ClientSecret: "client_secret",
			},
		},
	}

	user1 := &user.Info{
		Name:    "name",
		Email:   "user@valid-domain.com",
	}

	user2 := &user.Info{
		Name:    "name",
		Email:   "user@shady-domain.com",
	}

	if _, err := ValidateDomain(ctx, user1); err == nil {
		t.Fatalf("expected %s to fail validation", user1.Email)
	}

	if _, err := ValidateDomain(ctx, user2); err == nil {
		t.Fatalf("expected %s to fail validation", user2.Email)
	}
}
