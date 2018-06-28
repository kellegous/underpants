package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/playdots/underpants/auth"
	"github.com/playdots/underpants/config"
	"github.com/playdots/underpants/user"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Name ...
const Name = "google"

const profileURL = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json"

type provider struct{}

// Provider is the auth.Provider for Google OAuth
var Provider auth.Provider = &provider{}

func configFor(ctx *config.Context) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     ctx.Oauth.ClientID,
		ClientSecret: ctx.Oauth.ClientSecret,
		Endpoint:     google.Endpoint,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		RedirectURL: fmt.Sprintf("%s://%s%s",
			ctx.Scheme(),
			ctx.Host(),
			auth.BaseURI),
	}
}

func fetchUser(cfg *oauth2.Config, tok *oauth2.Token) (*user.Info, error) {
	res, err := cfg.Client(context.Background(), tok).Get(profileURL)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var u struct {
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture string `json:"picture"`
	}

	if err := json.NewDecoder(res.Body).Decode(&u); err != nil {
		return nil, err
	}

	return &user.Info{
		Name:    u.Name,
		Email:   u.Email,
		Picture: u.Picture,
	}, nil
}

func (p *provider) Validate(cfg *config.Info) error {
	return nil
}

func (p *provider) GetAuthURL(ctx *config.Context, r *http.Request) string {
	u := configFor(ctx).AuthCodeURL(
		auth.GetCurrentURL(ctx, r).String())

	// If the config is restricting by domain, then add that to the auth url.
	if ctx.HasDomainGroups() {
		u += "&hd=*"
	} else if d := ctx.Oauth.Domain; d != "" {
		u += fmt.Sprintf("&hd=%s", url.QueryEscape(d))
	}

	return u
}

func (p *provider) Authenticate(ctx *config.Context, r *http.Request) (*user.Info, *url.URL, error) {
	state := r.FormValue("state")
	if state == "" {
		return nil, nil, errors.New("state parameter is missing")
	}

	ret, err := url.Parse(state)
	if err != nil {
		return nil, nil, errors.New("invalid return URL")
	}

	cfg := configFor(ctx)

	code := r.FormValue("code")
	if code == "" {
		return nil, nil, errors.New("code parameter is missing")
	}

	tok, err := cfg.Exchange(context.Background(), code)
	if err != nil {
		return nil, nil, err
	}

	u, err := fetchUser(cfg, tok)
	if err != nil {
		return nil, nil, err
	}

	// Only check domain if there are no domain groups, otherwise this will be checked in
	// the proxy/backend.go serveHTTPProxy method
	if !ctx.HasDomainGroups() {
		if !strings.HasSuffix(u.Email, "@"+ctx.Oauth.Domain) {
			return nil, nil, fmt.Errorf("user %s is not in domain %s",
				u.Email,
				ctx.Oauth.Domain)
		}
	}

	return u, ret, nil
}
