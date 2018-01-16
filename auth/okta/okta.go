package okta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kellegous/underpants/auth"
	"github.com/kellegous/underpants/config"
	"github.com/kellegous/underpants/user"

	"golang.org/x/oauth2"
)

// Name is the name for this provider as used in config.Info.
const Name = "okta"

// Provider is the auth.Provider for Okta oauth
var Provider = &provider{}

type provider struct{}

func configFor(ctx *config.Context) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     ctx.Oauth.ClientID,
		ClientSecret: ctx.Oauth.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/oauth2/v1/authorize", ctx.Oauth.BaseURL),
			TokenURL: fmt.Sprintf("%s/oauth2/v1/token", ctx.Oauth.BaseURL),
		},
		Scopes: []string{
			"openid",
			"profile",
			"email",
		},
		RedirectURL: fmt.Sprintf("%s://%s%s",
			ctx.Scheme(),
			ctx.Host(),
			auth.BaseURI),
	}
}

func fetchUser(ctx *config.Context, c *http.Client) (*user.Info, error) {
	res, err := c.Get(fmt.Sprintf("%s/oauth2/v1/userinfo",
		strings.TrimRight(ctx.Oauth.BaseURL, "/")))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var u struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if err := json.NewDecoder(res.Body).Decode(&u); err != nil {
		return nil, err
	}

	return &user.Info{
		Email: u.Email,
		Name:  u.Name,
	}, nil
}

func (p *provider) GetAuthURL(ctx *config.Context, r *http.Request) string {
	return configFor(ctx).AuthCodeURL(
		auth.GetCurrentURL(ctx, r).String())
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

	u, err := fetchUser(ctx, cfg.Client(context.Background(), tok))
	if err != nil {
		return nil, nil, err
	}

	return u, ret, nil
}
