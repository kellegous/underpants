package mailchimp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/kellegous/underpants/auth"
	"github.com/kellegous/underpants/config"
	"github.com/kellegous/underpants/user"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/mailchimp"
)

// Name is the name for this provider as used in config.Info.
const Name = "mailchimp"

// Provider is the auth.Provider for Okta oauth
var Provider = &provider{}

type provider struct{}

func configFor(ctx *config.Context) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     ctx.Oauth.ClientID,
		ClientSecret: ctx.Oauth.ClientSecret,
		Endpoint:     mailchimp.Endpoint,
		RedirectURL: fmt.Sprintf("%s://%s%s",
			ctx.Scheme(),
			ctx.Host(),
			auth.BaseURI),
	}
}

func (p *provider) Validate(cfg *config.Info) error {
	if cfg.Oauth.ClientID == "" {
		return errors.New("the mailchimp provider requires a client-id")
	}

	if cfg.Oauth.ClientSecret == "" {
		return errors.New("the mailchimp provider requires a client-secret")
	}

	return nil
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

	u, err := fetchUser(cfg.Client(r.Context(), tok))
	if err != nil {
		return nil, nil, err
	}

	return u, ret, nil
}

func fetchUser(c *http.Client) (*user.Info, error) {
	req, err := http.NewRequest(http.MethodGet, "https://login.mailchimp.com/oauth2/metadata", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// This structure is not documented in official docs at https://mailchimp.com/developer/guides/how-to-use-oauth2/
	var info struct {
		Login struct {
			Email string
		}
	}

	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}

	u := user.Info{
		Email: info.Login.Email,
	}

	return &u, nil
}
