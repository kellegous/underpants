package slack

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/kellegous/underpants/auth"
	"github.com/kellegous/underpants/config"
	"github.com/kellegous/underpants/user"

	sapi "github.com/nlopes/slack"
	"golang.org/x/oauth2"
	slackoauth "golang.org/x/oauth2/slack"
)

// Name is the name for this provider as used in config.Info
const Name = "slack"

// Provider is the auth.Provider for Slack
var Provider = &provider{}

type provider struct{}

func configFor(ctx *config.Context) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     ctx.Oauth.ClientID,
		ClientSecret: ctx.Oauth.ClientSecret,
		Endpoint:     slackoauth.Endpoint,
		Scopes: []string{
			"bot",
			"users.profile:read",
		},
		RedirectURL: fmt.Sprintf("%s://%s%s",
			ctx.Scheme(),
			ctx.Host(),
			auth.BaseURI),
	}
}

func fetchUser(cfg *oauth2.Config, tok *oauth2.Token) (*user.Info, error) {
	sc := sapi.New(tok.AccessToken, sapi.OptionHTTPClient(cfg.Client(context.Background(), tok)))
	uid := tok.Extra("user_id").(string)
	res, err := sc.GetUserInfo(uid)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	return &user.Info{
		Name:    res.RealName,
		Email:   res.Profile.Email,
		Picture: res.Profile.Image48,
	}, nil

}

// Validate validates
func (p *provider) Validate(cfg *config.Info) error {
	return nil
}

// GetAuthURL gets the auth url
func (p *provider) GetAuthURL(ctx *config.Context, r *http.Request) string {
	return configFor(ctx).AuthCodeURL(
		auth.GetCurrentURL(ctx, r).String())
}

// Authenticate authenticates a user
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

	return u, ret, nil
}
