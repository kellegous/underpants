package proxy

import (
	"github.com/playdots/underpants/auth"
	"github.com/playdots/underpants/config"
	"github.com/playdots/underpants/internal"
	"github.com/playdots/underpants/mux"
)

// Setup adds the proxy handlers to the mux.Builder.
func Setup(ctx *config.Context, prv auth.Provider, mb *mux.Builder) {
	for _, route := range ctx.Routes {
		mb.ForHost(route.From).Handle("/",
			internal.AddSecurityHeaders(ctx.Info,
				&Backend{
					Ctx:          ctx,
					Route:        route,
					AuthProvider: prv,
				}))
	}
}
