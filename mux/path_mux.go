package mux

import (
	"net/http"
	"strings"

	"github.com/kellegous/underpants/util"
)

type route struct {
	path string
	hdr  http.Handler
}

// PathMux is a mux that routes only on request path.
type PathMux struct {
	routes []*route
}

// Handle associates a new handler to a path. Paths are matched consistent
// with net.ServeMux in the go standard library, except that host routes
// are not supported.
func (m *PathMux) Handle(path string, h http.Handler) *PathMux {
	if path == "" {
		panic("cannot route to empty path")
	}

	m.routes = append(m.routes, &route{
		path: path,
		hdr:  h,
	})

	return m
}

// HandleFunc is identical to Handle but accepts a function instead of a Handler.
func (m *PathMux) HandleFunc(path string, h func(w http.ResponseWriter, r *http.Request)) *PathMux {
	return m.Handle(path, http.HandlerFunc(h))
}

func (m *PathMux) build() {
	util.Sort(
		len(m.routes),
		func(i, j int) bool {
			return len(m.routes[i].path) > len(m.routes[j].path)
		}, func(i, j int) {
			m.routes[i], m.routes[j] = m.routes[j], m.routes[i]
		})
}

func pathDoesMatch(route, path string) bool {
	if route[len(route)-1] != '/' {
		return path == route
	}

	return strings.HasPrefix(path, route)
}

func (m *PathMux) findHandler(path string) http.Handler {
	// routes were sorted during build time by decreasing length, making
	// it possible to terminate early in this loop.
	for _, route := range m.routes {
		if pathDoesMatch(route.path, path) {
			return route.hdr
		}
	}

	return nil
}
