package mux

import (
	"net/http"
	"net/url"
	"testing"
)

func requestTo(host, path string) *http.Request {
	return &http.Request{
		URL: &url.URL{
			Path: path,
		},
		Host: host,
	}
}

type handler struct {
	count int
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.count++
}

func (h *handler) Reset() {
	h.count = 0
}

func (h *handler) WasCalled() bool {
	return h.count == 1
}

func TestPathMux(t *testing.T) {
	pm := &PathMux{}

	var a handler
	pm.Handle("/a/", &a)

	var b handler
	pm.Handle("/a/b/", &b)

	var c handler
	pm.Handle("/a/b", &c)

	pm.build()

	tests := map[string]http.Handler{
		"/a/z":   &a,
		"/a/":    &a,
		"/a":     nil,
		"/a/b":   &c,
		"/a/b/":  &b,
		"/a/bb":  &a,
		"/a/b/c": &b,
		"/":      nil,
		"/aaaa":  nil,
	}

	names := map[http.Handler]string{
		&a:  "a",
		&b:  "b",
		&c:  "c",
		nil: "nil",
	}

	for path, rt := range tests {
		h := pm.findHandler(path)
		if h == rt {
			continue
		}

		t.Fatalf("for path %s expected %s but got %s",
			path,
			names[rt],
			names[h])
	}
}
