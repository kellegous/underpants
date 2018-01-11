package mux

import "net/http"

// Serve ...
type Serve struct {
	hosts map[string]*PathMux
	any   *PathMux
}

func (s *Serve) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if hh := s.hosts[hostWithoutPort(r.Host)]; hh != nil {
		if ph := hh.findHandler(r.URL.Path); ph != nil {
			ph.ServeHTTP(w, r)
			return
		}
	}

	if ph := s.any.findHandler(r.URL.Path); ph != nil {
		ph.ServeHTTP(w, r)
		return
	}

	http.NotFound(w, r)
}
