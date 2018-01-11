package mux

import "strings"

// Builder allows the construction of an http.Handler that is able to
// route based on path and host.
type Builder struct {
	hosts map[string]*PathMux
	any   *PathMux
}

// ForHost creates or gets the PathMux associated with a given host. Note
// that any ports are stripped from the host so that localhost and localhost:8080
// are equivalent entries.
func (b *Builder) ForHost(host string) *PathMux {
	h := hostWithoutPort(host)
	if m := b.hosts[h]; m != nil {
		return m
	}

	m := &PathMux{}
	b.hosts[h] = m
	return m
}

// ForAnyHost gets the PathMux that matches a request to any host.
func (b *Builder) ForAnyHost() *PathMux {
	return b.any
}

// Build constructs an http.Handler that can be used for serving requests.
// Note that the Builder can no longer be used after Build is called.
func (b *Builder) Build() *Serve {
	hosts := b.hosts
	for _, host := range hosts {
		host.build()
	}

	any := b.any
	any.build()

	*b = Builder{}

	return &Serve{
		hosts: hosts,
		any:   any,
	}
}

func hostWithoutPort(host string) string {
	ix := strings.IndexByte(host, ':')
	if ix == -1 {
		return host
	}
	return host[:ix]
}

// Create constructs a new empty Builder.
func Create() *Builder {
	return &Builder{
		hosts: map[string]*PathMux{},
		any:   &PathMux{},
	}
}
