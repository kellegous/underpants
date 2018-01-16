package config

import "fmt"

// Context is the configuration info plus all runtime parameters.
type Context struct {
	*Info

	Port int

	Key []byte
}

// Host is the normalized host URLs to the hub.
func (c *Context) Host() string {
	switch c.Port {
	case 80, 443:
		return c.Info.Host
	}
	return fmt.Sprintf("%s:%d", c.Info.Host, c.Port)
}

// ListenAddr is the address that should be passed to net.Listen.
func (c *Context) ListenAddr() string {
	switch c.Port {
	case 80:
		return ":http"
	case 443:
		return ":https"
	}
	return fmt.Sprintf(":%d", c.Port)
}
