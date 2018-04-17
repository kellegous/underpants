package config

import "fmt"

// Context is the configuration info plus all runtime parameters.
type Context struct {
	// Info is the config Info that was loaded from the config file.
	*Info

	// Port is the http port that was specified on the command line.
	Port int

	// Key is the hmac signing key for cookies, this is usually ephemeral.
	Key []byte

	// groupIdx is an index of group membership that makes permission checking efficient.
	groupIdx map[membership]bool
}

// membership is used as a key in the groupIdx of the Context.
type membership struct {
	Email, Group string
}

// Host is the normalized host URLs to the hub.
func (c *Context) Host() string {
	return c.Info.Host
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

// BuildContext constructs a new context.
func BuildContext(cfg *Info, port int, key []byte) *Context {
	idx := map[membership]bool{}
	for name, emails := range cfg.Groups {
		for _, email := range emails {
			idx[membership{email, name}] = true
		}
	}

	return &Context{
		Info:     cfg,
		Port:     port,
		Key:      key,
		groupIdx: idx,
	}
}

// UserMemberOfAny determines if a user belongs to any of the given groups.
func (c *Context) UserMemberOfAny(email string, groups []string) bool {
	if !c.HasGroups() {
		return true
	}

	for _, group := range groups {
		// The semantics of * are as if there is an anonymous group that covers all users.
		if group == "*" {
			return true
		}

		if c.groupIdx[membership{email, group}] {
			return true
		}
	}

	return false
}
