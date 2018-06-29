package config

import (
	"strings"
	"testing"
)

type userMemberOfAnyTest struct {
	Email    string
	Groups   []string
	Expected bool
}

func TestUserMemberOfAny(t *testing.T) {
	cfg := &Info{
		Groups: map[string][]string{
			"a": {"a@a.com", "b@a.com"},
			"b": {"b@a.com", "b@b.com"},
		},
	}

	ctx := BuildContext(cfg, 80, []byte{})

	tests := []userMemberOfAnyTest{
		{"c@c.com", []string{"a", "b"}, false},
		{"c@c.com", []string{"*"}, true},

		{"a@a.com", []string{}, false},
		{"a@a.com", nil, false},
		{"a@a.com", []string{"b"}, false},
		{"a@a.com", []string{"a"}, true},
		{"a@a.com", []string{"a", "b"}, true},
		{"a@a.com", []string{"b", "*"}, true},
	}

	for _, test := range tests {
		if ctx.UserMemberOfAny(test.Email, test.Groups) != test.Expected {
			t.Fatalf("%s member of any of %s should have been %t",
				test.Email,
				strings.Join(test.Groups, ","),
				test.Expected)
		}
	}
}

type domainMemberOfAnyTest struct {
	Domain       string
	DomainGroups []string
	Expected     bool
}

func TestDomainMemberOfAny(t *testing.T) {
	cfg := &Info{
		DomainGroups: map[string][]string{
			"a": {"a.com", "ab.com"},
			"b": {"b.com"},
		},
	}

	ctx := BuildContext(cfg, 80, []byte{})

	tests := []domainMemberOfAnyTest{
		{"c.com", []string{"a", "b"}, false},
		{"c.com", []string{"*"}, true},

		{"a.com", []string{}, false},
		{"a.com", nil, false},
		{"a.com", []string{"b"}, false},
		{"a.com", []string{"a"}, true},
		{"a.com", []string{"a", "b"}, true},
		{"a.com", []string{"b", "*"}, true},
	}

	for _, test := range tests {
		if ctx.DomainMemberOfAny(test.Domain, test.DomainGroups) != test.Expected {
			t.Fatalf("%s member of any of %s should have been %t",
				test.Domain,
				strings.Join(test.DomainGroups, ","),
				test.Expected)
		}
	}
}

func TestDomainMemberOfAnyWithNoAllowedDomainGroups(t *testing.T) {
	cfg := &Info{
		DomainGroups: map[string][]string{
			"a": {"a.com"},
			"b": {"b.com"},
		},
	}

	ctx := BuildContext(cfg, 80, []byte{})

	tests := []domainMemberOfAnyTest{
		{"a.com", []string{}, false},
		{"b.com", []string{}, false},
	}

	for _, test := range tests {
		if ctx.DomainMemberOfAny(test.Domain, test.DomainGroups) != test.Expected {
			t.Fatalf("%s member of any of %s should have been %t",
				test.Domain,
				strings.Join(test.DomainGroups, ","),
				test.Expected)
		}
	}
}
