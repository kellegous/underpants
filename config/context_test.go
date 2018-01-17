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
