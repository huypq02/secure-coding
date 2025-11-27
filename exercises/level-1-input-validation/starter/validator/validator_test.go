package validator

import (
	"strings"
	"testing"
)

func TestValidateEmail(t *testing.T) {
	testcases := []struct {
		in string
		ok bool
	}{
		{"user@example.com", true},
		{"user.name+tag@example.co.uk", true},
		{"<script>alert(1)</script>@evil.com", false},
		{"", false},
		{"user@localhost", false},                            // no TLD
		{"user..name@example.com", false},                    // consecutive dots
		{"user@.example.com", false},                         // domain starts with dot
		{"user@example.com.", false},                         // domain ends with dot
		{"user@-example.com", false},                         // domain starts with hyphen
		{"a@b.c", true},                                      // minimal valid email
		{strings.Repeat("a", 65) + "@example.com", false},    // local too long
		{"user@" + strings.Repeat("a", 254) + ".com", false}, // domain too long
		{" user@example.com ", true},
	}

	for _, tc := range testcases {
		err := ValidateEmail(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("ValidateEmail(%q) ok=%v err=%v", tc.in, tc.ok, err)
		}
	}
}
