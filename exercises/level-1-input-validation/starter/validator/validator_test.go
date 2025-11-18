package validator

import (
	"testing"
)

func TestValidateEmail(t *testing.T) {
	testcases := []struct {
		in string
		ok bool
	}{
		{"user@example.com", true},
		{"<script>alert(1)</script>@evil.com", false},
		{"", false},
	}

	for _, tc := range testcases {
		err := ValidateEmail(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("ValidateEmail(%q) ok=%v err=%v", tc.in, tc.ok, err)
		}
	}
}
