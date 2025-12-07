package validator

import (
	"strings"
	"testing"
)

func TestValidateEmail(t *testing.T) {
	testcases := []struct {
		name string
		in   string
		ok   bool
	}{
		// Valid emails
		{"valid simple", "user@example.com", true},
		{"valid with dot and plus", "user.name+tag@example.co.uk", true},
		{"minimal valid", "a@b.c", true},
		{"with trimmed spaces", " user@example.com ", true},

		// Empty/invalid format
		{"empty string", "", false},
		{"no TLD", "user@localhost", false},

		// XSS/injection attempts
		{"XSS script tag", "<script>alert(1)</script>@evil.com", false},

		// Domain validation
		{"consecutive dots in local", "user..name@example.com", false},
		{"domain starts with dot", "user@.example.com", false},
		{"domain ends with dot", "user@example.com.", false},
		{"domain starts with hyphen", "user@-example.com", false},

		// Length validation
		{"local part too long", strings.Repeat("a", 65) + "@example.com", false},
		{"domain too long", "user@" + strings.Repeat("a", 254) + ".com", false},
	}

	for _, tc := range testcases {
		err := ValidateEmail(tc.in)
		t.Run(tc.name, func(t *testing.T) {
			if (err == nil) != tc.ok {
				t.Errorf("ValidateEmail(%q) ok=%v err=%v", tc.in, tc.ok, err)
			}
		})

	}
}

func TestValidateUsername(t *testing.T) {
	testcases := []struct {
		name string
		in   string
		ok   bool
	}{
		// Valid usernames
		{"valid simple", "john", true},
		{"valid with number", "user123", true},
		{"valid with underscore", "john_doe", true},
		{"valid with dash", "john-doe", true},
		{"valid with dot", "john.doe", true},
		{"valid mixed", "user_123.test", true},
		{"valid min length", "abc", true},
		{"valid max length", strings.Repeat("a", 32), true},
		{"valid alphanumeric", "User123Test", true},

		// Length validation (DoS protection)
		{"empty string", "", false},
		{"too short 1 char", "a", false},
		{"too short 2 chars", "ab", false},
		{"too long 33 chars", strings.Repeat("a", 33), false},
		{"too long 100 chars", strings.Repeat("a", 100), false},
		{"extremely long (DoS)", strings.Repeat("a", 10_000_000), false},

		// Invalid starting character
		{"starts with underscore", "_john", false},
		{"starts with dash", "-john", false},
		{"starts with dot", ".john", false},
		{"starts with number is OK", "1john", true},

		// Injection attacks
		{"null byte injection", "admin\x00hacker", false},
		{"null byte middle", "user\x00name", false},
		{"multiple null bytes", "\x00\x00\x00", false},

		// Control character injection
		{"newline injection", "user\nname", false},
		{"carriage return", "user\rname", false},
		{"tab character", "user\tname", false},
		{"bell character", "user\x07name", false},
		{"escape character", "user\x1bname", false},
		{"vertical tab", "user\x0bname", false},
		{"form feed", "user\x0cname", false},

		// Special characters (not in allow-list)
		{"space in middle", "john doe", false}, // Space in middle is still invalid
		{"exclamation mark", "john!", false},
		{"at symbol", "john@doe", false},
		{"hash symbol", "john#doe", false},
		{"dollar sign", "john$doe", false},
		{"percent sign", "john%doe", false},
		{"ampersand", "john&doe", false},
		{"asterisk", "john*doe", false},
		{"parentheses", "john(doe)", false},
		{"brackets", "john[doe]", false},
		{"braces", "john{doe}", false},
		{"angle brackets", "john<doe>", false},
		{"slash", "john/doe", false},
		{"backslash", "john\\doe", false},
		{"pipe", "john|doe", false},
		{"semicolon", "john;doe", false},
		{"colon", "john:doe", false},
		{"quotes", "john\"doe", false},
		{"single quote", "john'doe", false},
		{"backtick", "john`doe", false},
		{"tilde", "john~doe", false},
		{"plus sign", "john+doe", false},
		{"equal sign", "john=doe", false},
		{"question mark", "john?doe", false},
		{"comma", "john,doe", false},

		// SQL injection attempts
		{"sql comment", "admin'--", false},
		{"sql union", "admin' UNION SELECT", false},
		{"sql or true", "admin' OR '1'='1", false},

		// XSS attempts
		{"script tag", "<script>alert(1)</script>", false},
		{"img tag", "<img src=x onerror=alert(1)>", false},
		{"javascript protocol", "javascript:alert(1)", false},

		// Path traversal attempts
		{"path traversal", "../../../etc/passwd", false},
		{"windows path", "..\\..\\windows\\system32", false},

		// Command injection attempts
		{"command injection pipe", "user|whoami", false},
		{"command injection semicolon", "user;ls", false},
		{"command injection backtick", "user`whoami`", false},
		{"command injection dollar", "user$(whoami)", false},

		// Unicode/encoding attacks
		{"invalid UTF-8", "user\xFF\xFE", false},
		{"zero-width space", "user\u200Bname", false},
		{"right-to-left override", "user\u202Ename", false},

		// Multiple special chars
		{"consecutive dots", "user..name", false},
		{"consecutive dashes", "user--name", false},
		{"consecutive underscores", "user__name", false},
		{"mixed invalid", "user@#$name", false},

		// Edge cases with whitespace
		{"only spaces", "   ", false},
		{"tab only", "\t\t\t", false},
		{"newline only", "\n\n\n", false},
		{"whitespace mixed", " \t\n ", false},

		// Valid edge cases (should pass)
		{"single dash middle", "user-name", true},
		{"single dot middle", "user.name", true},
		{"single underscore middle", "user_name", true},
		{"multiple separators", "user-name.test_123", true},
		{"all lowercase", "abcdefgh", true},
		{"all uppercase", "ABCDEFGH", true},
		{"all numbers (starts with letter)", "a123456", true},
		{"mixed case", "JohnDoe", true},

		// Boundary testing
		{"exactly 3 chars", "abc", true},
		{"exactly 32 chars", "a" + strings.Repeat("b", 30) + "c", true},
		{"31 chars", strings.Repeat("a", 31), true},
		{"4 chars", "abcd", true},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateUsername(tc.in)
			if (err == nil) != tc.ok {
				t.Errorf("ValidateUsername(%q) ok=%v err=%v", tc.in, tc.ok, err)
			}
		})

	}
}
