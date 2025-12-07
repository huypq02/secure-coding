package validator

import (
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	MaxEmailLength      = 254
	MaxLocalPartLength  = 64
	MaxDomainPartLength = 190
	MaxUsernameLength   = 100
)

// Allow-list regexp for username
var (
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_\-.]{2,31}$`)
)

// Validate email by following RFC standard
func ValidateEmail(email string) error {

	// Validate the length of email (DoS protection)
	if len(email) == 0 || len(email) > MaxEmailLength {
		return errors.New("invalid email")
	}

	// Sanitize the input of email
	email = SanitizeInput(email)

	// Parse the mail format
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return errors.New("invalid email")
	}

	email = addr.Address

	// Remove special characters in the mail
	if strings.ContainsAny(email, "<>()[]\\,;:\" \t\r\n") {
		return errors.New("invalid email")
	}

	// Split and validate email parts
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return errors.New("invalid email")
	}

	localPart := parts[0]
	domainPart := parts[1]

	// Validate the length of the local part
	if len(localPart) == 0 || len(localPart) > MaxLocalPartLength {
		return errors.New("invalid email")
	}
	// Validate the length of the domain part
	if len(domainPart) == 0 || len(domainPart) > MaxDomainPartLength {
		return errors.New("invalid email")
	}

	// Domain must contain at least one dot
	if !strings.Contains(domainPart, ".") {
		return errors.New("invalid email")
	}

	// Domain must not start/end with dot or hyphen
	if strings.HasPrefix(domainPart, ".") || strings.HasSuffix(domainPart, ".") ||
		strings.HasPrefix(domainPart, "-") || strings.HasSuffix(domainPart, "-") {
		return errors.New("invalid email")
	}

	// Check for consecutive dots
	if strings.Contains(email, "..") {
		return errors.New("invalid email")
	}

	return nil
}

func ValidateUsername(username string) error {

	// Validate the length of username (DoS protection)
	if len(username) > MaxUsernameLength {
		return errors.New("invalid username")
	}

	// Validate username (business rule)
	if !usernameRegex.MatchString(username) {
		return errors.New("invalid username")
	}

	// Sanitize the input of username
	username = SanitizeInput(username)

	invalidPatterns := []string{"__", "..", "--"}
	for _, pattern := range invalidPatterns {
		// Check for invalid patterns
		if strings.Contains(username, pattern) {
			return errors.New("invalid username")
		}
	}

	return nil
}

// func ValidateAge(age int) error {

// }

// Handle canonicalization, remove null byte, standardize UTF-8
func SanitizeInput(input string) string {
	// Remove null byte
	input = strings.ReplaceAll(input, "\x00", "")
	// Standardize UTF-8
	if !utf8.ValidString(input) {
		input = strings.ToValidUTF8(input, "")
	}

	// Remove other characters unexpectedly
	input = strings.Map(func(r rune) rune {
		// Remove control chars (U+0000 to U+001F, U+007F to U+009F)
		if r < 0x20 || (r >= 0x7F && r <= 0x9F) {
			return -1
		}

		// Remove zero-width chars
		if r == 0x200B || r == 0x200C || r == 0x200D || r == 0xFEFF {
			return -1
		}

		// Remove directional overrides
		if r >= 0x202A && r <= 0x202E {
			return -1
		}
		return r
	}, input)

	// Trim leading/trailing whitespace
	input = strings.TrimSpace(input)

	return input
}
