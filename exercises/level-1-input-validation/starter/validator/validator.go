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
)

// Allow-list regexp for username
var (
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_\-.]{2,31}$`)
)

// Validate email by following RFC standard
func ValidateEmail(email string) error {

	// Validate the length of email
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

	return nil
}

// func ValidateUsername(email string) error {

// }

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
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return -1
		}
		if r == 0x7F { // DEL character
			return -1
		}
		return r
	}, input)

	return input
}
