package validator

import (
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	MaxEmailLength = 254
)

// Allow-list regexp for username
var (
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_\-.]{2,31}$`)
)

// Validate email by following RFC standard
func ValidateEmail(email string) error {

	// Check length of email
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

	// Remove special characters in the mail
	if strings.ContainsAny(addr.Address, "<>()[]\\,;:\" \t\r\n") {
		return errors.New("email contains special characters")
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
