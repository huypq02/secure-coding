package utils

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Allow-list regexp for username
var (
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-.]{2,31}$`)
)

// // Validate email by following RFC standard
// func ValidateEmail(email string) error {
// 	email := SanitizeInput(email)

// }

// func ValidateUsername(email string) error {

// }

// func ValidateAge(age int) error {

// }

// Handle canonicalization, remove null byte, standardize UTF-8
func SanitizeInput(input string) string {
	// Encode URL if capable
	input, _ = url.QueryUnescape(input)
	// TODO: remove later
	fmt.Println("URL-Encoded ", input)
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
		return r
	}, input)

	return input
}
