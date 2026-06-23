package keychain

import (
	"fmt"
	"strconv"
	"unicode"
)

// validateID rejects ids containing characters unsafe for OS keychain key names.
// Allowed: letters, digits, hyphens, underscores, dots, forward slashes.
func validateID(id string) error {
	if id == "" {
		return fmt.Errorf("secret id must not be empty")
	}
	for _, r := range id {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.' && r != '/' {
			return fmt.Errorf("invalid secret id %q: only letters, digits, -, _, ., / are allowed", id)
		}
	}
	return nil
}

// parseKeyID validates that a keyctl output string is a numeric kernel key serial.
func parseKeyID(s string) (string, error) {
	if _, err := strconv.ParseInt(s, 10, 64); err != nil {
		return "", fmt.Errorf("unexpected keyctl output: %q", s)
	}
	return s, nil
}
