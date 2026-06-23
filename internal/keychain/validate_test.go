package keychain

import (
	"testing"
)

func TestValidateID(t *testing.T) {
	valid := []string{
		"mykey",
		"my-key",
		"my_key",
		"my.key",
		"my/key",
		"project/env/SECRET_KEY",
		"key123",
		"ABC.def-ghi_123/jkl",
	}
	for _, id := range valid {
		if err := validateID(id); err != nil {
			t.Errorf("validateID(%q) unexpected error: %v", id, err)
		}
	}

	invalid := []struct {
		id  string
		msg string
	}{
		{"", "empty id"},
		{"my key", "space"},
		{"my@key", "at sign"},
		{"my;key", "semicolon"},
		{"my\nkey", "newline"},
		{"my$key", "dollar sign"},
		{"my`key", "backtick"},
	}
	for _, tc := range invalid {
		if err := validateID(tc.id); err == nil {
			t.Errorf("validateID(%q) expected error for %s, got nil", tc.id, tc.msg)
		}
	}
}

func TestParseKeyID(t *testing.T) {
	valid := []string{"123456789", "0", "-1", "999999999999"}
	for _, s := range valid {
		got, err := parseKeyID(s)
		if err != nil {
			t.Errorf("parseKeyID(%q) unexpected error: %v", s, err)
		}
		if got != s {
			t.Errorf("parseKeyID(%q) = %q, want %q", s, got, s)
		}
	}

	invalid := []string{"abc", "12abc", "", "12 34", "0x1F"}
	for _, s := range invalid {
		if _, err := parseKeyID(s); err == nil {
			t.Errorf("parseKeyID(%q) expected error, got nil", s)
		}
	}
}
