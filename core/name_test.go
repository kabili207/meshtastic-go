package core

import (
	"testing"
	"unicode/utf8"
)

func TestValidateLongName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"under the limit", "Kabi", "Kabi"},
		{"exactly at the limit", "123456789012345678901234", "123456789012345678901234"},
		{"one byte over", "1234567890123456789012345", "123456789012345678901234"},
		{"empty", "", ""},
		// The 24-byte cut lands mid-rune: the partial sequence is dropped rather
		// than emitted, so the result stays valid UTF-8.
		{"multibyte straddling the limit", "12345678901234567890123é", "12345678901234567890123"},
		{"four-byte rune straddling the limit", "1234567890123456789012\U0001F600", "1234567890123456789012"},
		{"all multibyte", "ééééééééééééé", "éééééééééééé"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateLongName(tt.input)
			if got != tt.want {
				t.Errorf("ValidateLongName(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if len(got) > MaxLongName {
				t.Errorf("ValidateLongName(%q) = %q, %d bytes exceeds MaxLongName %d",
					tt.input, got, len(got), MaxLongName)
			}
			if !utf8.ValidString(got) {
				t.Errorf("ValidateLongName(%q) = %q, not valid UTF-8", tt.input, got)
			}
		})
	}
}

func TestValidateShortName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"under the limit", "AB", "AB"},
		{"exactly at the limit", "ABCD", "ABCD"},
		{"one byte over", "ABCDE", "ABCD"},
		{"emoji fits exactly", "\U0001F600", "\U0001F600"},
		// A 4-byte rune cannot follow a 2-byte one within 4 bytes, so it is dropped whole.
		{"multibyte straddling the limit", "é\U0001F600", "é"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateShortName(tt.input)
			if got != tt.want {
				t.Errorf("ValidateShortName(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if len(got) > MaxShortName {
				t.Errorf("ValidateShortName(%q) = %q, %d bytes exceeds MaxShortName %d",
					tt.input, got, len(got), MaxShortName)
			}
			if !utf8.ValidString(got) {
				t.Errorf("ValidateShortName(%q) = %q, not valid UTF-8", tt.input, got)
			}
		})
	}
}
