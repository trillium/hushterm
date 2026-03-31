package redact

import (
	"strings"
	"testing"
)

func TestNewEngine_DefaultStyle(t *testing.T) {
	e, err := NewEngine("")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if e.style != StylePlaceholder {
		t.Errorf("default style = %q, want %q", e.style, StylePlaceholder)
	}
}

func TestNewEngine_CustomStyle(t *testing.T) {
	for _, style := range []Style{StyleMask, StylePlaceholder, StyleHash} {
		e, err := NewEngine(style)
		if err != nil {
			t.Fatalf("NewEngine(%q): %v", style, err)
		}
		if e.style != style {
			t.Errorf("style = %q, want %q", e.style, style)
		}
	}
}

func TestNewEngine_HasBuiltinPatterns(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.patterns) == 0 {
		t.Fatal("expected builtin patterns, got none")
	}
}

func TestRedact_BuiltinPatterns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string // expected substring in output
	}{
		{
			name:     "aws_access_key",
			input:    "key: AKIAIOSFODNN7EXAMPLE ",
			contains: "[REDACTED:AWS_KEY]",
		},
		{
			name:     "private_key",
			input:    "-----BEGIN RSA PRIVATE KEY-----",
			contains: "[REDACTED:PRIVATE_KEY]",
		},
		{
			name:     "jwt_token",
			input:    "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			contains: "[REDACTED:JWT]",
		},
		{
			name:     "github_token",
			input:    "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
			contains: "[REDACTED:GITHUB_TOKEN]",
		},
		{
			name:     "generic_api_key",
			input:    "key: sk-live-abcdefghijklmnopqrstuvwxyz",
			contains: "[REDACTED:API_KEY]",
		},
		{
			name:     "bearer_token",
			input:    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abc",
			contains: "[REDACTED:BEARER_TOKEN]",
		},
		{
			name:     "email",
			input:    "contact user@example.com for info",
			contains: "[REDACTED:EMAIL]",
		},
		{
			name:     "ssn",
			input:    "SSN: 123-45-6789",
			contains: "[REDACTED:SSN]",
		},
		{
			name:     "phone_us",
			input:    "call (555) 123-4567 now",
			contains: "[REDACTED:PHONE]",
		},
		{
			name:     "phone_international",
			input:    "dial +442071234567 please",
			contains: "[REDACTED:PHONE]",
		},
		{
			name:     "ipv4",
			input:    "server at 192.168.1.100 is down",
			contains: "[REDACTED:IP_ADDRESS]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := NewEngine(StylePlaceholder)
			if err != nil {
				t.Fatal(err)
			}
			out := string(e.Redact([]byte(tt.input)))
			if !strings.Contains(out, tt.contains) {
				t.Errorf("Redact(%q) = %q, want substring %q", tt.input, out, tt.contains)
			}
		})
	}
}

func TestRedact_DisabledPatternPassesThrough(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	// Disable all patterns.
	for i := range e.patterns {
		e.patterns[i].Enabled = false
	}
	input := "user@example.com and 123-45-6789"
	out := string(e.Redact([]byte(input)))
	if out != input {
		t.Errorf("with all patterns disabled, expected input unchanged, got %q", out)
	}
}

func TestRedact_StyleMask(t *testing.T) {
	e, err := NewEngine(StyleMask)
	if err != nil {
		t.Fatal(err)
	}
	input := "email: user@example.com end"
	out := string(e.Redact([]byte(input)))
	// The email "user@example.com" is 16 chars, so mask should be 16 asterisks.
	if !strings.Contains(out, "****************") {
		t.Errorf("StyleMask output = %q, expected asterisks for email", out)
	}
	if strings.Contains(out, "user@example.com") {
		t.Error("StyleMask did not redact the email")
	}
}

func TestRedact_StylePlaceholder(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	input := "email: user@example.com end"
	out := string(e.Redact([]byte(input)))
	if !strings.Contains(out, "[REDACTED:EMAIL]") {
		t.Errorf("StylePlaceholder output = %q, expected [REDACTED:EMAIL]", out)
	}
}

func TestRedact_MultiplePatterns(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	input := "user@example.com lives at 192.168.1.1"
	out := string(e.Redact([]byte(input)))
	if !strings.Contains(out, "[REDACTED:EMAIL]") {
		t.Errorf("expected EMAIL redaction in %q", out)
	}
	if !strings.Contains(out, "[REDACTED:IP_ADDRESS]") {
		t.Errorf("expected IP_ADDRESS redaction in %q", out)
	}
}

func TestRedact_EmptyInput(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	out := e.Redact([]byte(""))
	if len(out) != 0 {
		t.Errorf("expected empty output for empty input, got %q", out)
	}
}

func TestRedact_NoMatches(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	input := "just a normal sentence with no secrets"
	out := string(e.Redact([]byte(input)))
	if out != input {
		t.Errorf("expected unchanged output, got %q", out)
	}
}

func TestRedact_StyleMask_WithFiller(t *testing.T) {
	e, err := NewEngine(StyleMask)
	if err != nil {
		t.Fatal(err)
	}
	e.filler = "🤫"
	out := string(e.Redact([]byte("email: user@example.com")))
	// Should replace email with 🤫 repeated to match display width
	if !strings.Contains(out, "email: ") {
		t.Errorf("email label should be preserved, got %q", out)
	}
	if strings.Contains(out, "user@example.com") {
		t.Errorf("email should be redacted, got %q", out)
	}
	if !strings.Contains(out, "🤫") {
		t.Errorf("filler 🤫 should appear in output, got %q", out)
	}
}

func TestRedact_StylePlaceholder_PreserveWidth(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	e.preserveWidth = true
	out := string(e.Redact([]byte("email: user@example.com")))
	// [REDACTED:EMAIL] is 15 chars, user@example.com is 15 chars, should match exactly
	if !strings.Contains(out, "email: ") {
		t.Errorf("email label should be preserved, got %q", out)
	}
	if strings.Contains(out, "user@example.com") {
		t.Errorf("email should be redacted, got %q", out)
	}
	if !strings.Contains(out, "[REDACTED:EMAIL]") {
		t.Errorf("placeholder should appear, got %q", out)
	}
}

func TestFitToWidth_Shorter(t *testing.T) {
	e, _ := NewEngine(StylePlaceholder)
	result := e.fitToWidth("hi", 5)
	if len(result) != 5 {
		t.Errorf("fitToWidth should pad to 5 chars, got %q (len %d)", result, len(result))
	}
}

func TestFitToWidth_Longer(t *testing.T) {
	e, _ := NewEngine(StylePlaceholder)
	result := e.fitToWidth("verylongword", 5)
	if len([]rune(result)) > 5 {
		t.Errorf("fitToWidth should truncate to max 5 runes, got %q", result)
	}
	if !strings.Contains(result, "…") {
		t.Errorf("fitToWidth should add ellipsis when truncating, got %q", result)
	}
}

func TestRepeatToWidth_Basic(t *testing.T) {
	e, _ := NewEngine(StyleMask)
	result := e.repeatToWidth("*", 5)
	if result != "*****" {
		t.Errorf("repeatToWidth should produce 5 asterisks, got %q", result)
	}
}

func TestRepeatToWidth_MultiChar(t *testing.T) {
	e, _ := NewEngine(StyleMask)
	result := e.repeatToWidth("🤫", 3)
	// 🤫 has display width 2, so 3 width = 1.5 reps, should round up to 2 reps then trim
	if !strings.Contains(result, "🤫") {
		t.Errorf("repeatToWidth should contain filler, got %q", result)
	}
}

func TestApplyConfig_Filler(t *testing.T) {
	e, _ := NewEngine(StyleMask)
	cfg := &Config{
		Filler: "#",
	}
	e.ApplyConfig(cfg)
	if e.filler != "#" {
		t.Errorf("ApplyConfig should set filler to #, got %q", e.filler)
	}
}

func TestApplyConfig_PreserveWidth(t *testing.T) {
	e, _ := NewEngine(StylePlaceholder)
	cfg := &Config{
		PreserveWidth: true,
	}
	e.ApplyConfig(cfg)
	if !e.preserveWidth {
		t.Error("ApplyConfig should set preserveWidth to true")
	}
}
