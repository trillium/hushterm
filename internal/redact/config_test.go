package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, `
style: mask
patterns:
  email: false
  ssn: true
custom:
  - name: custom_secret
    pattern: "SECRET_[A-Z0-9]+"
    label: CUSTOM_SECRET
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Style != "mask" {
		t.Errorf("style = %q, want mask", cfg.Style)
	}
	if enabled, ok := cfg.Patterns["email"]; !ok || enabled {
		t.Errorf("patterns[email] = %v, %v; want false, true", enabled, ok)
	}
	if enabled, ok := cfg.Patterns["ssn"]; !ok || !enabled {
		t.Errorf("patterns[ssn] = %v, %v; want true, true", enabled, ok)
	}
	if len(cfg.Custom) != 1 {
		t.Fatalf("custom len = %d, want 1", len(cfg.Custom))
	}
	if cfg.Custom[0].Name != "custom_secret" {
		t.Errorf("custom[0].name = %q", cfg.Custom[0].Name)
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestApplyConfig_TogglesBuiltinPatterns(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Patterns: map[string]bool{
			"email": false,
			"ssn":   true,
		},
	}
	e.ApplyConfig(cfg)

	// Verify email is disabled.
	for _, p := range e.patterns {
		if p.Name == "email" && p.Enabled {
			t.Error("email pattern should be disabled")
		}
		if p.Name == "ssn" && !p.Enabled {
			t.Error("ssn pattern should be enabled")
		}
	}

	// Email should pass through.
	out := string(e.Redact([]byte("user@example.com")))
	if strings.Contains(out, "[REDACTED:EMAIL]") {
		t.Error("disabled email pattern should not redact")
	}

	// SSN should still be redacted.
	out = string(e.Redact([]byte("SSN: 123-45-6789")))
	if !strings.Contains(out, "[REDACTED:SSN]") {
		t.Errorf("SSN should be redacted, got %q", out)
	}
}

func TestApplyConfig_CustomRegexPatterns(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Custom: []CustomPattern{
			{
				Name:    "internal_id",
				Pattern: `INTID-[0-9]{6}`,
				Label:   "INTERNAL_ID",
			},
		},
	}
	e.ApplyConfig(cfg)

	out := string(e.Redact([]byte("record INTID-123456 found")))
	if !strings.Contains(out, "[REDACTED:INTERNAL_ID]") {
		t.Errorf("custom pattern not applied, got %q", out)
	}
}

func TestApplyConfig_InvalidCustomRegex_SkipsPattern(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	patternCountBefore := len(e.patterns)

	cfg := &Config{
		Custom: []CustomPattern{
			{
				Name:    "bad_regex",
				Pattern: `[invalid(`,
				Label:   "BAD",
			},
		},
	}
	// Should not panic; should skip the bad pattern.
	e.ApplyConfig(cfg)

	if len(e.patterns) != patternCountBefore {
		t.Errorf("bad regex should be skipped; patterns count %d, want %d", len(e.patterns), patternCountBefore)
	}
}

func TestApplyConfig_Nil_NoOp(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	patternsBefore := len(e.patterns)
	styleBefore := e.style

	e.ApplyConfig(nil)

	if len(e.patterns) != patternsBefore {
		t.Error("nil config changed pattern count")
	}
	if e.style != styleBefore {
		t.Error("nil config changed style")
	}
}

func TestApplyConfig_CustomPatternDisabled(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}

	disabled := false
	cfg := &Config{
		Custom: []CustomPattern{
			{
				Name:    "disabled_pat",
				Pattern: `DISABLED-[0-9]+`,
				Label:   "DISABLED",
				Enabled: &disabled,
			},
		},
	}
	e.ApplyConfig(cfg)

	out := string(e.Redact([]byte("value DISABLED-999 here")))
	if strings.Contains(out, "[REDACTED:DISABLED]") {
		t.Error("disabled custom pattern should not redact")
	}
	if !strings.Contains(out, "DISABLED-999") {
		t.Errorf("input should be unchanged for disabled pattern, got %q", out)
	}
}

func TestApplyConfig_StyleOverride(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Style: "mask"}
	e.ApplyConfig(cfg)

	if e.style != StyleMask {
		t.Errorf("style = %q, want %q", e.style, StyleMask)
	}
}

func TestApplyConfig_CustomPatternMissingFields_Skipped(t *testing.T) {
	e, err := NewEngine(StylePlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	countBefore := len(e.patterns)

	cfg := &Config{
		Custom: []CustomPattern{
			{Name: "", Pattern: "abc", Label: "X"},     // no name
			{Name: "n", Pattern: "", Label: "X"},        // no pattern
			{Name: "n", Pattern: "abc", Label: ""},      // no label
		},
	}
	e.ApplyConfig(cfg)

	if len(e.patterns) != countBefore {
		t.Errorf("incomplete custom patterns should be skipped; count %d, want %d", len(e.patterns), countBefore)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte(`{{{not yaml`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}
