package redact

import (
	"os"
	"path/filepath"
	"testing"
)

// testPlaceholderReplacer is a simple replacement function for tests.
func testPlaceholderReplacer(label string, match []byte) []byte {
	return []byte("[REDACTED:" + label + "]")
}

func TestLoadBlocklistDir_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "secrets.yaml"), `
version: 1
source: test
case_sensitive: false
entries:
  - value: "my-secret-password"
    label: "PASSWORD"
  - value: "api-key-12345"
    label: "API_KEY"
`)
	bl, err := LoadBlocklistDir(dir)
	if err != nil {
		t.Fatalf("LoadBlocklistDir: %v", err)
	}
	if bl == nil {
		t.Fatal("expected non-nil blocklist")
	}

	out := bl.ReplaceAll([]byte("use my-secret-password here"), testPlaceholderReplacer)
	want := "use [REDACTED:PASSWORD] here"
	if string(out) != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestLoadBlocklistDir_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.yaml"), `
version: 1
entries:
  - value: "alpha-secret"
    label: "SECRET_A"
`)
	writeFile(t, filepath.Join(dir, "b.yml"), `
version: 1
entries:
  - value: "beta-secret"
    label: "SECRET_B"
`)
	bl, err := LoadBlocklistDir(dir)
	if err != nil {
		t.Fatalf("LoadBlocklistDir: %v", err)
	}
	if bl == nil {
		t.Fatal("expected non-nil blocklist")
	}

	out := string(bl.ReplaceAll([]byte("alpha-secret and beta-secret"), testPlaceholderReplacer))
	if got := out; got != "[REDACTED:SECRET_A] and [REDACTED:SECRET_B]" {
		t.Errorf("got %q", got)
	}
}

func TestLoadBlocklistDir_Symlinks(t *testing.T) {
	// Create source file in a separate directory.
	srcDir := t.TempDir()
	srcFile := filepath.Join(srcDir, "real.yaml")
	writeFile(t, srcFile, `
version: 1
entries:
  - value: "symlinked-secret"
    label: "SYMLINK"
`)

	// Create blocklist dir with symlink.
	blDir := t.TempDir()
	link := filepath.Join(blDir, "link.yaml")
	if err := os.Symlink(srcFile, link); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	bl, err := LoadBlocklistDir(blDir)
	if err != nil {
		t.Fatalf("LoadBlocklistDir: %v", err)
	}
	if bl == nil {
		t.Fatal("expected non-nil blocklist from symlink")
	}

	out := string(bl.ReplaceAll([]byte("found symlinked-secret here"), testPlaceholderReplacer))
	if out != "found [REDACTED:SYMLINK] here" {
		t.Errorf("got %q", out)
	}
}

func TestLoadBlocklistDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	bl, err := LoadBlocklistDir(dir)
	if err != nil {
		t.Fatalf("LoadBlocklistDir on empty dir: %v", err)
	}
	if bl != nil {
		t.Errorf("expected nil blocklist for empty dir, got %+v", bl)
	}
}

func TestLoadBlocklistDir_InvalidYAML_SkipsBadFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "bad.yaml"), `{{{not valid yaml at all`)
	writeFile(t, filepath.Join(dir, "good.yaml"), `
version: 1
entries:
  - value: "valid-entry"
    label: "GOOD"
`)
	bl, err := LoadBlocklistDir(dir)
	if err != nil {
		t.Fatalf("LoadBlocklistDir: %v", err)
	}
	if bl == nil {
		t.Fatal("expected non-nil blocklist (good file should load)")
	}

	out := string(bl.ReplaceAll([]byte("has valid-entry"), testPlaceholderReplacer))
	if out != "has [REDACTED:GOOD]" {
		t.Errorf("got %q", out)
	}
}

func TestNewBlocklist_CaseInsensitive(t *testing.T) {
	entries := []BlocklistEntry{
		{Value: "SecretValue", Label: "SECRET"},
	}
	bl := NewBlocklist(entries, false) // case_sensitive=false
	if bl == nil {
		t.Fatal("expected non-nil blocklist")
	}

	tests := []struct {
		input string
		want  string
	}{
		{"has SecretValue here", "has [REDACTED:SECRET] here"},
		{"has secretvalue here", "has [REDACTED:SECRET] here"},
		{"has SECRETVALUE here", "has [REDACTED:SECRET] here"},
	}
	for _, tt := range tests {
		out := string(bl.ReplaceAll([]byte(tt.input), testPlaceholderReplacer))
		if out != tt.want {
			t.Errorf("ReplaceAll(%q) = %q, want %q", tt.input, out, tt.want)
		}
	}
}

func TestNewBlocklist_CaseSensitive(t *testing.T) {
	entries := []BlocklistEntry{
		{Value: "SecretValue", Label: "SECRET"},
	}
	bl := NewBlocklist(entries, true) // case_sensitive=true
	if bl == nil {
		t.Fatal("expected non-nil blocklist")
	}

	// Exact match should be replaced.
	out := string(bl.ReplaceAll([]byte("has SecretValue here"), testPlaceholderReplacer))
	if out != "has [REDACTED:SECRET] here" {
		t.Errorf("got %q", out)
	}

	// Wrong case should NOT be replaced.
	out = string(bl.ReplaceAll([]byte("has secretvalue here"), testPlaceholderReplacer))
	if out != "has secretvalue here" {
		t.Errorf("case-sensitive should not match lowercase, got %q", out)
	}
}

func TestReplaceAll_OverlappingEntries_LongestWins(t *testing.T) {
	entries := []BlocklistEntry{
		{Value: "secret", Label: "SHORT"},
		{Value: "secret-password", Label: "LONG"},
	}
	bl := NewBlocklist(entries, true)
	if bl == nil {
		t.Fatal("expected non-nil blocklist")
	}

	out := string(bl.ReplaceAll([]byte("my secret-password is here"), testPlaceholderReplacer))
	// Longest match should win.
	if out != "my [REDACTED:LONG] is here" {
		t.Errorf("got %q, want longest match to win", out)
	}
}

func TestReplaceAll_EmptyInput(t *testing.T) {
	entries := []BlocklistEntry{
		{Value: "secret", Label: "SECRET"},
	}
	bl := NewBlocklist(entries, true)
	out := bl.ReplaceAll([]byte(""), testPlaceholderReplacer)
	if len(out) != 0 {
		t.Errorf("expected empty output, got %q", out)
	}
}

func TestReplaceAll_NilBlocklist(t *testing.T) {
	var bl *Blocklist
	input := []byte("no redaction here")
	out := bl.ReplaceAll(input, testPlaceholderReplacer)
	if string(out) != string(input) {
		t.Errorf("nil blocklist should return input unchanged, got %q", out)
	}
}

func TestNewBlocklist_EmptyEntries(t *testing.T) {
	bl := NewBlocklist(nil, true)
	if bl != nil {
		t.Errorf("expected nil blocklist for empty entries, got %+v", bl)
	}
}

func TestBlocklistHolder_LoadStore(t *testing.T) {
	var h BlocklistHolder

	// Initially nil.
	if h.Load() != nil {
		t.Error("expected nil on initial load")
	}

	entries := []BlocklistEntry{{Value: "test", Label: "TEST"}}
	bl := NewBlocklist(entries, true)
	h.Store(bl)

	loaded := h.Load()
	if loaded == nil {
		t.Fatal("expected non-nil after store")
	}

	out := string(loaded.ReplaceAll([]byte("a test value"), testPlaceholderReplacer))
	if out != "a [REDACTED:TEST] value" {
		t.Errorf("got %q", out)
	}

	// Store nil to clear.
	h.Store(nil)
	if h.Load() != nil {
		t.Error("expected nil after storing nil")
	}
}

// writeFile is a test helper that creates a file with the given content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
