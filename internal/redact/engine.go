package redact

import (
	"regexp"

	"github.com/mattn/go-runewidth"
)

// Style controls how redacted content is displayed.
type Style string

const (
	StyleMask        Style = "mask"
	StylePlaceholder Style = "placeholder"
	StyleHash        Style = "hash"
)

// Pattern is a named regex pattern with a replacement label.
type Pattern struct {
	Name    string
	Regex   *regexp.Regexp
	Label   string // e.g. "AWS_KEY", "EMAIL"
	Enabled bool
}

// Engine applies redaction patterns to byte streams.
type Engine struct {
	style         Style
	patterns      []Pattern
	blocklist     BlocklistHolder
	preserveWidth bool
	filler        string
}

// NewEngine creates a redaction engine with builtin patterns.
func NewEngine(style Style) (*Engine, error) {
	if style == "" {
		style = StylePlaceholder
	}
	e := &Engine{
		style:         style,
		filler:        "*",
		preserveWidth: false,
	}
	e.patterns = builtinPatterns()
	return e, nil
}

// Blocklist returns the blocklist holder for external callers (watcher, CLI).
func (e *Engine) Blocklist() *BlocklistHolder {
	return &e.blocklist
}

// SetBlocklist atomically sets the active blocklist.
func (e *Engine) SetBlocklist(bl *Blocklist) {
	e.blocklist.Store(bl)
}

// Redact applies blocklist (literal matches) then regex patterns to the input.
func (e *Engine) Redact(data []byte) []byte {
	// Blocklist first — exact known PII takes priority.
	result := data
	if bl := e.blocklist.Load(); bl != nil {
		result = bl.ReplaceAll(result, e.replacement)
	}

	for _, p := range e.patterns {
		if !p.Enabled {
			continue
		}
		result = p.Regex.ReplaceAllFunc(result, func(match []byte) []byte {
			return e.replacement(p.Label, match)
		})
	}
	return result
}

// fitToWidth adjusts a string to match target display width.
// Pads with spaces if shorter, truncates with … if longer.
func (e *Engine) fitToWidth(s string, targetWidth int) string {
	if targetWidth <= 0 {
		return s
	}
	w := runewidth.StringWidth(s)
	if w == targetWidth {
		return s
	}
	if w < targetWidth {
		// Pad with spaces
		return s + repeatStr(" ", targetWidth-w)
	}
	// Truncate with ellipsis (…)
	// Try to fit "…" within target width
	if targetWidth <= 1 {
		return "…"
	}
	result := s
	for runewidth.StringWidth(result) > targetWidth-1 {
		// Remove last rune
		runes := []rune(result)
		if len(runes) == 0 {
			break
		}
		result = string(runes[:len(runes)-1])
	}
	return result + "…"
}

// repeatToWidth repeats a filler string to fill target display width.
// Truncates if last repeat exceeds the width.
func (e *Engine) repeatToWidth(filler string, targetWidth int) string {
	if targetWidth <= 0 || filler == "" {
		return ""
	}
	fillerWidth := runewidth.StringWidth(filler)
	if fillerWidth <= 0 {
		return filler
	}
	reps := (targetWidth + fillerWidth - 1) / fillerWidth // ceil division
	result := repeatStr(filler, reps)
	// Trim to exact width
	for runewidth.StringWidth(result) > targetWidth {
		runes := []rune(result)
		if len(runes) == 0 {
			break
		}
		result = string(runes[:len(runes)-1])
	}
	return result
}

// repeatStr repeats a string n times.
func repeatStr(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if n == 1 {
		return s
	}
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

func (e *Engine) replacement(label string, match []byte) []byte {
	switch e.style {
	case StyleMask:
		targetWidth := runewidth.StringWidth(string(match))
		filled := e.repeatToWidth(e.filler, targetWidth)
		return []byte(filled)
	case StyleHash:
		// Stub: just use label for now; real impl will use a short hash.
		placeholder := "[REDACTED:" + label + "]"
		if e.preserveWidth {
			targetWidth := runewidth.StringWidth(string(match))
			placeholder = e.fitToWidth(placeholder, targetWidth)
		}
		return []byte(placeholder)
	default: // placeholder
		placeholder := "[REDACTED:" + label + "]"
		if e.preserveWidth {
			targetWidth := runewidth.StringWidth(string(match))
			placeholder = e.fitToWidth(placeholder, targetWidth)
		}
		return []byte(placeholder)
	}
}
