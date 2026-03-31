package redact

import "regexp"

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
	style     Style
	patterns  []Pattern
	blocklist BlocklistHolder
}

// NewEngine creates a redaction engine with builtin patterns.
func NewEngine(style Style) (*Engine, error) {
	if style == "" {
		style = StylePlaceholder
	}
	e := &Engine{style: style}
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
		result = bl.ReplaceAll(result, e.style)
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

func (e *Engine) replacement(label string, match []byte) []byte {
	switch e.style {
	case StyleMask:
		masked := make([]byte, len(match))
		for i := range masked {
			masked[i] = '*'
		}
		return masked
	case StyleHash:
		// Stub: just use label for now; real impl will use a short hash.
		return []byte("[REDACTED:" + label + "]")
	default: // placeholder
		return []byte("[REDACTED:" + label + "]")
	}
}
