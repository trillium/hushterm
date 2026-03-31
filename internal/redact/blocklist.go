package redact

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
	"gopkg.in/yaml.v3"
)

// BlocklistEntry is a single literal string to redact.
type BlocklistEntry struct {
	Value string `yaml:"value"`
	Label string `yaml:"label"`
}

// BlocklistFile represents one YAML blocklist file.
type BlocklistFile struct {
	Version       int              `yaml:"version"`
	Source        string           `yaml:"source"`
	CaseSensitive bool            `yaml:"case_sensitive"`
	Entries       []BlocklistEntry `yaml:"entries"`
}

// Blocklist holds the compiled Aho-Corasick automaton and entry metadata.
type Blocklist struct {
	matcher ahocorasick.AhoCorasick
	entries []BlocklistEntry // parallel to patterns given to builder
	caseFold bool
}

// NewBlocklist compiles a set of entries into an Aho-Corasick automaton.
func NewBlocklist(entries []BlocklistEntry, caseSensitive bool) *Blocklist {
	if len(entries) == 0 {
		return nil
	}

	patterns := make([]string, len(entries))
	for i, e := range entries {
		if caseSensitive {
			patterns[i] = e.Value
		} else {
			patterns[i] = strings.ToLower(e.Value)
		}
	}

	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: !caseSensitive,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  true,
	})
	matcher := builder.Build(patterns)

	return &Blocklist{
		matcher:  matcher,
		entries:  entries,
		caseFold: !caseSensitive,
	}
}

// match represents a single match position.
type match struct {
	start int
	end   int
	label string
}

// ReplaceAll finds all blocklist matches and replaces them with redaction placeholders.
func (bl *Blocklist) ReplaceAll(data []byte, style Style) []byte {
	if bl == nil {
		return data
	}

	var searchData []byte
	if bl.caseFold {
		searchData = bytes.ToLower(data)
	} else {
		searchData = data
	}

	iter := bl.matcher.Iter(string(searchData))
	var matches []match
	for next := iter.Next(); next != nil; next = iter.Next() {
		m := *next
		matches = append(matches, match{
			start: m.Start(),
			end:   m.End(),
			label: bl.entries[m.Pattern()].Label,
		})
	}

	if len(matches) == 0 {
		return data
	}

	// Sort by start position, longest first for overlaps.
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].start == matches[j].start {
			return matches[i].end > matches[j].end
		}
		return matches[i].start < matches[j].start
	})

	// Remove overlapping matches, keeping the first (longest at each position).
	filtered := matches[:0]
	lastEnd := 0
	for _, m := range matches {
		if m.start >= lastEnd {
			filtered = append(filtered, m)
			lastEnd = m.end
		}
	}

	// Build result by replacing matches.
	var buf bytes.Buffer
	buf.Grow(len(data))
	prev := 0
	for _, m := range filtered {
		buf.Write(data[prev:m.start])
		buf.WriteString("[REDACTED:")
		buf.WriteString(m.label)
		buf.WriteByte(']')
		prev = m.end
	}
	buf.Write(data[prev:])

	return buf.Bytes()
}

// LoadBlocklistDir reads all .yaml/.yml files from a directory (following symlinks)
// and returns a merged Blocklist.
func LoadBlocklistDir(dir string) (*Blocklist, error) {
	// Resolve symlinks on the directory itself.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve blocklist dir: %w", err)
	}

	dirEntries, err := os.ReadDir(resolved)
	if err != nil {
		return nil, fmt.Errorf("read blocklist dir: %w", err)
	}

	var allEntries []BlocklistEntry
	caseSensitive := false // default: case-insensitive

	for _, de := range dirEntries {
		name := de.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		// Use os.Stat (not Lstat) to follow symlinks on individual files.
		filePath := filepath.Join(resolved, name)
		info, err := os.Stat(filePath)
		if err != nil || info.IsDir() {
			continue
		}

		// If the entry is a symlink, resolve to the real path for reading.
		realPath, err := filepath.EvalSymlinks(filePath)
		if err != nil {
			continue
		}

		entries, fileCaseSensitive, err := loadBlocklistFile(realPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hushterm: blocklist: skip %s: %v\n", name, err)
			continue
		}
		if fileCaseSensitive {
			caseSensitive = true
		}
		allEntries = append(allEntries, entries...)
	}

	if len(allEntries) == 0 {
		return nil, nil
	}

	return NewBlocklist(allEntries, caseSensitive), nil
}

func loadBlocklistFile(path string) ([]BlocklistEntry, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}

	var bf BlocklistFile
	if err := yaml.Unmarshal(data, &bf); err != nil {
		return nil, false, fmt.Errorf("parse yaml: %w", err)
	}

	// Filter out entries with empty values.
	var entries []BlocklistEntry
	for _, e := range bf.Entries {
		if e.Value != "" && e.Label != "" {
			entries = append(entries, e)
		}
	}

	return entries, bf.CaseSensitive, nil
}

// BlocklistHolder provides atomic access to a Blocklist for concurrent use.
type BlocklistHolder struct {
	ptr atomic.Pointer[Blocklist]
}

// Load returns the current Blocklist (may be nil).
func (h *BlocklistHolder) Load() *Blocklist {
	return h.ptr.Load()
}

// Store atomically swaps the Blocklist.
func (h *BlocklistHolder) Store(bl *Blocklist) {
	h.ptr.Store(bl)
}
