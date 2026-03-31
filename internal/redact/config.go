package redact

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// CustomPattern is a user-defined regex pattern in config.
type CustomPattern struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
	Label   string `yaml:"label"`
	Enabled *bool  `yaml:"enabled"` // nil = true (default on)
}

// Config is the top-level hushterm configuration file.
type Config struct {
	Patterns map[string]bool `yaml:"patterns"` // pattern name → enabled/disabled
	Custom   []CustomPattern `yaml:"custom"`
	Style    string          `yaml:"style"` // mask, placeholder, hash
}

// LoadConfig reads a hushterm config YAML file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &cfg, nil
}

// ApplyConfig overrides pattern enabled/disabled state based on config.
// Only patterns named in the config are changed; others keep their defaults.
func (e *Engine) ApplyConfig(cfg *Config) {
	if cfg == nil {
		return
	}
	if cfg.Style != "" {
		e.style = Style(cfg.Style)
	}
	for i := range e.patterns {
		if enabled, ok := cfg.Patterns[e.patterns[i].Name]; ok {
			e.patterns[i].Enabled = enabled
		}
	}

	// Compile and append custom patterns.
	for _, cp := range cfg.Custom {
		if cp.Name == "" || cp.Pattern == "" || cp.Label == "" {
			continue
		}
		re, err := regexp.Compile(cp.Pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hushterm: custom pattern %q: %v\n", cp.Name, err)
			continue
		}
		enabled := true
		if cp.Enabled != nil {
			enabled = *cp.Enabled
		}
		e.patterns = append(e.patterns, Pattern{
			Name:    cp.Name,
			Regex:   re,
			Label:   cp.Label,
			Enabled: enabled,
		})
	}
}
