package redact

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level hushterm configuration file.
type Config struct {
	Patterns map[string]bool `yaml:"patterns"` // pattern name → enabled/disabled
	Style    string          `yaml:"style"`    // mask, placeholder, hash
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
}
