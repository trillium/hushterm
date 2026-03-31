# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-31

### Added
- PTY-based command wrapping with real-time redaction
- Pipe mode for non-interactive commands
- 12 builtin regex patterns: AWS keys, private keys, JWT, GitHub tokens,
  generic API keys, bearer tokens, email, SSN, US phone, international phone,
  IPv4, credit card (disabled by default)
- Blocklist directory for literal string matching using Aho-Corasick
- Live reload of blocklist files via fsnotify
- Symlink support for blocklist directory and individual files
- Config file for toggling builtin patterns on/off
- Custom regex patterns via config YAML
- Three redaction styles: mask, placeholder, hash
- Width-preserving redaction (`preserve_width` config option)
- Customizable filler characters for mask style
- `--config`, `--blocklist-dir`, and `--style` CLI flags
- Build-time version injection via ldflags
