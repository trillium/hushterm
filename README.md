# hushterm

**PTY-based real-time terminal output redaction.**

<!-- badges -->
![CI](https://img.shields.io/github/actions/workflow/status/trilliumsmith/hushterm/ci.yaml?branch=main)
![Go](https://img.shields.io/badge/go-1.25-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## The Problem

AI coding assistants (Claude Code, Codex, Gemini CLI) routinely read and display secrets, API tokens, private keys, and PII in terminal output. 28.65M hardcoded secrets were pushed to public GitHub in 2025 alone, up 34% year-over-year, and AI-assisted commits leak credentials at 2x the baseline rate. No existing tool intercepts terminal output at the PTY level before it reaches your screen. hushterm fills that gap: a single binary that sits between any CLI program and your terminal, redacting sensitive content in real time.

## Quick Start

```bash
go install github.com/trilliumsmith/hushterm@latest

# Wrap any command
hushterm -- claude
```

That's it. All 10 default patterns (AWS keys, JWTs, emails, SSNs, etc.) are active immediately.

## Usage

### PTY mode (default) -- full TUI support

```bash
hushterm -- claude                # AI coding assistants
hushterm -- ssh prod-server       # SSH sessions
hushterm -- docker logs -f        # Container logs
hushterm -- kubectl logs pod/x    # Kubernetes
hushterm -- mysql -u root         # Database CLIs
```

hushterm allocates a PTY, so the wrapped program sees a real terminal. Colors, cursor movement, and interactive UIs work normally.

### Pipe mode -- non-interactive

When stdin is not a TTY, hushterm falls back to pipe mode, filtering stdout and stderr:

```bash
some-command 2>&1 | hushterm
cat secrets.log | hushterm
```

### Options

```
--config         Path to config.yaml (default: ~/.config/hushterm/config.yaml)
--style          Redaction style: mask | placeholder | hash (default: placeholder)
--blocklist-dir  Directory of blocklist YAML files for literal string matching
```

### Redaction styles

| Style | Input | Output |
|-------|-------|--------|
| `placeholder` | `AKIAIOSFODNN7EXAMPLE` | `[REDACTED:AWS_KEY]` |
| `mask` | `AKIAIOSFODNN7EXAMPLE` | `********************` |
| `hash` | `AKIAIOSFODNN7EXAMPLE` | `[REDACTED:AWS_KEY]` |

## Builtin Patterns

12 patterns ship with hushterm. 10 are enabled by default.

| Name | Detects | Default |
|------|---------|---------|
| `aws_access_key` | AWS access keys (`AKIA...`) | enabled |
| `private_key` | RSA/DSA/EC/OpenSSH/PGP private key headers | enabled |
| `jwt_token` | JSON Web Tokens (`eyJ...`) | enabled |
| `github_token` | GitHub PATs and app tokens (`ghp_`, `gho_`, etc.) | enabled |
| `generic_api_key` | Stripe-style keys (`sk-live_`, `pk_test_`, etc.) | enabled |
| `bearer_token` | Bearer authentication tokens | enabled |
| `email` | Email addresses | enabled |
| `ssn` | US Social Security Numbers (XXX-XX-XXXX) | enabled |
| `credit_card` | Credit card numbers (13-19 digits) | **disabled** |
| `phone_international` | International phone numbers (+country code) | enabled |
| `phone_us` | US phone numbers (various formats) | enabled |
| `ipv4` | IPv4 addresses | enabled |

`credit_card` is disabled by default due to false positives without Luhn validation.

## Blocklist (Literal String Matching)

For known sensitive values that regex cannot catch -- client names, addresses, specific identifiers -- hushterm supports blocklist files. These use [Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) multi-pattern matching for exact string redaction.

```bash
hushterm --blocklist-dir ~/.config/hushterm/blocklists -- claude
```

### Directory structure

```
~/.config/hushterm/blocklists/
├── client_db.yaml          # exported from database
├── booking_system.yaml     # exported from app
└── personal.yaml           # manually maintained
```

Both the directory and individual files can be **symlinks**. hushterm resolves them and watches the real targets.

### File format

```yaml
version: 1
source: client_db
case_sensitive: false          # default: false
entries:
  - value: "Jane Doe"
    label: "CLIENT_NAME"       # appears as [REDACTED:CLIENT_NAME]
  - value: "13105551234"
    label: "CLIENT_PHONE"
  - value: "742 Evergreen Terrace"
    label: "CLIENT_ADDRESS"
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `version` | no | -- | Schema version (currently `1`) |
| `source` | no | -- | Human-readable source name for log messages |
| `case_sensitive` | no | `false` | Case-insensitive matching when false |
| `entries[].value` | **yes** | -- | Literal string to match (non-empty) |
| `entries[].label` | **yes** | -- | Redaction label shown in output |

### Live reload

The blocklist directory is watched with `fsnotify`. Changes take effect without restarting hushterm:

- Edit a file -- entries reload within ~100ms
- Add a new file -- entries immediately available
- Delete a file -- entries removed from the matcher
- Modify a symlink target -- change detected and reloaded

If a file contains invalid YAML on reload, hushterm logs a warning and **keeps the previous working blocklist**.

## Configuration

Create `~/.config/hushterm/config.yaml`:

```yaml
# Toggle builtin patterns by name
patterns:
  credit_card: true        # enable a disabled-by-default pattern
  ipv4: false              # disable a pattern

# Add custom regex patterns
custom:
  - name: "internal_api"
    pattern: 'https://internal\.mycompany\.com/[^\s]+'
    label: "INTERNAL_URL"

# Redaction style: mask, placeholder, or hash
style: "placeholder"
```

```bash
hushterm --config ~/.config/hushterm/config.yaml -- claude
```

Only patterns named in the config are changed; all others keep their defaults.

## Architecture

```
┌──────────┐     ┌─────────┐     ┌──────────────┐
│ wrapped  │────>│  PTY    │────>│  hushterm    │────> terminal
│ command  │     │ (fake   │     │              │     (clean output)
│ (thinks  │     │  term)  │     │ 1. blocklist │
│  it's a  │     │         │     │ 2. regex     │
│  real    │     │         │     │ 3. style fmt │
│  term)   │     │         │     │              │
└──────────┘     └─────────┘     └──────────────┘
     ^                                  │
     └──────── stdin (passthrough) ─────┘
```

1. hushterm allocates a PTY via `creack/pty`
2. The wrapped command's stdout flows through hushterm
3. Each output chunk is run through the blocklist (Aho-Corasick), then regex patterns
4. Redacted output is written to the real terminal
5. User input is passed through to the PTY unmodified

## Performance

**Regex patterns**: O(N * chunk_size) where N is the number of enabled patterns. Go's RE2 engine guarantees linear-time matching with no catastrophic backtracking.

**Blocklist (Aho-Corasick)**: O(chunk_size), independent of entry count. 10 entries or 10,000 entries cost the same per-chunk time.

| Blocklist entries | Per-chunk latency | Automaton rebuild |
|-------------------|-------------------|-------------------|
| 100 | ~0.01ms | <1ms |
| 1,000 | ~0.01ms | ~2ms |
| 10,000 | ~0.01ms | ~10ms |

Rebuilds happen in a background goroutine. The PTY loop swaps in the new matcher atomically with zero lock contention.

## Comparison

| Tool | Approach | Limitation |
|------|----------|------------|
| **hushterm** | PTY wrapper, regex + Aho-Corasick | New project, pattern set growing |
| Warp | Built-in secret masking | Proprietary terminal, not portable |
| Zed | Terminal panel redaction | Editor-only, not extractable |
| RTK | CLI proxy for LLM context | Token reduction, not security |
| LLM Guard | Python input/output scanners | Server-side, not embeddable in CLI |
| Microsoft Presidio | NLP-based PII detection | Server-side, heavy runtime |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
