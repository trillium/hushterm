# hushterm — PTY-based real-time redaction wrapper

## The Problem

AI coding assistants (Claude Code, Codex, Gemini CLI) routinely read and display sensitive data — private keys, API tokens, passwords, PII — in their terminal output. There is no tool that intercepts this output before it reaches the user's screen.

- 28.65M hardcoded secrets pushed to public GitHub in 2025 (up 34% YoY)
- AI-assisted commits leak credentials at 2x the baseline rate
- Copilot alone associated with 2,702 hard-coded keys found in AI-generated code
- LLMs leak ~3% of PII sequences even with differential privacy (arxiv 2302.00539)
- PII extraction rates increase 5x with sophisticated adversarial attacks (arxiv 2410.06704)

## The Gap

Nobody has built a PTY-based redaction wrapper. The closest things:

| Tool | Approach | Why insufficient |
|------|----------|-----------------|
| claw-wrap (Go) | Unix socket wrapper + regex redaction | Not PTY — breaks TUI apps |
| Warp terminal | Built-in secret masking | Proprietary, baked into terminal emulator |
| Zed editor | Redacts private values in terminal panel | Baked into editor, not extractable |
| RTK (Rust, 15.8k stars) | CLI proxy filtering output before LLM context | Token reduction, not security |
| Hoop.dev (Go) | Enterprise access gateway + AI PII masking | Network proxy, overkill for local CLI |
| @agntor/sdk (JS) | Regex-based redaction for AI agents | 236KB, 3 deps, broader escrow SDK, not terminal-level |
| OpenRedaction (JS) | 570+ regex patterns | 10MB, requires Node builtins (fs, worker_threads) |
| redact-pii-light (JS) | PII redaction | No secrets coverage, depends on lodash |
| LLM Guard (Python) | 15 input / 20 output scanners | Server-side Python, not embeddable |
| Microsoft Presidio (Python) | Gold standard PII detection | Server-side, NLP-heavy |

## The Solution

A Go binary that wraps any CLI command in a PTY, intercepts output, and redacts sensitive content in real-time before it reaches the terminal. Works with any TUI — not just AI agents.

```bash
hushterm -- claude            # AI coding assistants
hushterm -- ssh prod-server   # SSH sessions
hushterm -- docker logs -f    # Container logs
hushterm -- kubectl logs      # K8s logs
hushterm -- mysql             # Database CLIs
```

### Architecture

```
┌──────────┐     ┌─────────┐     ┌──────────┐
│ claude   │────▶│  PTY    │────▶│ hushterm │────▶ your terminal
│ (thinks  │     │ (fake   │     │ (pattern │     (clean output)
│  it's a  │     │  term)  │     │  match + │
│  real    │     │         │     │  buffer) │
│  term)   │     │         │     │          │
└──────────┘     └─────────┘     └──────────┘
```

### Why Go

- Single static binary, zero runtime deps, cross-platform
- RE2 regex engine — guaranteed linear time, no catastrophic backtracking on 500+ patterns
- `creack/pty` is the standard PTY library, mature and well-tested
- Config-driven architecture is idiomatic (YAML/TOML)
- Fast enough for real-time stream processing

### Usage Modes

```bash
# Wrap a command
hushterm -- claude

# Pipe mode (non-TUI only)
some-command 2>&1 | hushterm

# Server mode (for apps like Happy to call via HTTP)
hushterm serve --port 8080
```

### Config-driven pattern management

```yaml
# ~/.config/hushterm/config.yaml
builtin:
  secrets:
    aws_keys: true
    private_keys: true
    jwt_tokens: true
    api_keys: true
    bearer_tokens: true
    github_tokens: true
    gcp_keys: true
    azure_keys: true
  pii:
    emails: true
    phone_numbers: true
    ssn: true
    credit_cards: true
    ip_addresses: true
    street_addresses: true
    names: false          # too many false positives in code context

custom:
  - name: "internal_api"
    pattern: 'https://internal\.mycompany\.com/[^\s]+'
    replacement: "[REDACTED_URL]"

output:
  style: "mask"           # mask | placeholder | hash
  # mask:        "AKIAIOSFODNN7EXAMPLE" → "████████████████████"
  # placeholder: "AKIAIOSFODNN7EXAMPLE" → "[REDACTED:AWS_KEY]"
  # hash:        "AKIAIOSFODNN7EXAMPLE" → "[REDACTED:a1b2c3]"
```

### Blocklist Redaction (Literal String Matching)

In addition to regex patterns, hushterm supports **blocklist files** — YAML files containing known sensitive strings (client names, addresses, phone numbers) that are matched literally against terminal output using [Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) multi-pattern matching.

This is designed for cases where regex can't help — you **know** the sensitive values (e.g., exported from a database) and want exact-match redaction.

#### Usage

```bash
hushterm --blocklist-dir ~/.config/hushterm/blocklists -- claude
```

#### Directory Structure

The `--blocklist-dir` flag points to a directory. All `.yaml` / `.yml` files in that directory are loaded and merged into a single matcher. Each file typically represents a different data source:

```
~/.config/hushterm/blocklists/
├── massage_tracker.yaml        # exported from client DB
├── massage_booking_app.yaml    # exported from booking system
├── barter_system.yaml          # exported from barter network
└── personal.yaml               # manually maintained
```

Both the directory and individual files can be **symlinks** — hushterm resolves them and watches the real targets for changes.

```bash
# Symlink a blocklist from another project
ln -s ~/code/massage-tracker/redactions.yaml ~/.config/hushterm/blocklists/massage_tracker.yaml
```

#### File Format

```yaml
# Each file is independent and self-contained
version: 1
source: massage_tracker           # optional — identifies the data source in logs
case_sensitive: false             # default: false (case-insensitive matching)
entries:
  - value: "Jane Doe"            # exact string to match
    label: "CLIENT_NAME"         # appears in [REDACTED:CLIENT_NAME]
  - value: "13105551234"
    label: "CLIENT_PHONE"
  - value: "742 Evergreen Terrace"
    label: "CLIENT_ADDRESS"
  - value: "jane.doe"            # catch partial matches (e.g., in usernames)
    label: "CLIENT_ALIAS"
```

**Fields:**

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `version` | no | — | Schema version (currently `1`) |
| `source` | no | — | Human-readable source name, used in log messages |
| `case_sensitive` | no | `false` | When `false`, "Jane Doe" matches "jane doe", "JANE DOE", etc. |
| `entries[].value` | **yes** | — | The literal string to match. Must be non-empty. |
| `entries[].label` | **yes** | — | The redaction label. Appears as `[REDACTED:<label>]` in output. |

**Common labels by convention:**

| Label | Use for |
|-------|---------|
| `CLIENT_NAME` | Full names |
| `CLIENT_PHONE` | Phone numbers (any format) |
| `CLIENT_ADDRESS` | Street addresses |
| `CLIENT_EMAIL` | Email addresses (supplements regex pattern) |
| `CONTACT_NAME` | Non-client contacts |
| `BUSINESS_NAME` | Business names that shouldn't be visible |

Labels are freeform strings — use whatever makes sense for your data.

#### How It Works

1. At startup, all `.yaml`/`.yml` files in `--blocklist-dir` are read and parsed
2. All entries across all files are compiled into a single **Aho-Corasick automaton** — a state machine that matches all patterns in a single pass over the input
3. On every PTY output chunk, the blocklist runs **before** regex patterns
4. Matched strings are replaced with `[REDACTED:<label>]`
5. When overlapping entries match (e.g., "Jane" and "Jane Doe" both in the list), the **longest match wins**

#### Live Reload

The directory is watched with `fsnotify`. Changes take effect **without restarting hushterm**:

- **Edit a file** → entries are reloaded within ~100ms
- **Add a new file** → its entries are immediately available
- **Delete a file** → its entries are removed from the matcher
- **Modify a symlink target** → change is detected and reloaded

If a file contains invalid YAML on reload, hushterm logs a warning and **keeps the previous working blocklist** — it never drops protection due to a parse error.

#### Performance

The Aho-Corasick algorithm matches **all** blocklist entries in a single pass over each output chunk — O(chunk_size), independent of the number of entries. Adding 10,000 entries costs the same per-chunk time as adding 10.

| Entries | Per-chunk latency | Automaton rebuild |
|---------|-------------------|-------------------|
| 100 | ~0.01ms | <1ms |
| 1,000 | ~0.01ms | ~2ms |
| 10,000 | ~0.01ms | ~10ms |

Rebuilds happen off the hot path in the watcher goroutine. The PTY loop swaps in the new matcher atomically with zero lock contention.

#### Generating Blocklist Files

Export scripts should produce the YAML format above. Example patterns:

```bash
# From a PostgreSQL database
psql -c "SELECT json_build_object('value', name, 'label', 'CLIENT_NAME') FROM clients" \
  | jq -s '{version: 1, source: "client_db", case_sensitive: false, entries: .}' \
  | yq -P > ~/.config/hushterm/blocklists/clients.yaml

# From a CSV
awk -F',' '{print "  - value: \""$1"\"\n    label: \"CLIENT_NAME\""}' clients.csv \
  | cat <(echo -e "version: 1\nsource: csv_export\ncase_sensitive: false\nentries:") - \
  > ~/.config/hushterm/blocklists/clients.yaml
```

#### Limitations

- **Unknown values are not caught** — only entries explicitly listed in blocklist files are matched. New clients/contacts must be added to the blocklist (or caught by regex patterns for structured formats like emails/phones).
- **Cross-chunk boundary splits** — a name split across two 4096-byte PTY read boundaries may not be matched. This is rare in practice and will be addressed with an overlap buffer in a future release.
- **ANSI escape sequences** — if an escape code is inserted mid-word (e.g., `Ja\033[0mne`), the literal match will miss. This is uncommon in normal terminal output.

### Key Technical Challenges

1. **Cross-chunk matching** — ANSI escape sequences and streaming can split secrets across PTY read chunks. Need a sliding buffer (few hundred bytes) to ensure pattern matching works across boundaries.

2. **ANSI-aware matching** — Terminal output contains escape codes for colors, cursor positioning, etc. Patterns need to match the underlying text, not the escape sequences. Strip ANSI → match → reinsert ANSI.

3. **Performance** — Must add negligible latency to terminal output. RE2 helps. Pre-compiled pattern sets help. Most patterns are simple prefix/format matches.

4. **False positives in code** — Variable names, test fixtures, and example strings can trigger patterns. Context-aware rules (e.g., only flag strings that appear in output, not in code blocks) may help but add complexity.

### Coverage Requirements

Must detect BOTH secrets AND PII:

**Secrets:**
- AWS access keys (AKIA...)
- Private keys (-----BEGIN ... PRIVATE KEY-----)
- JWT tokens (eyJ...)
- API keys with known prefixes (sk-live_, pk_live_, ghp_, gho_, etc.)
- Bearer tokens
- OAuth tokens
- Database connection strings with passwords
- GitHub/GitLab/Bitbucket tokens
- GCP/Azure credentials
- Generic high-entropy strings (entropy analysis)

**PII:**
- Email addresses
- Phone numbers (international formats)
- Social Security Numbers
- Credit card numbers (with Luhn validation)
- IP addresses
- Street addresses
- Passport/driver's license numbers
- International government IDs (stretch goal)

### Pattern Sources

Battle-tested regex databases to draw from:

- **gitleaks** (Go, open source) — extensive secret patterns, TOML config format
- **trufflehog** (Go, open source) — massive pattern database with verification
- **OpenRedaction** — 570+ patterns including international PII
- **redact-pii** — well-tested PII patterns
- **@agntor/sdk** — 17 secret/PII patterns

### Building Blocks

| Component | Library | Maturity |
|-----------|---------|----------|
| PTY allocation | `creack/pty` | Standard, mature |
| PTY convenience | `fearlessdots/ptywrapper` | Thin wrapper, ANSI stripping |
| Config parsing | `spf13/viper` or `koanf` | Mature |
| YAML | `gopkg.in/yaml.v3` | Standard |
| Regex | Go stdlib `regexp` (RE2) | Built-in |
| ANSI parsing | `acarl005/stripansi` or manual | Simple |

### Distribution

- Homebrew tap
- GitHub releases (goreleaser)
- AUR package
- Single binary download

### Relationship to Happy

This is a standalone open source project, NOT coupled to Happy. However, Happy could use it in two ways:
1. **Server mode** — Happy's backend calls `hushterm serve` to filter agent output before sending to the mobile app
2. **Embedded patterns** — Happy extracts the pattern database and runs matching in its own reducer pipeline (JS/TS port of just the patterns)

## Prior Art & References

- [claw-wrap](https://github.com/dedene/claw-wrap) — Unix socket credential proxy (Go, 122 stars)
- [CleanSH](https://github.com/KarmaYama/cleansh-workspace) — Entropy-based terminal HUD (Rust)
- [RTK](https://github.com/rtk-ai/rtk) — CLI output proxy for LLM context (Rust, 15.8k stars)
- [AgentGateway](https://github.com/agentgateway/agentgateway) — Agentic proxy (Rust)
- [creack/pty](https://github.com/creack/pty) — Go PTY library
- [creack/pty #82](https://github.com/creack/pty/issues/82) — I/O separation challenges
- [fearlessdots/ptywrapper](https://github.com/fearlessdots/ptywrapper) — PTY convenience wrapper
- [dtolnay/faketty](https://github.com/dtolnay/faketty) — Rust PTY wrapper
- [gitleaks](https://github.com/gitleaks/gitleaks) — Secret scanner with streaming request (#1759)
- [trufflehog](https://github.com/trufflesecurity/trufflehog) — Secret scanner
- [Warp secret redaction](https://docs.warp.dev/privacy/secret-redaction) — Terminal-embedded redaction
- [Zed #51893](https://github.com/zed-industries/zed/issues/51893) — Terminal redaction feature
- [LLM Guard](https://github.com/protectai/llm-guard) — Python guardrail framework
- [Microsoft Presidio](https://github.com/microsoft/presidio) — PII detection/anonymization
- [NeMo Guardrails](https://developer.nvidia.com/nemo-guardrails) — Enterprise guardrails
- [Analyzing PII Leakage in LLMs](https://arxiv.org/abs/2302.00539) — Foundation paper
- [PII-Scope](https://arxiv.org/abs/2410.06704) — Adversarial PII extraction
- [Deploying Privacy Guardrails](https://arxiv.org/html/2501.12456v1) — Comparative analysis
