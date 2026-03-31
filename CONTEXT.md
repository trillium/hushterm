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
