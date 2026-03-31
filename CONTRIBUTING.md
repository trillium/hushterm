# Contributing to hushterm

## Development Setup

```bash
git clone https://github.com/trillium/hushterm.git
cd hushterm
go mod download
go build .
```

## Running Tests

```bash
go test ./...
go test -race ./...     # with race detector
go test -v ./...        # verbose
```

## Code Style

- `gofmt` is enforced (Go default)
- Run `golangci-lint run` before submitting PRs
- Keep functions short and focused
- No external test frameworks — use stdlib `testing`

## Making Changes

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/my-change`)
3. Write tests for new functionality
4. Ensure `go test ./...` passes
5. Commit with conventional commit messages:
   - `feat(scope): description` for new features
   - `fix(scope): description` for bug fixes
   - `docs: description` for documentation
6. Open a pull request

## Adding a Builtin Pattern

Edit `internal/redact/patterns.go` and add to the `builtinPatterns()` slice:

```go
{
    Name:    "my_pattern",
    Regex:   regexp.MustCompile(`your-regex-here`),
    Label:   "MY_LABEL",
    Enabled: true,
},
```

Include tests in `internal/redact/engine_test.go` with both matching and non-matching examples.

## Adding a Custom Pattern (No Code Change)

Users can add regex patterns via config without contributing code:

```yaml
# ~/.config/hushterm/config.yaml
custom:
  - name: my_pattern
    pattern: 'your-regex-here'
    label: MY_LABEL
```

## Submitting a Pattern Request

If you want a new builtin pattern but aren't sure about the regex, open a
[Pattern Request](https://github.com/trillium/hushterm/issues/new?template=pattern_request.yml)
issue with example strings that should and should not match.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
