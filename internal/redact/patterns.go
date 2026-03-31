package redact

import "regexp"

// builtinPatterns returns the default set of secret and PII detection patterns.
// This is a starter set — the full library will be built out in ht-q6x.7.
func builtinPatterns() []Pattern {
	return []Pattern{
		// Secrets
		{
			Name:    "aws_access_key",
			Regex:   regexp.MustCompile(`(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)`),
			Label:   "AWS_KEY",
			Enabled: true,
		},
		{
			Name:    "private_key",
			Regex:   regexp.MustCompile(`-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----`),
			Label:   "PRIVATE_KEY",
			Enabled: true,
		},
		{
			Name:    "jwt_token",
			Regex:   regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
			Label:   "JWT",
			Enabled: true,
		},
		{
			Name:    "github_token",
			Regex:   regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`),
			Label:   "GITHUB_TOKEN",
			Enabled: true,
		},
		{
			Name:    "generic_api_key",
			Regex:   regexp.MustCompile(`(?:sk|pk)[-_](?:live|test)[-_][A-Za-z0-9]{20,}`),
			Label:   "API_KEY",
			Enabled: true,
		},
		{
			Name:    "bearer_token",
			Regex:   regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-.~+/]{20,}`),
			Label:   "BEARER_TOKEN",
			Enabled: true,
		},

		// PII
		{
			Name:    "email",
			Regex:   regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			Label:   "EMAIL",
			Enabled: true,
		},
		{
			Name:    "ssn",
			Regex:   regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			Label:   "SSN",
			Enabled: true,
		},
		{
			Name:    "credit_card",
			Regex:   regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
			Label:   "CREDIT_CARD",
			Enabled: false, // Too many false positives without Luhn — disabled until ht-q6x.7.
		},
		{
			Name:    "phone_international",
			Regex:   regexp.MustCompile(`\+[1-9][0-9]{6,14}`),
			Label:   "PHONE",
			Enabled: true,
		},
		{
			Name:    "phone_us",
			Regex:   regexp.MustCompile(`\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`),
			Label:   "PHONE",
			Enabled: true,
		},
		{
			Name:    "ipv4",
			Regex:   regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`),
			Label:   "IP_ADDRESS",
			Enabled: true,
		},
	}
}
