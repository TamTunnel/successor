// Package scan detects secret-shaped material in strings that must never
// contain it (audit details, handover reasons, adapter output, new
// references). It reports only the pattern name that matched, never the
// matched text itself — error messages must not echo secret material.
//
// The patterns below are detection logic, not secret values. They cover
// well-known secret shapes only. Key IDs and vault paths are references
// and are deliberately NOT flagged (for example, an AWS access key ID is
// an identifier, not the secret); the distinction between a reference
// and secret material is load-bearing for this product.
package scan

import (
	"regexp"
	"strings"
)

type pattern struct {
	name string
	re   *regexp.Regexp
}

var patterns = []pattern{
	{"pem-private-key", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)},
	{"openai-secret-key", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)},
	{"stripe-live-secret", regexp.MustCompile(`sk_live_[A-Za-z0-9]{10,}`)},
	{"github-token", regexp.MustCompile(`(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]+`)},
	{"slack-token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]+`)},
	{"bearer-token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+-]{20,}`)},
	{"google-api-key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{"password-assignment", regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*\S+`)},
}

// forbiddenDetailKeys are audit-detail field names that must never appear.
// They would indicate a caller trying to smuggle credential material (or a
// hash of a credential value) into the trail under a plausible name.
var forbiddenDetailKeys = []string{
	"secret", "password", "passwd", "private_key", "credential_value",
}

// Match returns the name of the first secret-shaped pattern found in s,
// or "" when s is clean.
func Match(s string) string {
	for _, p := range patterns {
		if p.re.MatchString(s) {
			return p.name
		}
	}
	return ""
}

// ForbiddenKey returns true when an audit-detail field name is on the
// forbidden list (case-insensitive substring match).
func ForbiddenKey(key string) bool {
	lower := strings.ToLower(key)
	for _, f := range forbiddenDetailKeys {
		if strings.Contains(lower, f) {
			return true
		}
	}
	return false
}

// IsReference reports whether s looks like a credential reference rather
// than secret material: non-empty, single line, no whitespace, and not
// secret-shaped. References are vault paths, key IDs, and grant IDs.
func IsReference(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	return Match(s) == ""
}
