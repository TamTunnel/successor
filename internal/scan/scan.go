// Package scan detects secret-shaped material in strings that must never
// contain it (audit details, handover reasons, adapter output, new
// references). It reports only the pattern name that matched, never the
// matched text itself — error messages must not echo secret material.
//
// The patterns below are detection logic, not secret values. They cover
// well-known secret shapes (private-key blocks, vendor API key formats,
// bearer tokens, password and key assignments, AWS secret keys, JWTs).
// Key IDs and vault paths are references and are deliberately NOT
// flagged (for example, an AWS access key ID is an identifier, not the
// secret); the distinction between a reference and secret material is
// load-bearing for this product. One shape is deliberately excluded
// from Match: a bare 64-hex string is indistinguishable from a SHA-256
// hash, and audit details legitimately carry hashes, so it is refused
// only where hashes never belong (MatchStrict, IsReference).
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
	// A bare 40-character base64 token is the shape of an AWS secret
	// access key. The boundary guards keep it from firing inside longer
	// runs (a 64-hex hash, a vault path segment): the token must stand
	// alone. Vault paths contain separators that break the run, and a
	// namespaced reference is not a bare token.
	{"aws-secret-key", regexp.MustCompile(`(?:^|[^A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?:[^A-Za-z0-9/+=]|$)`)},
	// JWTs are unmistakable: three base64url segments, the first
	// decoding to a JSON header (hence the eyJ prefix).
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)},
	// Generic key assignments in prose, where a key word is followed
	// by a separator and a value. Bare "token" is deliberately NOT in
	// this list:
	// Go code legitimately writes "token :=" and the zero-secret source
	// scan runs over the repo itself, so a bare-token rule would flag
	// the tool's own source.
	{"generic-key-assignment", regexp.MustCompile(`(?i)(api[_-]?key|secret|access[_-]?key|auth[_-]?token)\s*[:=]\s*\S+`)},
}

// bareHex64 matches a standalone 64-hex string. It is deliberately NOT
// in patterns: a bare 64-hex string is indistinguishable from a SHA-256
// hash, and audit details legitimately carry hashes (the checkpoint
// event records the chain hash). Flagging it in Match would break
// checkpointing. It is refused where hashes never legitimately appear:
// free-text user input (MatchStrict) and credential references
// (IsReference), where a reference must be a namespaced path or ID,
// not a bare hash-shaped token.
var bareHex64 = regexp.MustCompile(`(?:^|[^A-Fa-f0-9])[A-Fa-f0-9]{64}(?:[^A-Fa-f0-9]|$)`)

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

// MatchStrict is Match plus the bare-64-hex rule, for inputs where a
// hash-shaped value can never be legitimate: free-text fields and
// hook output. Audit details keep using Match, because checkpoint
// events legitimately carry a chain hash.
func MatchStrict(s string) string {
	if name := Match(s); name != "" {
		return name
	}
	if bareHex64.MatchString(s) {
		return "bare-hex-token"
	}
	return ""
}

// forbiddenDetailKeys are audit-detail field names that must never appear.
// They would indicate a caller trying to smuggle credential material (or a
// hash of a credential value) into the trail under a plausible name.
var forbiddenDetailKeys = []string{
	"secret", "password", "passwd", "private_key", "credential_value",
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
// secret-shaped. References are vault paths, key IDs, and grant IDs. A
// bare hash-shaped token is not a reference: it carries no namespace
// and is indistinguishable from raw key material.
func IsReference(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	return MatchStrict(s) == ""
}
