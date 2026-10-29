package scan

import (
	"strings"
	"testing"
)

// Secret-shaped test inputs are constructed programmatically (prefix +
// repeated characters), never written as realistic literals: the repo
// must contain no secret-shaped material, including in its tests.
func fakeKey(prefix string, n int) string { return prefix + strings.Repeat("k", n) }

func TestMatchFlagsSecretShapes(t *testing.T) {
	shapes := []string{
		fakeKey("sk-", 48),
		fakeKey("sk_live_", 24),
		fakeKey("ghp_", 36),
		fakeKey("xoxb-", 20),
		"Bearer " + strings.Repeat("t", 32),
		"-----BEGIN " + "PRIVATE KEY-----\n" + strings.Repeat("QUJD", 16) + "\n-----END " + "PRIVATE KEY-----",
		// Built from fragments: a literal password assignment on this
		// line would itself trip the zero-secret source scan.
		strings.Join([]string{"pass", "word="}, "") + strings.Repeat("p", 12),
	}
	for _, s := range shapes {
		if Match(s) == "" {
			t.Errorf("detector missed secret-shaped input starting %q", s[:12])
		}
	}
}

func TestMatchPassesReferences(t *testing.T) {
	refs := []string{
		"vault:prod/deploy-bot/key",
		"aws:iam/key/EXAMPLE1",
		"acme/api-key",
		"cron:nightly-deploy",
		"key-id-1234",
		"",
	}
	for _, r := range refs {
		if r == "" {
			continue
		}
		if Match(r) != "" {
			t.Errorf("detector flagged reference %q as secret-shaped", r)
		}
	}
}

func TestIsReference(t *testing.T) {
	if !IsReference("vault:prod/key") {
		t.Error("plain reference rejected")
	}
	if IsReference("has space") || IsReference("two\nlines") || IsReference("") {
		t.Error("non-reference accepted")
	}
	if IsReference(fakeKey("sk-", 48)) {
		t.Error("secret-shaped value accepted as reference")
	}
}

func TestForbiddenKey(t *testing.T) {
	for _, k := range []string{"secret", "password", "private_key", "credential_value", "passwd"} {
		if !ForbiddenKey(k) {
			t.Errorf("forbidden key %q not flagged", k)
		}
	}
	if ForbiddenKey("ref") || ForbiddenKey("key_id") || ForbiddenKey("previous_ref") {
		t.Error("legitimate reference field flagged")
	}
}
