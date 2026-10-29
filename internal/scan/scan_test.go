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

func TestMatchFlagsWidenedShapes(t *testing.T) {
	// Built programmatically, never as realistic literals: the repo
	// must contain no secret-shaped material, including in its tests.
	awsKey := strings.Repeat("A", 20) + strings.Repeat("B", 20)
	jwt := "eyJ" + strings.Repeat("h", 10) + "." + strings.Repeat("p", 10) + "." + strings.Repeat("s", 10)
	// Fragment-joined so no assignment literal appears in source.
	assign := strings.Join([]string{"api", "_key", ": "}, "") + strings.Repeat("k", 16)
	for _, s := range []string{awsKey, jwt, assign} {
		if Match(s) == "" {
			t.Errorf("detector missed secret-shaped input %q...", s[:12])
		}
	}
}

func TestBareHexIsStrictOnly(t *testing.T) {
	// A bare 64-hex string is indistinguishable from a SHA-256 hash,
	// and audit details legitimately carry hashes (checkpoint events).
	// Plain Match must NOT flag it, or checkpointing breaks; the strict
	// scan (free text, references, hook output) must.
	hex64 := strings.Repeat("a", 64)
	if Match(hex64) != "" {
		t.Error("plain Match flagged a bare 64-hex string; checkpoint hashes would break")
	}
	if MatchStrict(hex64) == "" {
		t.Error("strict scan missed a bare 64-hex token")
	}
}

func TestIsReferenceRejectsBareTokens(t *testing.T) {
	if IsReference(strings.Repeat("a", 64)) {
		t.Error("bare 64-hex token accepted as reference")
	}
	if IsReference(strings.Repeat("A", 40)) {
		t.Error("bare 40-char base64 token accepted as reference")
	}
	if !IsReference("vault:prod/key") {
		t.Error("namespaced reference rejected")
	}
	if !IsReference("aws:iam/key/EXAMPLE1") {
		t.Error("key-ID-style reference rejected")
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
