package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func generateTestKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func TestChainVerifyAndTamper(t *testing.T) {
	dir := t.TempDir()
	log := &Log{Path: filepath.Join(dir, "audit.jsonl")}
	for i, action := range []string{"a.one", "a.two", "a.three"} {
		if _, err := log.Append(Event{Ts: "2026-01-01T00:00:00Z", ActorID: "E-1009", Action: action}); err != nil {
			t.Fatal(err)
		}
		_ = i
	}
	if _, err := log.Verify(); err != nil {
		t.Fatalf("clean chain failed verification: %v", err)
	}
	// Line-level tamper: alter the middle event's action, keep the rest.
	data, err := os.ReadFile(log.Path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	lines[1] = strings.Replace(lines[1], "a.two", "a.TAMPERED", 1)
	if err := os.WriteFile(log.Path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Verify(); err == nil {
		t.Fatal("tampered chain verified clean")
	} else if !strings.Contains(err.Error(), "seq 2") {
		t.Fatalf("tamper not attributed to seq 2: %v", err)
	}
}

func TestValidateDetailRefusesSecrets(t *testing.T) {
	// Constructed shape, never a literal.
	shape := "sk-" + strings.Repeat("k", 48)
	if err := ValidateDetail(map[string]any{"reason": shape}); err == nil {
		t.Error("secret-shaped detail accepted")
	}
	if err := ValidateDetail(map[string]any{"password": "not-a-secret"}); err == nil {
		t.Error("forbidden field name accepted")
	}
	if err := ValidateDetail(map[string]any{"ref": "vault:prod/key", "count": 2}); err != nil {
		t.Errorf("clean detail refused: %v", err)
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	dir := t.TempDir()
	log := &Log{Path: filepath.Join(dir, "audit.jsonl")}
	for _, action := range []string{"a.one", "a.two"} {
		if _, err := log.Append(Event{Ts: "2026-01-01T00:00:00Z", ActorID: "E-1009", Action: action}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := log.Verify()
	if err != nil {
		t.Fatal(err)
	}
	latest := events[len(events)-1]
	pub, privKey, err := generateTestKey()
	if err != nil {
		t.Fatal(err)
	}
	cp := SignCheckpoint(privKey, KeyID(pub), latest.Seq, latest.Hash, 1)
	if err := VerifyCheckpoint(cp, pub, events, 1); err != nil {
		t.Fatalf("checkpoint failed: %v", err)
	}
	// Full rewrite with a recomputed chain: chain verifies, but the
	// checkpoint no longer pins the log.
	rewritten := make([]Event, len(events))
	copy(rewritten, events)
	rewritten[0].Action = "a.FORGED"
	rewritten[0].PrevHash = ZeroHash
	rewritten[0].Hash = HashOf(rewritten[0])
	for i := 1; i < len(rewritten); i++ {
		rewritten[i].PrevHash = rewritten[i-1].Hash
		rewritten[i].Hash = HashOf(rewritten[i])
	}
	if err := VerifyCheckpoint(cp, pub, rewritten, 1); err == nil {
		t.Fatal("rewritten chain passed the old checkpoint")
	}
	// Restored backup: checkpoint generation newer than the store's.
	if err := VerifyCheckpoint(cp, pub, events, 0); err == nil {
		t.Fatal("newer checkpoint passed against an older store generation")
	}
}
