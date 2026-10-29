// Audit commands: verify, export, checkpoint, rotate-key.
//
// The audit log is a hash-chained JSONL file. Every event carries a
// sequence number and the SHA-256 of the previous event's canonical
// form, so line-level tampering breaks the chain at exactly the line
// that changed, and a full rewrite with a recomputed chain still
// breaks every checkpoint taken before the rewrite (checkpoints are
// signed, generation-stamped, and meant to live off the box).
//
// Checkpoints are the off-box trust anchor: an operator exports one
// after handover completion, stores it somewhere the box cannot
// rewrite, and later verifies the live log still passes through the
// checkpointed (seq, hash). A restore from an old backup fails
// verification because its generation is older than the checkpoint's.
package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"successor/internal/audit"
	"successor/internal/store"
)

// genEd25519Key generates a fresh Ed25519 keypair, public key first
// to match genKey's (pub, priv) order in cli.go. Defined here because
// the audit commands own key lifecycle (init, rotation).
func genEd25519Key() (pub, priv []byte, err error) {
	p, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return []byte(p), []byte(k), nil
}

func (c *ctx) cmdAudit(args []string) int {
	if len(args) == 0 {
		return c.fail(fmt.Errorf("usage: successor audit <verify|export|checkpoint|rotate-key>"))
	}
	switch args[0] {
	case "verify":
		return c.cmdAuditVerify(args[1:])
	case "export":
		return c.cmdAuditExport(args[1:])
	case "checkpoint":
		return c.cmdAuditCheckpoint(args[1:])
	case "rotate-key":
		return c.cmdAuditRotateKey(args[1:])
	default:
		return c.fail(fmt.Errorf("unknown audit subcommand %q", args[0]))
	}
}

func (c *ctx) cmdAuditVerify(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	s, err := c.openRead()
	if err != nil {
		return c.fail(err)
	}
	log := &audit.Log{Path: s.AuditPath()}
	events, verr := log.Verify()
	ok, detail := true, "audit log valid"
	if verr != nil {
		ok = false
		detail = "audit log INVALID: " + verr.Error()
		events = nil
		if evs, lerr := log.Load(); lerr == nil {
			events = evs
		}
	}
	// Optional checkpoint verification: --checkpoint <file> pins the log
	// to a previously exported off-box checkpoint.
	if cpPath := f.opt("checkpoint"); cpPath != "" {
		data, err := os.ReadFile(cpPath)
		if err != nil {
			return c.fail(err)
		}
		var chk audit.Checkpoint
		if err := json.Unmarshal(data, &chk); err != nil {
			return c.fail(fmt.Errorf("checkpoint file is not valid JSON: %w", err))
		}
		pub, err := s.PublicKeyFor(chk.KeyID)
		if err != nil {
			ok = false
			detail = fmt.Sprintf("checkpoint key %s not found", chk.KeyID)
		} else if err := audit.VerifyCheckpoint(chk, pub, events, s.Meta.Generation); err != nil {
			ok = false
			detail = "checkpoint verification FAILED: " + err.Error()
		} else {
			detail += fmt.Sprintf("; checkpoint seq %d verified (key %s)", chk.Seq, chk.KeyID)
		}
	}
	// With --actor, the verification itself is audited (pass or fail).
	// Without it, verify is read-only and leaves no trace.
	if actorFlag := f.opt("actor"); actorFlag != "" {
		if _, err := c.knownActor(s, actorFlag); err != nil {
			return c.fail(err)
		}
		ls, err := c.openLocked()
		if err != nil {
			return c.fail(err)
		}
		defer ls.Unlock()
		_ = c.auditEvent(ls, actorFlag, "audit.verified", "", "", map[string]any{"valid": ok, "detail": detail})
	}
	if !ok {
		return c.fail(fmt.Errorf("%s", detail))
	}
	return c.print(map[string]any{"valid": true, "events": len(events), "detail": detail}, detail)
}

func (c *ctx) cmdAuditExport(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	out := f.opt("out")
	if out == "" {
		return c.fail(fmt.Errorf("audit export requires --out <path>"))
	}
	if err := checkClean(out); err != nil {
		return c.fail(err)
	}
	s, err := c.openRead()
	if err != nil {
		return c.fail(err)
	}
	log := &audit.Log{Path: s.AuditPath()}
	events, err := log.Load()
	if err != nil {
		return c.fail(err)
	}
	// Export is a byte copy of the log, not a re-render: the exported
	// file must hash-identically to the on-disk log for off-box checks.
	data, err := os.ReadFile(s.AuditPath())
	if err != nil {
		return c.fail(err)
	}
	if err := os.WriteFile(out, data, 0600); err != nil {
		return c.fail(err)
	}
	return c.print(map[string]any{"events": len(events), "out": out},
		fmt.Sprintf("exported %d audit events to %s", len(events), out))
}

func (c *ctx) cmdAuditCheckpoint(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	out := f.opt("out")
	s, err := c.openLocked()
	if err != nil {
		return c.fail(err)
	}
	defer s.Unlock()
	actor, err := c.actor(f)
	if err != nil {
		return c.fail(err)
	}
	ap, err := c.knownActor(s, actor)
	if err != nil {
		return c.fail(err)
	}
	if err := requireRole(ap, "admin"); err != nil {
		return c.fail(err)
	}
	log := &audit.Log{Path: s.AuditPath()}
	latest, err := log.Latest()
	if err != nil {
		return c.fail(err)
	}
	if latest == nil {
		return c.fail(fmt.Errorf("audit log is empty: nothing to checkpoint"))
	}
	priv, err := s.LoadPrivateKey()
	if err != nil {
		return c.fail(err)
	}
	cp := audit.SignCheckpoint(priv, s.Meta.KeyID, latest.Seq, latest.Hash, s.Meta.Generation)
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return c.fail(err)
	}
	if out != "" {
		if err := checkClean(out); err != nil {
			return c.fail(err)
		}
		if err := os.WriteFile(out, append(data, '\n'), 0600); err != nil {
			return c.fail(err)
		}
	}
	// The checkpoint itself is recorded in the log (seq/hash/key_id,
	// never the signature — the signature lives off-box).
	if err := c.auditEvent(s, actor, "audit.checkpoint", "", "", map[string]any{
		"seq": cp.Seq, "hash": cp.Hash, "key_id": cp.KeyID, "generation": cp.Generation,
	}); err != nil {
		return c.fail(err)
	}
	if out != "" {
		return c.print(map[string]any{"seq": cp.Seq, "hash": cp.Hash, "key_id": cp.KeyID, "generation": cp.Generation, "out": out},
			fmt.Sprintf("checkpoint seq %d written to %s (store this off-box; the box cannot be trusted to keep its own proof)", cp.Seq, out))
	}
	return c.print(map[string]any{"seq": cp.Seq, "hash": cp.Hash, "key_id": cp.KeyID, "generation": cp.Generation}, string(data))
}

func (c *ctx) cmdAuditRotateKey(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	s, err := c.openLocked()
	if err != nil {
		return c.fail(err)
	}
	defer s.Unlock()
	actor, err := c.actor(f)
	if err != nil {
		return c.fail(err)
	}
	ap, err := c.knownActor(s, actor)
	if err != nil {
		return c.fail(err)
	}
	if err := requireRole(ap, "admin"); err != nil {
		return c.fail(err)
	}
	oldKeyID := s.Meta.KeyID
	// Archive the old public key so checkpoints signed under it remain
	// verifiable after rotation.
	oldPub, err := s.PublicKeyFor(oldKeyID)
	if err == nil {
		archive := filepath.Join(s.KeysDir(), oldKeyID+".pub")
		if err := os.WriteFile(archive, []byte(hex.EncodeToString(oldPub)+"\n"), 0644); err != nil {
			return c.fail(err)
		}
	}
	pub, priv, err := genEd25519Key()
	if err != nil {
		return c.fail(err)
	}
	newKeyID := audit.KeyID(pub)
	if err := os.WriteFile(s.PrivKeyPath(), []byte(hex.EncodeToString(priv)+"\n"), 0600); err != nil {
		return c.fail(err)
	}
	if err := os.WriteFile(s.PubKeyPath(), []byte(hex.EncodeToString(pub)+"\n"), 0644); err != nil {
		return c.fail(err)
	}
	s.Meta.KeyID = newKeyID
	if err := s.SaveMeta(); err != nil {
		return c.fail(err)
	}
	if err := s.BumpGeneration(); err != nil {
		return c.fail(err)
	}
	if err := c.auditEvent(s, actor, "audit.key-rotated", "", "", map[string]any{"old_key_id": oldKeyID, "new_key_id": newKeyID}); err != nil {
		return c.fail(err)
	}
	return c.print(map[string]any{"old_key_id": oldKeyID, "new_key_id": newKeyID},
		fmt.Sprintf("audit key rotated: %s -> %s (old checkpoints remain verifiable)", oldKeyID, newKeyID))
}

var _ = store.NowUTC
