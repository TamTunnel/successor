// Package audit implements the hash-chained, append-only JSONL audit log
// and signed checkpoints. The log is the system of record for history.
//
// Chain format: one JSON object per line. Event hashes are SHA-256 over
// the canonical JSON of the event with the "hash" field removed, chained
// on prev_hash. The genesis event has prev_hash of all zeros. Because
// Go's encoding/json marshals structs in field order and map keys in
// sorted order, the canonical form is deterministic and verifiable by
// any tool that can read JSON and compute SHA-256 — no Successor binary
// required.
//
// What verification proves: the chain alone proves this copy of the log
// has not been altered since it was written. It does NOT prove a
// full-store rewrite did not happen — only an independently held signed
// checkpoint defeats that, and the docs say so plainly.
package audit

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"successor/internal/scan"
)

// ZeroHash is the prev_hash of the genesis event.
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Event is one audit log line. Field order is fixed: it is part of the
// canonical hash input, so it must never be reordered casually.
type Event struct {
	Seq        int            `json:"seq"`
	Ts         string         `json:"ts"`
	ActorID    string         `json:"actor_id"`
	Action     string         `json:"action"`
	AgentID    string         `json:"agent_id,omitempty"`
	HandoverID string         `json:"handover_id,omitempty"`
	Detail     map[string]any `json:"detail,omitempty"`
	PrevHash   string         `json:"prev_hash"`
	Hash       string         `json:"hash"`
}

// eventNoHash mirrors Event without the Hash field: the hash input.
type eventNoHash struct {
	Seq        int            `json:"seq"`
	Ts         string         `json:"ts"`
	ActorID    string         `json:"actor_id"`
	Action     string         `json:"action"`
	AgentID    string         `json:"agent_id,omitempty"`
	HandoverID string         `json:"handover_id,omitempty"`
	Detail     map[string]any `json:"detail,omitempty"`
	PrevHash   string         `json:"prev_hash"`
}

// HashOf computes the chain hash of an event (hash field excluded).
func HashOf(e Event) string {
	nh := eventNoHash{
		Seq: e.Seq, Ts: e.Ts, ActorID: e.ActorID, Action: e.Action,
		AgentID: e.AgentID, HandoverID: e.HandoverID, Detail: e.Detail,
		PrevHash: e.PrevHash,
	}
	b, err := json.Marshal(nh)
	if err != nil {
		// Marshaling a struct of strings/ints/maps cannot fail.
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ValidateDetail refuses detail content at write time: no secret-shaped
// strings anywhere in the detail, and no forbidden field names. A refused
// write appends nothing — redaction after the fact would mean the secret
// already touched the log file, and "deleted" lines in an append-only log
// are a contradiction. The returned error names the rule violated, never
// the matched material.
func ValidateDetail(detail map[string]any) error {
	for k, v := range detail {
		if scan.ForbiddenKey(k) {
			return fmt.Errorf("audit detail field %q is forbidden: field names must not carry credential material", k)
		}
		if err := scanValue(v); err != nil {
			return err
		}
	}
	return nil
}

func scanValue(v any) error {
	switch t := v.(type) {
	case string:
		if name := scan.Match(t); name != "" {
			return fmt.Errorf("audit detail refused: secret-shaped material detected (%s)", name)
		}
	case []string:
		for _, s := range t {
			if name := scan.Match(s); name != "" {
				return fmt.Errorf("audit detail refused: secret-shaped material detected (%s)", name)
			}
		}
	case []any:
		for _, e := range t {
			if err := scanValue(e); err != nil {
				return err
			}
		}
	case map[string]any:
		for k, e := range t {
			if scan.ForbiddenKey(k) {
				return fmt.Errorf("audit detail field %q is forbidden", k)
			}
			if err := scanValue(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// Log is an audit.jsonl file. Callers must hold the store lock while
// appending; Load and Verify are read-only.
type Log struct {
	Path string
}

// Load parses every line strictly. It does not verify the chain; use
// Verify for that.
func (l *Log) Load() ([]Event, error) {
	f, err := os.Open(l.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var events []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("audit log line %d: corrupt event: %w", lineNo, err)
		}
		events = append(events, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

// Verify recomputes the chain from genesis. On failure it reports the
// first bad sequence number, as the gate probes require.
func (l *Log) Verify() ([]Event, error) {
	events, err := l.Load()
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("audit log is empty: no genesis event")
	}
	prev := ZeroHash
	for i, e := range events {
		wantSeq := i + 1
		if e.Seq != wantSeq {
			return nil, fmt.Errorf("audit chain broken at seq %d: sequence gap (found seq %d)", wantSeq, e.Seq)
		}
		if e.PrevHash != prev {
			return nil, fmt.Errorf("audit chain broken at seq %d: prev_hash mismatch", e.Seq)
		}
		if HashOf(e) != e.Hash {
			return nil, fmt.Errorf("audit chain broken at seq %d: hash mismatch (event altered)", e.Seq)
		}
		prev = e.Hash
	}
	return events, nil
}

// Latest returns the last event, or nil when the log is empty.
func (l *Log) Latest() (*Event, error) {
	events, err := l.Load()
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, nil
	}
	return &events[len(events)-1], nil
}

// Append validates the detail, assigns seq/prev_hash/hash, and writes
// the whole log via temp file + fsync + rename (atomic under the store
// lock). The caller supplies seq-independent fields; Ts must already be
// set in UTC RFC3339.
func (l *Log) Append(e Event) (Event, error) {
	if err := ValidateDetail(e.Detail); err != nil {
		return Event{}, err
	}
	events, err := l.Load()
	if err != nil {
		if !os.IsNotExist(err) {
			return Event{}, err
		}
		events = nil
	}
	prev := ZeroHash
	if len(events) > 0 {
		prev = events[len(events)-1].Hash
	}
	e.Seq = len(events) + 1
	e.PrevHash = prev
	e.Hash = HashOf(e)
	events = append(events, e)
	var sb strings.Builder
	for _, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			return Event{}, err
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	if err := writeAtomic(l.Path, []byte(sb.String())); err != nil {
		return Event{}, err
	}
	return e, nil
}

// writeAtomic writes data to path via a temp file in the same directory,
// fsyncs, and renames over the destination.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// Checkpoint is a signed (seq, hash) pair meant to be stored off-box.
type Checkpoint struct {
	Seq        int    `json:"seq"`
	Hash       string `json:"hash"`
	Signature  string `json:"signature"` // hex Ed25519 signature
	KeyID      string `json:"key_id"`
	Generation int    `json:"generation"`
}

// CheckpointMessage is the exact signed payload. It is part of the
// format contract in FORMAT.md; changing it invalidates old checkpoints.
func CheckpointMessage(seq int, hash string, generation int) string {
	return fmt.Sprintf("successor-checkpoint-v1:%d:%s:%d", seq, hash, generation)
}

// SignCheckpoint signs the latest chain state.
func SignCheckpoint(priv ed25519.PrivateKey, keyID string, seq int, hash string, generation int) Checkpoint {
	msg := CheckpointMessage(seq, hash, generation)
	sig := ed25519.Sign(priv, []byte(msg))
	return Checkpoint{
		Seq: seq, Hash: hash,
		Signature: hex.EncodeToString(sig), KeyID: keyID, Generation: generation,
	}
}

// VerifyCheckpoint checks the signature against pub, then confirms the
// chain passes through (seq, hash): the event at that seq must carry
// that hash. Generation is a tripwire only: a checkpoint newer than the
// store means the store predates it (e.g. a restored backup).
func VerifyCheckpoint(cp Checkpoint, pub ed25519.PublicKey, events []Event, storeGeneration int) error {
	if cp.Generation > storeGeneration {
		return fmt.Errorf("checkpoint generation %d is newer than store generation %d: store predates checkpoint (possible restored backup)", cp.Generation, storeGeneration)
	}
	sig, err := hex.DecodeString(cp.Signature)
	if err != nil {
		return fmt.Errorf("checkpoint signature is not valid hex: %w", err)
	}
	msg := CheckpointMessage(cp.Seq, cp.Hash, cp.Generation)
	if !ed25519.Verify(pub, []byte(msg), sig) {
		return fmt.Errorf("checkpoint signature does not verify against key %s", cp.KeyID)
	}
	for _, e := range events {
		if e.Seq == cp.Seq {
			if e.Hash != cp.Hash {
				return fmt.Errorf("chain does not pass through checkpoint: event at seq %d has a different hash", cp.Seq)
			}
			return nil
		}
	}
	return fmt.Errorf("chain does not pass through checkpoint: no event at seq %d", cp.Seq)
}

// KeyID derives a key identifier from a public key: first 16 hex chars
// of SHA-256(public key bytes).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}
