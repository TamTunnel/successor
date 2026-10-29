// Package store implements the file-based store: JSON records, atomic
// writes, single-writer locking, and strict load-time validation.
//
// Layout:
//
//	<store>/
//	  meta.json, audit.key (0600), audit.pub, audit.jsonl
//	  agents/<ulid>.json, handovers/<ulid>.json, persons/<emp-id>.json
//	  keys/<key-id>.pub (archived public keys after rotation)
//	  .lock
//
// Records are never user-editable through the CLI's back door: the CLI
// is the only writer, and it enforces the handover state machine. Direct
// file editing by someone with store write access is the org's
// responsibility to prevent; load-time validation fails loud on
// tampered records instead of silently accepting or auto-repairing them.
package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// NowUTC returns the current UTC time in RFC3339.
func NowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// --- ULID (26-char Crockford, time-ordered) ---

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// GenerateULID mints a ULID: 48-bit millisecond timestamp + 80 bits of
// crypto randomness, Crockford base32 encoded.
func GenerateULID() (string, error) {
	ms := time.Now().UnixMilli()
	var rnd [10]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", err
	}
	var buf [26]byte
	// 48-bit timestamp: 10 chars (first char capped by 48 bits).
	v := uint64(ms)
	for i := 9; i >= 0; i-- {
		buf[i] = crockford[v&0x1F]
		v >>= 5
	}
	// 80 bits randomness: 16 chars.
	bits := make([]byte, 0, 10)
	bits = append(bits, rnd[:]...)
	acc := 0
	nbits := 0
	idx := 10
	for _, b := range bits {
		acc = (acc << 8) | int(b)
		nbits += 8
		for nbits >= 5 {
			nbits -= 5
			buf[idx] = crockford[(acc>>nbits)&0x1F]
			idx++
		}
	}
	if nbits > 0 {
		buf[idx] = crockford[(acc<<(5-nbits))&0x1F]
		idx++
	}
	return string(buf[:]), nil
}

// ValidULID reports whether s is a canonical 26-char Crockford ULID with
// a 48-bit timestamp (first char 0-7).
func ValidULID(s string) bool {
	if len(s) != 26 {
		return false
	}
	if s[0] < '0' || s[0] > '7' {
		return false
	}
	for i := 0; i < 26; i++ {
		if !strings.ContainsRune(crockford, rune(s[i])) {
			return false
		}
	}
	return true
}

// --- Records ---

type Person struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
	Departed    bool     `json:"departed"`
	CreatedAt   string   `json:"created_at"`
}

func (p Person) HasRole(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

type CredentialRef struct {
	Ref    string `json:"ref"`
	Kind   string `json:"kind"`
	Status string `json:"status"` // current|reissued|revoked|rotation-required|unknown
}

type Agent struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	OwnerID        string          `json:"owner_id"`
	Status         string          `json:"status"` // active|quarantined|archived
	Runtime        string          `json:"runtime"`
	ConfigRef      *string         `json:"config_ref"`
	ConfigHash     *string         `json:"config_hash"`
	RunbookRef     *string         `json:"runbook_ref"`
	CredentialRefs []CredentialRef `json:"credential_refs"`
	ScheduleRef    *string         `json:"schedule_ref"`
	CreatedAt      string          `json:"created_at"`
	UpdatedAt      string          `json:"updated_at"`
}

type ChecklistItem struct {
	Item     string `json:"item"`
	Kind     string `json:"kind"` // schedule-disable|revoke|reissue|verify-successor|verify-leaver
	Ref      string `json:"ref,omitempty"`
	Status   string `json:"status"` // pending|done|waived
	Reason   string `json:"reason,omitempty"`
	SignedBy string `json:"signed_by,omitempty"`
	SignedAt string `json:"signed_at,omitempty"`
	// NewRef carries the replacement reference supplied at re-issue
	// sign-off (manual) or printed by the reissue hook (script). It is
	// a reference, never secret material, and is validated as such.
	NewRef string `json:"new_ref,omitempty"`
}

type Handover struct {
	ID string `json:"id"`
	// AgentID is the agent being handed over.
	AgentID       string  `json:"agent_id"`
	FromOwnerID   string  `json:"from_owner_id"`
	ToSuccessorID string  `json:"to_successor_id"`
	RequesterID   string  `json:"requester_id"`
	ApproverID    *string `json:"approver_id"`
	// State: requested|approved|accepted|executed|partial|rejected|expired.
	State string `json:"state"`
	// AcceptanceTokenHash holds ONLY the SHA-256 hash of the one-time
	// acceptance token, never the token itself. The token is printed once
	// at approval time and delivered out-of-band by the admin. This hash
	// is the assessment-mandated exception to "hashes of references only":
	// it is a hash of a single-use random value, not of credential
	// material, and it is what makes token verification possible without
	// storing the token.
	AcceptanceTokenHash *string         `json:"acceptance_token_hash"`
	TokenExpiresAt      *string         `json:"token_expires_at"`
	Checklist           []ChecklistItem `json:"checklist"`
	ResidualRisks       []string        `json:"residual_risks"`
	RiskAcceptedBy      []string        `json:"risk_accepted_by"`
	RequestedAt         string          `json:"requested_at"`
	ApprovedAt          *string         `json:"approved_at"`
	AcceptedAt          *string         `json:"accepted_at"`
	ExecutedAt          *string         `json:"executed_at"`
	ExpiresAt           string          `json:"expires_at"`
	Adapter             string          `json:"adapter,omitempty"`
	HookDir             string          `json:"hook_dir,omitempty"`
	// EventsEmitted counts checklist items whose outcome audit events
	// were already written. Execute retries skip those events (the
	// outcomes are still folded in) so a retry never duplicates events.
	EventsEmitted int    `json:"events_emitted"`
	Reason        string `json:"reason,omitempty"`
}

type Meta struct {
	Version    int    `json:"version"`
	CreatedAt  string `json:"created_at"`
	KeyID      string `json:"key_id"`
	Generation int    `json:"generation"`
}

// --- Validation ---

// checkTimestamp validates an RFC3339 timestamp that records when
// something happened: it must not be in the future (clock skew
// allowance: one minute). Deadline fields (ExpiresAt,
// TokenExpiresAt) are validated by checkDeadline instead — a deadline
// in the future is the normal case.
func checkTimestamp(ts string) error {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return fmt.Errorf("timestamp %q is not RFC3339: %w", ts, err)
	}
	if t.After(time.Now().Add(time.Minute)) {
		return fmt.Errorf("timestamp %q is in the future", ts)
	}
	return nil
}

func checkDeadline(ts string) error {
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		return fmt.Errorf("timestamp %q is not RFC3339: %w", ts, err)
	}
	return nil
}

func validPersonID(id string) bool {
	if id == "" {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return id != "." && id != ".." && !strings.Contains(id, "..")
}

var agentStatuses = map[string]bool{"active": true, "quarantined": true, "archived": true}
var credStatuses = map[string]bool{"current": true, "reissued": true, "revoked": true, "rotation-required": true, "unknown": true}
var handoverStates = map[string]bool{"requested": true, "approved": true, "accepted": true, "executed": true, "partial": true, "rejected": true, "expired": true}
var checklistStatuses = map[string]bool{"pending": true, "done": true, "waived": true}

// ValidateAgent fails loud on any malformed field. It never repairs.
func ValidateAgent(a Agent, filename string) error {
	if !ValidULID(a.ID) {
		return fmt.Errorf("agent id %q is not a valid ULID", a.ID)
	}
	if a.ID != filename {
		return fmt.Errorf("agent id %q does not match file name %q", a.ID, filename)
	}
	if a.Name == "" {
		return fmt.Errorf("agent %s: name is empty", a.ID)
	}
	if !validPersonID(a.OwnerID) {
		return fmt.Errorf("agent %s: owner_id %q is invalid", a.ID, a.OwnerID)
	}
	if !agentStatuses[a.Status] {
		return fmt.Errorf("agent %s: unknown status %q", a.ID, a.Status)
	}
	if err := checkTimestamp(a.CreatedAt); err != nil {
		return fmt.Errorf("agent %s: created_at: %w", a.ID, err)
	}
	if err := checkTimestamp(a.UpdatedAt); err != nil {
		return fmt.Errorf("agent %s: updated_at: %w", a.ID, err)
	}
	for _, c := range a.CredentialRefs {
		if c.Ref == "" || c.Kind == "" {
			return fmt.Errorf("agent %s: credential ref with empty ref or kind", a.ID)
		}
		if !credStatuses[c.Status] {
			return fmt.Errorf("agent %s: unknown credential status %q", a.ID, c.Status)
		}
	}
	return nil
}

// ValidateHandover fails loud on any malformed field.
func ValidateHandover(h Handover, filename string) error {
	if !ValidULID(h.ID) {
		return fmt.Errorf("handover id %q is not a valid ULID", h.ID)
	}
	if h.ID != filename {
		return fmt.Errorf("handover id %q does not match file name %q", h.ID, filename)
	}
	if !ValidULID(h.AgentID) {
		return fmt.Errorf("handover %s: agent_id %q is not a valid ULID", h.ID, h.AgentID)
	}
	if !validPersonID(h.FromOwnerID) || !validPersonID(h.ToSuccessorID) || !validPersonID(h.RequesterID) {
		return fmt.Errorf("handover %s: invalid person id", h.ID)
	}
	if !handoverStates[h.State] {
		return fmt.Errorf("handover %s: unknown state %q", h.ID, h.State)
	}
	if err := checkTimestamp(h.RequestedAt); err != nil {
		return fmt.Errorf("handover %s: requested_at: %w", h.ID, err)
	}
	if err := checkDeadline(h.ExpiresAt); err != nil {
		return fmt.Errorf("handover %s: expires_at: %w", h.ID, err)
	}
	for _, ts := range []*string{h.ApprovedAt, h.AcceptedAt, h.ExecutedAt} {
		if ts != nil {
			if err := checkTimestamp(*ts); err != nil {
				return fmt.Errorf("handover %s: timestamp: %w", h.ID, err)
			}
		}
	}
	if h.TokenExpiresAt != nil {
		if err := checkDeadline(*h.TokenExpiresAt); err != nil {
			return fmt.Errorf("handover %s: token_expires_at: %w", h.ID, err)
		}
	}
	if h.AcceptanceTokenHash != nil {
		if len(*h.AcceptanceTokenHash) != 64 {
			return fmt.Errorf("handover %s: acceptance token hash is malformed", h.ID)
		}
		if _, err := hex.DecodeString(*h.AcceptanceTokenHash); err != nil {
			return fmt.Errorf("handover %s: acceptance token hash is not hex", h.ID)
		}
	}
	for _, it := range h.Checklist {
		if !checklistStatuses[it.Status] {
			return fmt.Errorf("handover %s: unknown checklist status %q", h.ID, it.Status)
		}
		if it.SignedAt != "" {
			if err := checkTimestamp(it.SignedAt); err != nil {
				return fmt.Errorf("handover %s: checklist signed_at: %w", h.ID, err)
			}
		}
	}
	return nil
}

// ValidatePerson fails loud on any malformed field.
func ValidatePerson(p Person, filename string) error {
	if !validPersonID(p.ID) {
		return fmt.Errorf("person id %q is invalid", p.ID)
	}
	if p.ID != filename {
		return fmt.Errorf("person id %q does not match file name %q", p.ID, filename)
	}
	if p.DisplayName == "" {
		return fmt.Errorf("person %s: display_name is empty", p.ID)
	}
	for _, r := range p.Roles {
		if r != "admin" && r != "approver" {
			return fmt.Errorf("person %s: unknown role %q", p.ID, r)
		}
	}
	if err := checkTimestamp(p.CreatedAt); err != nil {
		return fmt.Errorf("person %s: created_at: %w", p.ID, err)
	}
	return nil
}

// --- Store ---

type Store struct {
	Dir      string
	Meta     Meta
	lockFile *os.File
}

func (s *Store) AgentsDir() string    { return filepath.Join(s.Dir, "agents") }
func (s *Store) HandoversDir() string { return filepath.Join(s.Dir, "handovers") }
func (s *Store) PersonsDir() string   { return filepath.Join(s.Dir, "persons") }
func (s *Store) KeysDir() string      { return filepath.Join(s.Dir, "keys") }
func (s *Store) AuditPath() string    { return filepath.Join(s.Dir, "audit.jsonl") }
func (s *Store) PrivKeyPath() string  { return filepath.Join(s.Dir, "audit.key") }
func (s *Store) PubKeyPath() string   { return filepath.Join(s.Dir, "audit.pub") }
func (s *Store) MetaPath() string     { return filepath.Join(s.Dir, "meta.json") }

// Open loads an existing store and validates every record. It does not
// take the lock; call Lock after Open for mutating commands.
func Open(dir string) (*Store, error) {
	s := &Store{Dir: dir}
	b, err := os.ReadFile(s.MetaPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("store %q is not initialized (run successor init)", dir)
		}
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s.Meta); err != nil {
		return nil, fmt.Errorf("meta.json is corrupt: %w", err)
	}
	if _, _, _, err := s.LoadAll(); err != nil {
		return nil, err
	}
	return s, nil
}

// Lock takes the exclusive store lock (blocking: a second writer waits
// rather than corrupting state).
func (s *Store) Lock() error {
	f, err := os.OpenFile(filepath.Join(s.Dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return err
	}
	s.lockFile = f
	return nil
}

// Unlock releases the store lock.
func (s *Store) Unlock() {
	if s.lockFile != nil {
		_ = syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
		s.lockFile.Close()
		s.lockFile = nil
	}
}

func decodeFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// LoadAll loads and validates every record. Duplicate IDs and
// id/filename mismatches are refused.
func (s *Store) LoadAll() (agents []Agent, handovers []Handover, persons []Person, err error) {
	seenAgents := map[string]bool{}
	entries, err := os.ReadDir(s.AgentsDir())
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var a Agent
		if err := decodeFile(filepath.Join(s.AgentsDir(), e.Name()), &a); err != nil {
			return nil, nil, nil, fmt.Errorf("agent file %s: %w", e.Name(), err)
		}
		base := strings.TrimSuffix(e.Name(), ".json")
		if err := ValidateAgent(a, base); err != nil {
			return nil, nil, nil, err
		}
		if seenAgents[a.ID] {
			return nil, nil, nil, fmt.Errorf("duplicate agent id %s", a.ID)
		}
		seenAgents[a.ID] = true
		agents = append(agents, a)
	}
	seenHandovers := map[string]bool{}
	entries, err = os.ReadDir(s.HandoversDir())
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var h Handover
		if err := decodeFile(filepath.Join(s.HandoversDir(), e.Name()), &h); err != nil {
			return nil, nil, nil, fmt.Errorf("handover file %s: %w", e.Name(), err)
		}
		base := strings.TrimSuffix(e.Name(), ".json")
		if err := ValidateHandover(h, base); err != nil {
			return nil, nil, nil, err
		}
		if seenHandovers[h.ID] {
			return nil, nil, nil, fmt.Errorf("duplicate handover id %s", h.ID)
		}
		seenHandovers[h.ID] = true
		handovers = append(handovers, h)
	}
	entries, err = os.ReadDir(s.PersonsDir())
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var p Person
		if err := decodeFile(filepath.Join(s.PersonsDir(), e.Name()), &p); err != nil {
			return nil, nil, nil, fmt.Errorf("person file %s: %w", e.Name(), err)
		}
		base := strings.TrimSuffix(e.Name(), ".json")
		if err := ValidatePerson(p, base); err != nil {
			return nil, nil, nil, err
		}
		persons = append(persons, p)
	}
	return agents, handovers, persons, nil
}

func (s *Store) LoadAgent(id string) (Agent, error) {
	var a Agent
	if err := decodeFile(filepath.Join(s.AgentsDir(), id+".json"), &a); err != nil {
		if os.IsNotExist(err) {
			return a, fmt.Errorf("agent %s not found", id)
		}
		return a, err
	}
	if err := ValidateAgent(a, id); err != nil {
		return a, err
	}
	return a, nil
}

func (s *Store) LoadHandover(id string) (Handover, error) {
	var h Handover
	if err := decodeFile(filepath.Join(s.HandoversDir(), id+".json"), &h); err != nil {
		if os.IsNotExist(err) {
			return h, fmt.Errorf("handover %s not found", id)
		}
		return h, err
	}
	if err := ValidateHandover(h, id); err != nil {
		return h, err
	}
	return h, nil
}

func (s *Store) LoadPerson(id string) (Person, error) {
	var p Person
	if err := decodeFile(filepath.Join(s.PersonsDir(), id+".json"), &p); err != nil {
		if os.IsNotExist(err) {
			return p, fmt.Errorf("person %s not found", id)
		}
		return p, err
	}
	if err := ValidatePerson(p, id); err != nil {
		return p, err
	}
	return p, nil
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
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
	if err := os.Chmod(tmpName, perm); err != nil {
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

func marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// SaveAgent writes an agent record atomically, refreshing UpdatedAt.
func (s *Store) SaveAgent(a Agent) error {
	a.UpdatedAt = NowUTC()
	b, err := marshal(a)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.AgentsDir(), a.ID+".json"), b, 0644)
}

// SaveHandover writes a handover record atomically.
func (s *Store) SaveHandover(h Handover) error {
	b, err := marshal(h)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.HandoversDir(), h.ID+".json"), b, 0644)
}

// SavePerson writes a person record atomically.
func (s *Store) SavePerson(p Person) error {
	b, err := marshal(p)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.PersonsDir(), p.ID+".json"), b, 0644)
}

// SaveMeta writes meta.json atomically.
func (s *Store) SaveMeta() error {
	b, err := marshal(s.Meta)
	if err != nil {
		return err
	}
	return writeAtomic(s.MetaPath(), b, 0644)
}

// BumpGeneration increments the store generation (handover execution,
// key rotation) and persists meta.json.
func (s *Store) BumpGeneration() error {
	s.Meta.Generation++
	return s.SaveMeta()
}

// LoadPrivateKey reads audit.key (hex of the 64-byte Ed25519 private key).
func (s *Store) LoadPrivateKey() (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(s.PrivKeyPath())
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("audit.key is not valid hex: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("audit.key has wrong length %d", len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

// LoadPublicKey reads audit.pub (hex of the 32-byte Ed25519 public key).
func (s *Store) LoadPublicKey() (ed25519.PublicKey, error) {
	b, err := os.ReadFile(s.PubKeyPath())
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("audit.pub is not valid hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("audit.pub has wrong length %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// PublicKeyFor returns the public key for a key ID: the current key, or
// an archived key from keys/<key-id>.pub after rotation.
func (s *Store) PublicKeyFor(keyID string) (ed25519.PublicKey, error) {
	if keyID == s.Meta.KeyID {
		return s.LoadPublicKey()
	}
	b, err := os.ReadFile(filepath.Join(s.KeysDir(), keyID+".pub"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no public key for key id %s", keyID)
		}
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("archived key %s is not valid hex: %w", keyID, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("archived key %s has wrong length", keyID)
	}
	return ed25519.PublicKey(raw), nil
}

// KeyFingerprint derives a key ID from a public key.
func KeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}
