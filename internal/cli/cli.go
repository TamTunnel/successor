// Package cli implements the successor command line: flag parsing,
// dispatch, actor enforcement, and the agent/person/init commands.
// Handover commands live in handover.go; audit commands in auditcmd.go;
// reports in report.go.
package cli

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"successor/internal/audit"
	"successor/internal/scan"
	"successor/internal/store"
)

// Run executes the CLI. It returns a process exit code and never calls
// os.Exit itself, so tests can invoke it in-process.
func Run(args []string, stdout, stderr io.Writer) int {
	c := &ctx{out: stdout, err: stderr, storeDir: defaultStoreDir()}
	// Global flags may appear anywhere; extract them first.
	rest, err := c.extractGlobals(args)
	if err != nil {
		return c.fail(err)
	}
	if len(rest) == 0 {
		return c.fail(fmt.Errorf("usage: successor <command> [args] (try: successor init, successor agent list, successor handover list)"))
	}
	switch rest[0] {
	case "init":
		return c.cmdInit(rest[1:])
	case "agent":
		return c.cmdAgent(rest[1:])
	case "person":
		return c.cmdPerson(rest[1:])
	case "handover":
		return c.cmdHandover(rest[1:])
	case "audit":
		return c.cmdAudit(rest[1:])
	case "report":
		return c.cmdReport(rest[1:])
	default:
		return c.fail(fmt.Errorf("unknown command %q", rest[0]))
	}
}

func defaultStoreDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".successor"
	}
	return filepath.Join(home, ".successor")
}

type ctx struct {
	out      io.Writer
	err      io.Writer
	storeDir string
	jsonOut  bool
}

func (c *ctx) fail(err error) int {
	fmt.Fprintln(c.err, "error:", err.Error())
	return 1
}

// extractGlobals pulls --store and --json out of the argument list.
func (c *ctx) extractGlobals(args []string) ([]string, error) {
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--store":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--store requires a directory")
			}
			c.storeDir = args[i+1]
			i++
		case strings.HasPrefix(a, "--store="):
			c.storeDir = strings.TrimPrefix(a, "--store=")
		case a == "--json":
			c.jsonOut = true
		default:
			rest = append(rest, a)
		}
	}
	return rest, nil
}

// flagSet is a minimal flag parser: --name value, --name=value, bool
// flags, and positionals. Unknown flags are refused.
type flagSet struct {
	vals  map[string]string
	bools map[string]bool
	pos   []string
}

func parseFlags(args []string, boolNames map[string]bool) (*flagSet, error) {
	f := &flagSet{vals: map[string]string{}, bools: map[string]bool{}}
	noMore := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if noMore {
			f.pos = append(f.pos, a)
			continue
		}
		if a == "--" {
			noMore = true
			continue
		}
		if strings.HasPrefix(a, "--") {
			name := strings.TrimPrefix(a, "--")
			if idx := strings.Index(name, "="); idx >= 0 {
				key, val := name[:idx], name[idx+1:]
				if boolNames[key] {
					f.bools[key] = val == "true" || val == "1"
					continue
				}
				f.vals[key] = val
				continue
			}
			if boolNames[name] {
				f.bools[name] = true
				continue
			}
			if i+1 >= len(args) {
				return nil, fmt.Errorf("flag --%s requires a value", name)
			}
			f.vals[name] = args[i+1]
			i++
			continue
		}
		f.pos = append(f.pos, a)
	}
	return f, nil
}

func (f *flagSet) req(name string) (string, error) {
	v, ok := f.vals[name]
	if !ok || v == "" {
		return "", fmt.Errorf("missing required flag --%s", name)
	}
	return v, nil
}

func (f *flagSet) opt(name string) string { return f.vals[name] }

// print emits result as JSON with --json, or human text otherwise.
func (c *ctx) print(result map[string]any, human string) int {
	if c.jsonOut {
		enc := json.NewEncoder(c.out)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(result)
	} else {
		fmt.Fprintln(c.out, human)
	}
	return 0
}

// openRead opens an existing store without locking (read-only commands).
func (c *ctx) openRead() (*store.Store, error) {
	return store.Open(c.storeDir)
}

// openLocked opens an existing store and takes the exclusive lock.
func (c *ctx) openLocked() (*store.Store, error) {
	s, err := store.Open(c.storeDir)
	if err != nil {
		return nil, err
	}
	if err := s.Lock(); err != nil {
		return nil, err
	}
	return s, nil
}

// auditEvent appends one audit event. Detail values are built only from
// references, statuses, and counts; the audit writer refuses anything
// secret-shaped at write time.
func (c *ctx) auditEvent(s *store.Store, actor, action, agentID, handoverID string, detail map[string]any) error {
	log := &audit.Log{Path: s.AuditPath()}
	_, err := log.Append(audit.Event{
		Ts: store.NowUTC(), ActorID: actor, Action: action,
		AgentID: agentID, HandoverID: handoverID, Detail: detail,
	})
	return err
}

// actor resolves --actor or SUCCESSOR_ACTOR. Mutating commands require it.
func (c *ctx) actor(f *flagSet) (string, error) {
	a := f.opt("actor")
	if a == "" {
		a = os.Getenv("SUCCESSOR_ACTOR")
	}
	if a == "" {
		return "", fmt.Errorf("mutating commands require --actor or SUCCESSOR_ACTOR (no anonymous actors)")
	}
	return a, nil
}

// knownActor loads the actor's person record; unknown actors are refused.
// A departed person cannot act: after departure their employee ID is
// dead for every mutation, which is what makes "leaver access is gone"
// hold inside the tool as well as in the credential grants.
func (c *ctx) knownActor(s *store.Store, actor string) (store.Person, error) {
	p, err := s.LoadPerson(actor)
	if err != nil {
		return p, fmt.Errorf("unknown actor %q: actors must be registered persons", actor)
	}
	if p.Departed {
		return p, fmt.Errorf("actor %q has departed and cannot act", actor)
	}
	return p, nil
}

func requireRole(p store.Person, role string) error {
	if !p.HasRole(role) {
		return fmt.Errorf("person %s lacks the %s role", p.ID, role)
	}
	return nil
}

// checkClean refuses free-text input containing secret-shaped material.
// The error never echoes the input.
func checkClean(s string) error {
	if s == "" {
		return nil
	}
	if strings.Contains(s, "\n") || strings.Contains(s, "\r") {
		return fmt.Errorf("input must be a single line")
	}
	if name := scan.Match(s); name != "" {
		return fmt.Errorf("input refused: secret-shaped material detected (%s)", name)
	}
	return nil
}

// checkRef validates a reference: single line, non-empty, not
// secret-shaped. Strict refs (credential references) also forbid
// whitespace: they are identifiers, not prose.
func checkRef(s string, strict bool) error {
	if err := checkClean(s); err != nil {
		return err
	}
	if s == "" {
		return fmt.Errorf("reference is empty")
	}
	if strict && strings.ContainsAny(s, " \t") {
		return fmt.Errorf("credential reference %q must not contain whitespace", s)
	}
	return nil
}

// sweepExpiry transitions overdue requested/approved/accepted handovers
// to expired and audits each transition. It runs under the store lock at
// the start of every mutating command.
func (c *ctx) sweepExpiry(s *store.Store) error {
	_, handovers, _, err := s.LoadAll()
	if err != nil {
		return err
	}
	now := time.Now()
	for _, h := range handovers {
		if h.State != "requested" && h.State != "approved" && h.State != "accepted" {
			continue
		}
		exp, err := time.Parse(time.RFC3339, h.ExpiresAt)
		if err != nil {
			continue
		}
		if now.After(exp) {
			h.State = "expired"
			if err := s.SaveHandover(h); err != nil {
				return err
			}
			_ = c.auditEvent(s, "system", "handover.expired", h.AgentID, h.ID, map[string]any{
				"from_owner_id": h.FromOwnerID, "to_successor_id": h.ToSuccessorID,
			})
		}
	}
	return nil
}

func strptr(s string) *string { return &s }

func generateToken() (token string, hash string, err error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(b[:])
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

func tokenMatches(provided, storedHash string) bool {
	sum := sha256.Sum256([]byte(provided))
	raw, err := hex.DecodeString(storedHash)
	if err != nil {
		return false
	}
	if len(raw) != len(sum) {
		return false
	}
	match := true
	for i := range raw {
		if raw[i] != sum[i] {
			match = false
		}
	}
	return match
}

// --- init ---

func (c *ctx) cmdInit(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	if _, err := os.Stat(filepath.Join(c.storeDir, "meta.json")); err == nil {
		return c.fail(fmt.Errorf("store %q already initialized", c.storeDir))
	}
	for _, d := range []string{"agents", "handovers", "persons", "keys"} {
		if err := os.MkdirAll(filepath.Join(c.storeDir, d), 0755); err != nil {
			return c.fail(err)
		}
	}
	if _, err := os.OpenFile(filepath.Join(c.storeDir, ".lock"), os.O_CREATE|os.O_RDWR, 0600); err != nil {
		return c.fail(err)
	}
	// Ed25519 audit keypair. The private key lives on-box at 0600: the
	// documented v1 weakness (see README honest limits). Checkpoints
	// exported off-box are what defeat a full-store rewrite.
	pub, priv, err := genKey()
	if err != nil {
		return c.fail(err)
	}
	keyID := store.KeyFingerprint(pub)
	if err := os.WriteFile(filepath.Join(c.storeDir, "audit.key"), []byte(hex.EncodeToString(priv)+"\n"), 0600); err != nil {
		return c.fail(err)
	}
	if err := os.WriteFile(filepath.Join(c.storeDir, "audit.pub"), []byte(hex.EncodeToString(pub)+"\n"), 0644); err != nil {
		return c.fail(err)
	}
	s := &store.Store{Dir: c.storeDir}
	s.Meta = store.Meta{Version: 1, CreatedAt: store.NowUTC(), KeyID: keyID, Generation: 1}
	if err := s.SaveMeta(); err != nil {
		return c.fail(err)
	}
	if err := s.Lock(); err != nil {
		return c.fail(err)
	}
	defer s.Unlock()
	log := &audit.Log{Path: s.AuditPath()}
	if _, err := log.Append(audit.Event{Ts: store.NowUTC(), ActorID: "system", Action: "audit.genesis", Detail: map[string]any{"store_version": 1}}); err != nil {
		return c.fail(err)
	}
	human := fmt.Sprintf("store initialized at %s\nkey id: %s\nAudit signing key is on-box at 0600: export checkpoints off-box regularly (see README honest limits).", c.storeDir, keyID)
	result := map[string]any{"store": c.storeDir, "key_id": keyID}
	if admin := f.opt("admin"); admin != "" {
		name := f.opt("admin-name")
		if name == "" {
			name = admin
		}
		if err := checkClean(name); err != nil {
			return c.fail(err)
		}
		p := store.Person{ID: admin, DisplayName: name, Roles: []string{"admin"}, CreatedAt: store.NowUTC()}
		if err := s.SavePerson(p); err != nil {
			return c.fail(err)
		}
		if err := c.auditEvent(s, admin, "person.added", "", "", map[string]any{"person_id": admin, "bootstrap": true}); err != nil {
			return c.fail(err)
		}
		human += fmt.Sprintf("\nadmin seeded: %s", admin)
		result["admin"] = admin
	}
	return c.print(result, human)
}

func genKey() (pub, priv []byte, err error) {
	// Implemented in auditcmd.go (Ed25519 key generation wrapper).
	return genEd25519Key()
}

// --- person ---

func (c *ctx) cmdPerson(args []string) int {
	if len(args) == 0 {
		return c.fail(fmt.Errorf("usage: successor person <add|list|depart>"))
	}
	switch args[0] {
	case "add":
		return c.cmdPersonAdd(args[1:])
	case "list":
		return c.cmdPersonList(args[1:])
	case "depart":
		return c.cmdPersonDepart(args[1:])
	default:
		return c.fail(fmt.Errorf("unknown person subcommand %q", args[0]))
	}
}

func (c *ctx) cmdPersonAdd(args []string) int {
	f, err := parseFlags(args, map[string]bool{"admin": true, "approver": true})
	if err != nil {
		return c.fail(err)
	}
	id, err := f.req("id")
	if err != nil {
		return c.fail(err)
	}
	name, err := f.req("name")
	if err != nil {
		return c.fail(err)
	}
	if err := checkClean(name); err != nil {
		return c.fail(err)
	}
	s, err := c.openLocked()
	if err != nil {
		return c.fail(err)
	}
	defer s.Unlock()
	if err := c.sweepExpiry(s); err != nil {
		return c.fail(err)
	}
	_, _, persons, err := s.LoadAll()
	if err != nil {
		return c.fail(err)
	}
	bootstrap := len(persons) == 0
	var actor string
	if bootstrap {
		actor = id
	} else {
		actor, err = c.actor(f)
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
	}
	if _, err := s.LoadPerson(id); err == nil {
		return c.fail(fmt.Errorf("person %s already exists", id))
	}
	var roles []string
	if f.bools["admin"] {
		roles = append(roles, "admin")
	}
	if f.bools["approver"] {
		roles = append(roles, "approver")
	}
	p := store.Person{ID: id, DisplayName: name, Roles: roles, CreatedAt: store.NowUTC()}
	if err := s.SavePerson(p); err != nil {
		return c.fail(err)
	}
	detail := map[string]any{"person_id": id, "roles": roles}
	if bootstrap {
		detail["bootstrap"] = true
	}
	if err := c.auditEvent(s, actor, "person.added", "", "", detail); err != nil {
		return c.fail(err)
	}
	return c.print(map[string]any{"id": id, "display_name": name, "roles": roles},
		fmt.Sprintf("person %s (%s) added, roles: %s", id, name, strings.Join(roles, ",")))
}

func (c *ctx) cmdPersonList(args []string) int {
	if _, err := parseFlags(args, nil); err != nil {
		return c.fail(err)
	}
	s, err := c.openRead()
	if err != nil {
		return c.fail(err)
	}
	_, _, persons, err := s.LoadAll()
	if err != nil {
		return c.fail(err)
	}
	sort.Slice(persons, func(i, j int) bool { return persons[i].ID < persons[j].ID })
	var rows []map[string]any
	var lines []string
	for _, p := range persons {
		rows = append(rows, map[string]any{"id": p.ID, "display_name": p.DisplayName, "roles": p.Roles, "departed": p.Departed})
		status := ""
		if p.Departed {
			status = " departed"
		}
		lines = append(lines, fmt.Sprintf("%s %s roles=%s%s", p.ID, p.DisplayName, strings.Join(p.Roles, ","), status))
	}
	if c.jsonOut {
		return c.print(map[string]any{"persons": rows}, "")
	}
	return c.print(map[string]any{"persons": rows}, strings.Join(lines, "\n"))
}

func (c *ctx) cmdPersonDepart(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	if len(f.pos) != 1 {
		return c.fail(fmt.Errorf("usage: successor person depart <emp-id>"))
	}
	id := f.pos[0]
	s, err := c.openLocked()
	if err != nil {
		return c.fail(err)
	}
	defer s.Unlock()
	if err := c.sweepExpiry(s); err != nil {
		return c.fail(err)
	}
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
	p, err := s.LoadPerson(id)
	if err != nil {
		return c.fail(err)
	}
	p.Departed = true
	if err := s.SavePerson(p); err != nil {
		return c.fail(err)
	}
	if err := c.auditEvent(s, actor, "person.departed", "", "", map[string]any{"person_id": id}); err != nil {
		return c.fail(err)
	}
	return c.print(map[string]any{"id": id, "departed": true}, fmt.Sprintf("person %s marked departed", id))
}

// --- agent ---

func (c *ctx) cmdAgent(args []string) int {
	if len(args) == 0 {
		return c.fail(fmt.Errorf("usage: successor agent <register|list|show|archive|quarantine|unquarantine>"))
	}
	switch args[0] {
	case "register":
		return c.cmdAgentRegister(args[1:])
	case "list":
		return c.cmdAgentList(args[1:])
	case "show":
		return c.cmdAgentShow(args[1:])
	case "archive":
		return c.cmdAgentArchive(args[1:])
	case "quarantine":
		return c.cmdAgentQuarantine(args[1:], true)
	case "unquarantine":
		return c.cmdAgentQuarantine(args[1:], false)
	default:
		return c.fail(fmt.Errorf("unknown agent subcommand %q", args[0]))
	}
}

// splitCredentialRef parses "kind:ref" or a bare ref (kind "generic").
// The split is on the first colon, so vault-style paths keep working.
func splitCredentialRef(s string) (kind, ref string) {
	if idx := strings.Index(s, ":"); idx > 0 {
		return s[:idx], s[idx+1:]
	}
	return "generic", s
}

func (c *ctx) cmdAgentRegister(args []string) int {
	// --credential-ref is repeatable: parseFlags keeps only the last
	// value, so pre-scan for repeats first.
	var credRefs []string
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--credential-ref" && i+1 < len(args) {
			credRefs = append(credRefs, args[i+1])
			i++
			continue
		}
		if strings.HasPrefix(args[i], "--credential-ref=") {
			credRefs = append(credRefs, strings.TrimPrefix(args[i], "--credential-ref="))
			continue
		}
		rest = append(rest, args[i])
	}
	f, err := parseFlags(rest, nil)
	if err != nil {
		return c.fail(err)
	}
	name, err := f.req("name")
	if err != nil {
		return c.fail(err)
	}
	owner, err := f.req("owner")
	if err != nil {
		return c.fail(err)
	}
	runtime, err := f.req("runtime")
	if err != nil {
		return c.fail(err)
	}
	for _, v := range []string{name, owner, runtime, f.opt("config-ref"), f.opt("runbook-ref"), f.opt("schedule-ref")} {
		if err := checkClean(v); err != nil {
			return c.fail(err)
		}
	}
	for _, cr := range credRefs {
		if err := checkRef(cr, true); err != nil {
			return c.fail(err)
		}
	}
	s, err := c.openLocked()
	if err != nil {
		return c.fail(err)
	}
	defer s.Unlock()
	if err := c.sweepExpiry(s); err != nil {
		return c.fail(err)
	}
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
	if _, err := s.LoadPerson(owner); err != nil {
		return c.fail(fmt.Errorf("owner %s is not a registered person", owner))
	}
	id, err := store.GenerateULID()
	if err != nil {
		return c.fail(err)
	}
	a := store.Agent{
		ID: id, Name: name, OwnerID: owner, Status: "active", Runtime: runtime,
		CreatedAt: store.NowUTC(), UpdatedAt: store.NowUTC(),
	}
	if v := f.opt("config-ref"); v != "" {
		a.ConfigRef = strptr(v)
	}
	if v := f.opt("runbook-ref"); v != "" {
		a.RunbookRef = strptr(v)
	}
	if v := f.opt("schedule-ref"); v != "" {
		a.ScheduleRef = strptr(v)
	}
	for _, cr := range credRefs {
		kind, ref := splitCredentialRef(cr)
		a.CredentialRefs = append(a.CredentialRefs, store.CredentialRef{Ref: ref, Kind: kind, Status: "current"})
	}
	if err := s.SaveAgent(a); err != nil {
		return c.fail(err)
	}
	if err := c.auditEvent(s, actor, "agent.registered", a.ID, "", map[string]any{"name": name, "owner_id": owner}); err != nil {
		return c.fail(err)
	}
	return c.print(map[string]any{"id": a.ID, "name": name, "owner_id": owner, "status": "active"},
		fmt.Sprintf("agent registered: %s (%s), owner %s", a.ID, name, owner))
}

func (c *ctx) cmdAgentList(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	s, err := c.openRead()
	if err != nil {
		return c.fail(err)
	}
	agents, _, _, err := s.LoadAll()
	if err != nil {
		return c.fail(err)
	}
	ownerFilter, statusFilter := f.opt("owner"), f.opt("status")
	sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })
	var rows []map[string]any
	var lines []string
	for _, a := range agents {
		if ownerFilter != "" && a.OwnerID != ownerFilter {
			continue
		}
		if statusFilter != "" && a.Status != statusFilter {
			continue
		}
		rows = append(rows, map[string]any{"id": a.ID, "name": a.Name, "owner_id": a.OwnerID, "status": a.Status, "runtime": a.Runtime})
		lines = append(lines, fmt.Sprintf("%s %s owner=%s status=%s", a.ID, a.Name, a.OwnerID, a.Status))
	}
	if c.jsonOut {
		return c.print(map[string]any{"agents": rows}, "")
	}
	return c.print(map[string]any{"agents": rows}, strings.Join(lines, "\n"))
}

func agentJSON(a store.Agent) map[string]any {
	m := map[string]any{
		"id": a.ID, "name": a.Name, "owner_id": a.OwnerID, "status": a.Status,
		"runtime": a.Runtime, "credential_refs": a.CredentialRefs,
		"created_at": a.CreatedAt, "updated_at": a.UpdatedAt,
	}
	if a.ConfigRef != nil {
		m["config_ref"] = *a.ConfigRef
	}
	if a.ConfigHash != nil {
		m["config_hash"] = *a.ConfigHash
	}
	if a.RunbookRef != nil {
		m["runbook_ref"] = *a.RunbookRef
	}
	if a.ScheduleRef != nil {
		m["schedule_ref"] = *a.ScheduleRef
	}
	return m
}

func (c *ctx) cmdAgentShow(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	if len(f.pos) != 1 {
		return c.fail(fmt.Errorf("usage: successor agent show <agent-id>"))
	}
	s, err := c.openRead()
	if err != nil {
		return c.fail(err)
	}
	a, err := s.LoadAgent(f.pos[0])
	if err != nil {
		return c.fail(err)
	}
	if c.jsonOut {
		return c.print(agentJSON(a), "")
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("id: %s\nname: %s\nowner: %s\nstatus: %s\nruntime: %s\n", a.ID, a.Name, a.OwnerID, a.Status, a.Runtime))
	if a.ConfigRef != nil {
		b.WriteString("config_ref: " + *a.ConfigRef + "\n")
	}
	if a.ConfigHash != nil {
		b.WriteString("config_hash: " + *a.ConfigHash + "\n")
	}
	if a.RunbookRef != nil {
		b.WriteString("runbook_ref: " + *a.RunbookRef + "\n")
	}
	if a.ScheduleRef != nil {
		b.WriteString("schedule_ref: " + *a.ScheduleRef + "\n")
	}
	for _, cr := range a.CredentialRefs {
		b.WriteString(fmt.Sprintf("credential: %s [%s] %s\n", cr.Ref, cr.Kind, cr.Status))
	}
	return c.print(agentJSON(a), strings.TrimRight(b.String(), "\n"))
}

func (c *ctx) cmdAgentArchive(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	if len(f.pos) != 1 {
		return c.fail(fmt.Errorf("usage: successor agent archive <agent-id>"))
	}
	s, err := c.openLocked()
	if err != nil {
		return c.fail(err)
	}
	defer s.Unlock()
	if err := c.sweepExpiry(s); err != nil {
		return c.fail(err)
	}
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
	a, err := s.LoadAgent(f.pos[0])
	if err != nil {
		return c.fail(err)
	}
	if _, handovers, _, err := s.LoadAll(); err != nil {
		return c.fail(err)
	} else {
		for _, h := range handovers {
			if h.AgentID == a.ID && (h.State == "requested" || h.State == "approved" || h.State == "accepted") {
				return c.fail(fmt.Errorf("agent %s has a pending handover %s; resolve it before archiving", a.ID, h.ID))
			}
		}
	}
	a.Status = "archived"
	if err := s.SaveAgent(a); err != nil {
		return c.fail(err)
	}
	if err := c.auditEvent(s, actor, "agent.archived", a.ID, "", nil); err != nil {
		return c.fail(err)
	}
	return c.print(map[string]any{"id": a.ID, "status": "archived"}, fmt.Sprintf("agent %s archived", a.ID))
}

func (c *ctx) cmdAgentQuarantine(args []string, quarantine bool) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	if len(f.pos) != 1 {
		verb := "quarantine"
		if !quarantine {
			verb = "unquarantine"
		}
		return c.fail(fmt.Errorf("usage: successor agent %s <agent-id>", verb))
	}
	s, err := c.openLocked()
	if err != nil {
		return c.fail(err)
	}
	defer s.Unlock()
	if err := c.sweepExpiry(s); err != nil {
		return c.fail(err)
	}
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
	a, err := s.LoadAgent(f.pos[0])
	if err != nil {
		return c.fail(err)
	}
	if quarantine {
		if a.Status != "active" {
			return c.fail(fmt.Errorf("agent %s is %s, not active", a.ID, a.Status))
		}
		a.Status = "quarantined"
		if err := s.SaveAgent(a); err != nil {
			return c.fail(err)
		}
		if err := c.auditEvent(s, actor, "agent.quarantined", a.ID, "", nil); err != nil {
			return c.fail(err)
		}
		return c.print(map[string]any{"id": a.ID, "status": "quarantined"}, fmt.Sprintf("agent %s quarantined", a.ID))
	}
	if a.Status != "quarantined" {
		return c.fail(fmt.Errorf("agent %s is %s, not quarantined", a.ID, a.Status))
	}
	a.Status = "active"
	if err := s.SaveAgent(a); err != nil {
		return c.fail(err)
	}
	if err := c.auditEvent(s, actor, "agent.unquarantined", a.ID, "", nil); err != nil {
		return c.fail(err)
	}
	return c.print(map[string]any{"id": a.ID, "status": "active"}, fmt.Sprintf("agent %s unquarantined", a.ID))
}
