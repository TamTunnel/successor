// Handover commands: request, approve, reject, accept, execute,
// checklist sign-off, list, show. This file enforces the governed state
// machine from the assessment:
//
//	requested -> approved -> accepted -> executed
//	                                      \-> partial (named risks)
//
// Invariants enforced in code, not by convention:
//   - approver holds the approver role and differs from the requester
//   - acceptance needs the one-time token (hash-stored, single-use,
//     72h TTL) plus the successor's employee ID; failures never reveal
//     which part was wrong (no oracle)
//   - execution requires approval + acceptance and a non-expired request
//   - execution re-validates the record at run time: a forged record
//     (approver == requester, approver without the role, approval or
//     acceptance present only in the record and absent from the audit
//     log, departed successor) is refused even if the file says
//     otherwise
//   - acceptance likewise requires a matching approval event in the
//     audit log, so a forged approved record with an attacker-chosen
//     token hash cannot be accepted
//   - a credential that cannot be re-issued lands the handover in
//     partial with the residual risk named, never silently complete
package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"successor/internal/adapter"
	"successor/internal/audit"
	"successor/internal/store"
)

func (c *ctx) cmdHandover(args []string) int {
	if len(args) == 0 {
		return c.fail(fmt.Errorf("usage: successor handover <request|list|show|approve|reject|accept|execute|checklist>"))
	}
	switch args[0] {
	case "request":
		return c.cmdHandoverRequest(args[1:])
	case "list":
		return c.cmdHandoverList(args[1:])
	case "show":
		return c.cmdHandoverShow(args[1:])
	case "approve":
		return c.cmdHandoverApprove(args[1:])
	case "reject":
		return c.cmdHandoverReject(args[1:])
	case "accept":
		return c.cmdHandoverAccept(args[1:])
	case "execute":
		return c.cmdHandoverExecute(args[1:])
	case "checklist":
		return c.cmdHandoverChecklist(args[1:])
	default:
		return c.fail(fmt.Errorf("unknown handover subcommand %q", args[0]))
	}
}

// buildChecklist generates the execution plan from the agent's inventory
// at request time: schedule disable, per-credential revoke + re-issue,
// then successor/leaver access verification. Credentials in scope are
// those live or previously stuck: current, unknown, rotation-required.
// A handover covers the inventory at request time; credentials added
// later are not covered (documented limitation).
func buildChecklist(a store.Agent) []store.ChecklistItem {
	var items []store.ChecklistItem
	if a.ScheduleRef != nil && *a.ScheduleRef != "" {
		items = append(items, store.ChecklistItem{
			Item: "disable schedule: " + *a.ScheduleRef, Kind: "schedule-disable",
			Ref: *a.ScheduleRef, Status: "pending",
		})
	}
	for _, cr := range a.CredentialRefs {
		if cr.Status != "current" && cr.Status != "unknown" && cr.Status != "rotation-required" {
			continue
		}
		items = append(items, store.ChecklistItem{
			Item: "revoke credential: " + cr.Ref, Kind: "revoke", Ref: cr.Ref, Status: "pending",
		})
		items = append(items, store.ChecklistItem{
			Item: "re-issue credential: " + cr.Ref, Kind: "reissue", Ref: cr.Ref, Status: "pending",
		})
	}
	items = append(items, store.ChecklistItem{Item: "verify successor access", Kind: "verify-successor", Status: "pending"})
	items = append(items, store.ChecklistItem{Item: "verify leaver access is gone", Kind: "verify-leaver", Status: "pending"})
	return items
}

func pendingHandoverForAgent(handovers []store.Handover, agentID string) *store.Handover {
	for i, h := range handovers {
		if h.AgentID == agentID && (h.State == "requested" || h.State == "approved" || h.State == "accepted") {
			return &handovers[i]
		}
	}
	return nil
}

func (c *ctx) cmdHandoverRequest(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	agentID, err := f.req("agent")
	if err != nil {
		return c.fail(err)
	}
	to, err := f.req("to")
	if err != nil {
		return c.fail(err)
	}
	reason := f.opt("reason")
	if err := checkClean(reason); err != nil {
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
	a, err := s.LoadAgent(agentID)
	if err != nil {
		return c.fail(err)
	}
	if a.Status == "archived" {
		return c.fail(fmt.Errorf("agent %s is archived and cannot be handed over", agentID))
	}
	toPerson, err := s.LoadPerson(to)
	if err != nil {
		return c.fail(fmt.Errorf("successor %s is not a registered person", to))
	}
	if toPerson.Departed {
		return c.fail(fmt.Errorf("successor %s has departed and cannot receive a handover", to))
	}
	_, handovers, _, err := s.LoadAll()
	if err != nil {
		return c.fail(err)
	}
	if p := pendingHandoverForAgent(handovers, agentID); p != nil {
		return c.fail(fmt.Errorf("agent %s already has a pending handover %s in state %s", agentID, p.ID, p.State))
	}
	id, err := store.GenerateULID()
	if err != nil {
		return c.fail(err)
	}
	now := time.Now().UTC()
	h := store.Handover{
		ID: id, AgentID: agentID, FromOwnerID: a.OwnerID, ToSuccessorID: to,
		RequesterID: actor, State: "requested", Checklist: buildChecklist(a),
		RequestedAt: now.Format(time.RFC3339),
		ExpiresAt:   now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Reason:      reason,
	}
	if err := s.SaveHandover(h); err != nil {
		return c.fail(err)
	}
	detail := map[string]any{"from_owner_id": a.OwnerID, "to_successor_id": to}
	if reason != "" {
		detail["reason"] = reason
	}
	if err := c.auditEvent(s, actor, "handover.requested", agentID, h.ID, detail); err != nil {
		return c.fail(err)
	}
	return c.print(map[string]any{"id": h.ID, "agent_id": agentID, "from_owner_id": a.OwnerID, "to_successor_id": to, "state": "requested", "expires_at": h.ExpiresAt},
		fmt.Sprintf("handover requested: %s (agent %s, %s -> %s, expires %s)", h.ID, agentID, a.OwnerID, to, h.ExpiresAt))
}

func handoverJSON(h store.Handover) map[string]any {
	m := map[string]any{
		"id": h.ID, "agent_id": h.AgentID, "from_owner_id": h.FromOwnerID,
		"to_successor_id": h.ToSuccessorID, "requester_id": h.RequesterID,
		"state": h.State, "checklist": h.Checklist, "residual_risks": h.ResidualRisks,
		"risk_accepted_by": h.RiskAcceptedBy, "requested_at": h.RequestedAt,
		"expires_at": h.ExpiresAt,
	}
	if h.ApproverID != nil {
		m["approver_id"] = *h.ApproverID
	}
	if h.ApprovedAt != nil {
		m["approved_at"] = *h.ApprovedAt
	}
	if h.AcceptedAt != nil {
		m["accepted_at"] = *h.AcceptedAt
	}
	if h.ExecutedAt != nil {
		m["executed_at"] = *h.ExecutedAt
	}
	if h.TokenExpiresAt != nil {
		m["token_expires_at"] = *h.TokenExpiresAt
	}
	if h.Reason != "" {
		m["reason"] = h.Reason
	}
	if h.Adapter != "" {
		m["adapter"] = h.Adapter
	}
	return m
}

func (c *ctx) cmdHandoverList(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	s, err := c.openRead()
	if err != nil {
		return c.fail(err)
	}
	_, handovers, _, err := s.LoadAll()
	if err != nil {
		return c.fail(err)
	}
	statusFilter, agentFilter := f.opt("status"), f.opt("agent")
	sort.Slice(handovers, func(i, j int) bool { return handovers[i].RequestedAt < handovers[j].RequestedAt })
	var rows []map[string]any
	var lines []string
	for _, h := range handovers {
		if statusFilter != "" && h.State != statusFilter {
			continue
		}
		if agentFilter != "" && h.AgentID != agentFilter {
			continue
		}
		rows = append(rows, handoverJSON(h))
		lines = append(lines, fmt.Sprintf("%s agent=%s %s -> %s state=%s", h.ID, h.AgentID, h.FromOwnerID, h.ToSuccessorID, h.State))
	}
	if c.jsonOut {
		return c.print(map[string]any{"handovers": rows}, "")
	}
	return c.print(map[string]any{"handovers": rows}, strings.Join(lines, "\n"))
}

func (c *ctx) cmdHandoverShow(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	if len(f.pos) != 1 {
		return c.fail(fmt.Errorf("usage: successor handover show <handover-id>"))
	}
	s, err := c.openRead()
	if err != nil {
		return c.fail(err)
	}
	h, err := s.LoadHandover(f.pos[0])
	if err != nil {
		return c.fail(err)
	}
	if c.jsonOut {
		return c.print(handoverJSON(h), "")
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("id: %s\nagent: %s\nfrom: %s\nto: %s\nrequester: %s\nstate: %s\nrequested: %s\nexpires: %s\n",
		h.ID, h.AgentID, h.FromOwnerID, h.ToSuccessorID, h.RequesterID, h.State, h.RequestedAt, h.ExpiresAt))
	if h.ApproverID != nil {
		b.WriteString("approver: " + *h.ApproverID + "\n")
	}
	if h.Reason != "" {
		b.WriteString("reason: " + h.Reason + "\n")
	}
	for i, it := range h.Checklist {
		b.WriteString(fmt.Sprintf("checklist %d [%s] %s", i+1, it.Status, it.Item))
		if it.SignedBy != "" {
			b.WriteString(fmt.Sprintf(" (signed by %s)", it.SignedBy))
		}
		if it.Reason != "" {
			b.WriteString(fmt.Sprintf(" (reason: %s)", it.Reason))
		}
		b.WriteString("\n")
	}
	for _, r := range h.ResidualRisks {
		b.WriteString("residual risk: " + r + "\n")
	}
	if len(h.RiskAcceptedBy) > 0 {
		b.WriteString("risk accepted by: " + strings.Join(h.RiskAcceptedBy, ", ") + "\n")
	}
	return c.print(handoverJSON(h), strings.TrimRight(b.String(), "\n"))
}

func (c *ctx) cmdHandoverApprove(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	if len(f.pos) != 1 {
		return c.fail(fmt.Errorf("usage: successor handover approve <handover-id> --approver <emp-id>"))
	}
	approver, err := f.req("approver")
	if err != nil {
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
	actor, err := c.actor(f)
	if err != nil {
		return c.fail(err)
	}
	if actor != approver {
		return c.fail(fmt.Errorf("approver %s must be the actor running the command", approver))
	}
	ap, err := c.knownActor(s, actor)
	if err != nil {
		return c.fail(err)
	}
	if err := requireRole(ap, "approver"); err != nil {
		return c.fail(err)
	}
	h, err := s.LoadHandover(f.pos[0])
	if err != nil {
		return c.fail(err)
	}
	if h.State != "requested" && h.State != "approved" {
		return c.fail(fmt.Errorf("handover %s is %s, not requested or approved", h.ID, h.State))
	}
	if approver == h.RequesterID {
		return c.fail(fmt.Errorf("approver must differ from requester (self-approval refused)"))
	}
	token, hash, err := generateToken()
	if err != nil {
		return c.fail(err)
	}
	now := time.Now().UTC()
	h.ApproverID = strptr(approver)
	h.ApprovedAt = strptr(now.Format(time.RFC3339))
	h.AcceptanceTokenHash = strptr(hash)
	h.TokenExpiresAt = strptr(now.Add(72 * time.Hour).Format(time.RFC3339))
	h.State = "approved"
	if err := s.SaveHandover(h); err != nil {
		return c.fail(err)
	}
	if err := c.auditEvent(s, actor, "handover.approved", h.AgentID, h.ID, map[string]any{"approver_id": approver}); err != nil {
		return c.fail(err)
	}
	human := fmt.Sprintf("handover %s approved by %s\nacceptance token (deliver out-of-band via the org's secure channel, shown once): %s\ntoken expires: %s",
		h.ID, approver, token, *h.TokenExpiresAt)
	return c.print(map[string]any{"id": h.ID, "state": "approved", "approver_id": approver, "acceptance_token": token, "token_expires_at": *h.TokenExpiresAt}, human)
}

func (c *ctx) cmdHandoverReject(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	if len(f.pos) != 1 {
		return c.fail(fmt.Errorf("usage: successor handover reject <handover-id> --approver <emp-id> --reason <text>"))
	}
	approver, err := f.req("approver")
	if err != nil {
		return c.fail(err)
	}
	reason, err := f.req("reason")
	if err != nil {
		return c.fail(err)
	}
	if err := checkClean(reason); err != nil {
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
	actor, err := c.actor(f)
	if err != nil {
		return c.fail(err)
	}
	if actor != approver {
		return c.fail(fmt.Errorf("approver %s must be the actor running the command", approver))
	}
	ap, err := c.knownActor(s, actor)
	if err != nil {
		return c.fail(err)
	}
	if err := requireRole(ap, "approver"); err != nil {
		return c.fail(err)
	}
	h, err := s.LoadHandover(f.pos[0])
	if err != nil {
		return c.fail(err)
	}
	if h.State != "requested" && h.State != "approved" {
		return c.fail(fmt.Errorf("handover %s is %s, not requested or approved", h.ID, h.State))
	}
	if approver == h.RequesterID {
		return c.fail(fmt.Errorf("approver must differ from requester (self-rejection refused)"))
	}
	h.State = "rejected"
	h.ApproverID = strptr(approver)
	if err := s.SaveHandover(h); err != nil {
		return c.fail(err)
	}
	if err := c.auditEvent(s, actor, "handover.rejected", h.AgentID, h.ID, map[string]any{"approver_id": approver, "reason": reason}); err != nil {
		return c.fail(err)
	}
	return c.print(map[string]any{"id": h.ID, "state": "rejected"}, fmt.Sprintf("handover %s rejected by %s", h.ID, approver))
}

func (c *ctx) cmdHandoverAccept(args []string) int {
	f, err := parseFlags(args, nil)
	if err != nil {
		return c.fail(err)
	}
	if len(f.pos) != 1 {
		return c.fail(fmt.Errorf("usage: successor handover accept <handover-id> --token <token> --successor <emp-id>"))
	}
	token, err := f.req("token")
	if err != nil {
		return c.fail(err)
	}
	successor, err := f.req("successor")
	if err != nil {
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
	actor, err := c.actor(f)
	if err != nil {
		return c.fail(err)
	}
	// Every acceptance failure reports the identical message: the caller
	// must not learn whether the token or the successor ID was wrong.
	refuse := func() int {
		h, lerr := s.LoadHandover(f.pos[0])
		if lerr == nil {
			_ = c.auditEvent(s, actor, "handover.accept-refused", h.AgentID, h.ID, map[string]any{"reason": "acceptance refused"})
		}
		return c.fail(fmt.Errorf("acceptance refused"))
	}
	if actor != successor {
		return refuse()
	}
	h, err := s.LoadHandover(f.pos[0])
	if err != nil {
		return c.fail(err)
	}
	if h.State != "approved" {
		return refuse()
	}
	if successor != h.ToSuccessorID {
		return refuse()
	}
	// The successor must still be a live, registered person: accepting
	// as a departed or deleted successor would transfer ownership to
	// someone who cannot hold it. Funnelled through refuse() like every
	// other acceptance failure — no oracle.
	if succ, err := s.LoadPerson(successor); err != nil || succ.Departed {
		return refuse()
	}
	// The approval must exist in the audit log, not just in the mutable
	// record: a hand-edited record claiming approval, with no approved
	// event in the log, is a forgery and is refused here. This is the
	// same cross-check execute performs for acceptance.
	if h.ApproverID == nil {
		return refuse()
	}
	if ok, err := c.auditHasEvent(s, h.ID, "handover.approved", "approver_id", *h.ApproverID); err != nil || !ok {
		return refuse()
	}
	if h.AcceptanceTokenHash == nil {
		return refuse()
	}
	if h.TokenExpiresAt != nil {
		if exp, err := time.Parse(time.RFC3339, *h.TokenExpiresAt); err == nil && time.Now().After(exp) {
			return refuse()
		}
	}
	if !tokenMatches(token, *h.AcceptanceTokenHash) {
		return refuse()
	}
	now := time.Now().UTC().Format(time.RFC3339)
	h.AcceptedAt = strptr(now)
	h.AcceptanceTokenHash = nil // single-use: consumed
	h.TokenExpiresAt = nil
	h.State = "accepted"
	if err := s.SaveHandover(h); err != nil {
		return c.fail(err)
	}
	if err := c.auditEvent(s, actor, "handover.accepted", h.AgentID, h.ID, map[string]any{"successor_id": successor}); err != nil {
		return c.fail(err)
	}
	return c.print(map[string]any{"id": h.ID, "state": "accepted"}, fmt.Sprintf("handover %s accepted by %s", h.ID, successor))
}

func (c *ctx) cmdHandoverChecklist(args []string) int {
	f, err := parseFlags(args, map[string]bool{"done": true, "waived": true})
	if err != nil {
		return c.fail(err)
	}
	if len(f.pos) != 1 {
		return c.fail(fmt.Errorf("usage: successor handover checklist <handover-id> [--item <n> --done|--waived [--reason <text>] [--new-ref <ref>]]"))
	}
	s, err := c.openLocked()
	if err != nil {
		return c.fail(err)
	}
	defer s.Unlock()
	if err := c.sweepExpiry(s); err != nil {
		return c.fail(err)
	}
	h, err := s.LoadHandover(f.pos[0])
	if err != nil {
		return c.fail(err)
	}
	itemFlag := f.opt("item")
	if itemFlag == "" {
		// Show mode: no actor required, read-only output.
		var lines []string
		for i, it := range h.Checklist {
			line := fmt.Sprintf("%d [%s] %s", i+1, it.Status, it.Item)
			if it.SignedBy != "" {
				line += fmt.Sprintf(" (signed by %s)", it.SignedBy)
			}
			if it.Reason != "" {
				line += fmt.Sprintf(" (reason: %s)", it.Reason)
			}
			lines = append(lines, line)
		}
		if c.jsonOut {
			return c.print(handoverJSON(h), "")
		}
		return c.print(handoverJSON(h), strings.Join(lines, "\n"))
	}
	// Sign-off mode.
	var idx int
	if _, err := fmt.Sscanf(itemFlag, "%d", &idx); err != nil || idx < 1 || idx > len(h.Checklist) {
		return c.fail(fmt.Errorf("no checklist item %s", itemFlag))
	}
	it := &h.Checklist[idx-1]
	if it.Status != "pending" {
		return c.fail(fmt.Errorf("checklist item %d is already %s", idx, it.Status))
	}
	done, waived := f.bools["done"], f.bools["waived"]
	if done == waived {
		return c.fail(fmt.Errorf("sign-off requires exactly one of --done or --waived"))
	}
	actor, err := c.actor(f)
	if err != nil {
		return c.fail(err)
	}
	ap, err := c.knownActor(s, actor)
	if err != nil {
		return c.fail(err)
	}
	// Sign-off is a trust-bearing attestation, not a clerical mark. The
	// signer must hold the admin role and must not be the handover's
	// from-owner: the person whose access is being revoked cannot attest
	// that it was revoked, and neither can an arbitrary bystander.
	if err := requireRole(ap, "admin"); err != nil {
		return c.fail(err)
	}
	if actor == h.FromOwnerID {
		return c.fail(fmt.Errorf("the handover's from-owner cannot sign off its own checklist items"))
	}
	newRef := f.opt("new-ref")
	reason := f.opt("reason")
	if done {
		if it.Kind == "reissue" {
			if newRef == "" {
				return c.fail(fmt.Errorf("signing a re-issue done requires --new-ref"))
			}
			if err := checkRef(newRef, true); err != nil {
				return c.fail(err)
			}
			it.NewRef = newRef
		} else if newRef != "" {
			return c.fail(fmt.Errorf("--new-ref only applies to re-issue items"))
		}
		it.Status = "done"
	} else {
		if reason == "" {
			return c.fail(fmt.Errorf("waiving an item requires --reason"))
		}
		if err := checkClean(reason); err != nil {
			return c.fail(err)
		}
		it.Status = "waived"
		it.Reason = reason
	}
	it.SignedBy = actor
	it.SignedAt = store.NowUTC()
	if err := s.SaveHandover(h); err != nil {
		return c.fail(err)
	}
	detail := map[string]any{"item_index": idx, "kind": it.Kind, "status": it.Status, "signed_by": actor}
	if it.Ref != "" {
		detail["ref"] = it.Ref
	}
	if it.NewRef != "" {
		detail["new_ref"] = it.NewRef
	}
	if err := c.auditEvent(s, actor, "handover.checklist-signed", h.AgentID, h.ID, detail); err != nil {
		return c.fail(err)
	}
	return c.print(map[string]any{"id": h.ID, "item": idx, "status": it.Status},
		fmt.Sprintf("checklist item %d marked %s by %s", idx, it.Status, actor))
}

// auditHasEvent reports whether the audit log contains an event with
// the given action for this handover whose detail carries the expected
// key/value pair. It loads (parses) the log but does not verify the
// chain: a forged record is caught by the absence of the event, and a
// tampered chain is the audit-verify command's job. A log that cannot
// be loaded fails closed (false with an error).
func (c *ctx) auditHasEvent(s *store.Store, handoverID, action, detailKey, detailValue string) (bool, error) {
	log := &audit.Log{Path: s.AuditPath()}
	events, err := log.Load()
	if err != nil {
		return false, err
	}
	for _, e := range events {
		if e.HandoverID != handoverID || e.Action != action {
			continue
		}
		if detailKey == "" {
			return true, nil
		}
		if v, ok := e.Detail[detailKey]; ok && v == detailValue {
			return true, nil
		}
	}
	return false, nil
}

// validateExecutable re-checks every handover invariant at execution
// time. A forged record (approver == requester, approver without the
// role, missing acceptance) is refused even if the file claims
// otherwise. This is what makes probe 1 pass.
//
// The audit log is cross-checked, not just the record: approval and
// acceptance must each have a matching event in the log (with the
// approver/successor the record names). A hand-edited record claiming
// approval and acceptance, with zero such events in the log, is refused
// here. This defeats record-only forgery; it does not defeat an
// attacker who can also forge log entries, which is why store write
// access remains the trust boundary and checkpoints remain the
// off-box anchor (see README honest limits).
func (c *ctx) validateExecutable(s *store.Store, h store.Handover) error {
	if h.State != "accepted" {
		return fmt.Errorf("handover %s is %s, not accepted", h.ID, h.State)
	}
	if h.ApproverID == nil {
		return fmt.Errorf("handover %s has no approver", h.ID)
	}
	approver, err := s.LoadPerson(*h.ApproverID)
	if err != nil {
		return fmt.Errorf("handover %s approver is not a registered person", h.ID)
	}
	if !approver.HasRole("approver") {
		return fmt.Errorf("handover %s approver lacks the approver role", h.ID)
	}
	if *h.ApproverID == h.RequesterID {
		return fmt.Errorf("handover %s approver equals requester (self-approval)", h.ID)
	}
	if h.AcceptedAt == nil {
		return fmt.Errorf("handover %s was never accepted", h.ID)
	}
	// The successor must still be a live, registered person at
	// execution time: executing to a departed successor would transfer
	// ownership to someone who cannot hold it.
	succ, err := s.LoadPerson(h.ToSuccessorID)
	if err != nil {
		return fmt.Errorf("handover %s successor is not a registered person", h.ID)
	}
	if succ.Departed {
		return fmt.Errorf("handover %s successor has departed", h.ID)
	}
	// Approval and acceptance must be in the audit log, not just the
	// record. (A departed approver mid-flight is not refused here:
	// approval is a point-in-time act, and the approver was live when
	// it was given.)
	if ok, err := c.auditHasEvent(s, h.ID, "handover.approved", "approver_id", *h.ApproverID); err != nil {
		return fmt.Errorf("handover %s audit log cannot be read: %w", h.ID, err)
	} else if !ok {
		return fmt.Errorf("handover %s has no matching approval in the audit log (record-only approval refused)", h.ID)
	}
	if ok, err := c.auditHasEvent(s, h.ID, "handover.accepted", "successor_id", h.ToSuccessorID); err != nil {
		return fmt.Errorf("handover %s audit log cannot be read: %w", h.ID, err)
	} else if !ok {
		return fmt.Errorf("handover %s has no matching acceptance in the audit log (record-only acceptance refused)", h.ID)
	}
	if exp, err := time.Parse(time.RFC3339, h.ExpiresAt); err == nil && time.Now().After(exp) {
		return fmt.Errorf("handover %s is expired", h.ID)
	}
	return nil
}

// executeState carries per-execution mutable state while items are
// applied in order.
type executeState struct {
	agent  store.Agent
	result map[string]*credResult // by original credential ref
	risks  []string
}

// credResult accumulates the outcome for one credential across its
// revoke and re-issue items, in whatever order they were signed.
// A waived revoke plus a done re-issue is coherent: the old grant is
// still live (rotation-required) and the new grant also exists. The
// two must not collapse into one another.
type credResult struct {
	revoked          bool
	rotationRequired bool
	newRef           string
	kind             string
}

func (es *executeState) res(ref string) *credResult {
	r, ok := es.result[ref]
	if !ok {
		r = &credResult{}
		es.result[ref] = r
	}
	return r
}

func (es *executeState) addRisk(r string) {
	for _, e := range es.risks {
		if e == r {
			return
		}
	}
	es.risks = append(es.risks, r)
}

// computeItemOutcome folds one signed-off checklist item into the
// execution state without emitting events. Event emission is separate
// (emitItemOutcome) so a retry — e.g. the second execute run that
// accepts residual risks — does not duplicate per-item audit events:
// handover.EventsEmitted records how many items already had their
// outcome events written, and retries skip those.
func computeItemOutcome(it store.ChecklistItem, es *executeState) {
	switch it.Kind {
	case "schedule-disable":
		if it.Status == "waived" {
			es.addRisk(fmt.Sprintf("schedule was not disabled during handover: %s", it.Reason))
		}
	case "revoke":
		r := es.res(it.Ref)
		if it.Status == "done" {
			r.revoked = true
		} else {
			r.rotationRequired = true
			es.addRisk(fmt.Sprintf("credential %s is rotation-required: %s", it.Ref, it.Reason))
		}
	case "reissue":
		if it.Status == "done" {
			r := es.res(it.Ref)
			kind := "generic"
			for _, cr := range es.agent.CredentialRefs {
				if cr.Ref == it.Ref {
					kind = cr.Kind
				}
			}
			r.kind = kind
			r.newRef = it.NewRef
		}
		// Waived re-issue after a revoke: the old grant is dead, so this
		// is an operational loss, not a security residual risk. Recorded
		// via the checklist waiver itself; no risk entry.
	case "verify-successor":
		if it.Status == "waived" {
			es.addRisk(fmt.Sprintf("successor access was not verified: %s", it.Reason))
		}
	case "verify-leaver":
		if it.Status == "waived" {
			es.addRisk(fmt.Sprintf("leaver access was not verified gone: %s", it.Reason))
		}
	}
}

// emitItemOutcome writes the catalog event for one applied item.
func (c *ctx) emitItemOutcome(s *store.Store, actor string, h store.Handover, it store.ChecklistItem, es *executeState) error {
	switch it.Kind {
	case "schedule-disable":
		if it.Status == "done" {
			return c.auditEvent(s, actor, "schedule.disabled", h.AgentID, h.ID, map[string]any{"schedule_ref": it.Ref})
		}
	case "revoke":
		if it.Status == "done" {
			return c.auditEvent(s, actor, "credential.revoked", h.AgentID, h.ID, map[string]any{"ref": it.Ref})
		}
		return c.auditEvent(s, actor, "credential.rotation-required", h.AgentID, h.ID, map[string]any{"ref": it.Ref, "reason": it.Reason})
	case "reissue":
		if it.Status == "done" {
			return c.auditEvent(s, actor, "credential.reissued", h.AgentID, h.ID, map[string]any{"ref": it.NewRef, "previous_ref": it.Ref})
		}
	case "verify-successor":
		if it.Status == "done" {
			return c.auditEvent(s, actor, "access.verified", h.AgentID, h.ID, map[string]any{"direction": "successor", "employee_id": h.ToSuccessorID})
		}
		return c.auditEvent(s, actor, "access.verification-waived", h.AgentID, h.ID, map[string]any{"direction": "successor", "employee_id": h.ToSuccessorID, "reason": it.Reason})
	case "verify-leaver":
		if it.Status == "done" {
			return c.auditEvent(s, actor, "access.verified", h.AgentID, h.ID, map[string]any{"direction": "leaver", "employee_id": h.FromOwnerID})
		}
		return c.auditEvent(s, actor, "access.verification-waived", h.AgentID, h.ID, map[string]any{"direction": "leaver", "employee_id": h.FromOwnerID, "reason": it.Reason})
	}
	return nil
}

func (c *ctx) cmdHandoverExecute(args []string) int {
	f, err := parseFlags(args, map[string]bool{"accept-residual-risk": true})
	if err != nil {
		return c.fail(err)
	}
	if len(f.pos) != 1 {
		return c.fail(fmt.Errorf("usage: successor handover execute <handover-id> [--adapter manual|script] [--hook-dir <dir>] [--accept-residual-risk]"))
	}
	adapterName := f.opt("adapter")
	if adapterName == "" {
		adapterName = "manual"
	}
	if adapterName != "manual" && adapterName != "script" {
		return c.fail(fmt.Errorf("unknown adapter %q (manual or script)", adapterName))
	}
	hookDir := f.opt("hook-dir")
	if adapterName == "script" {
		if hookDir == "" {
			return c.fail(fmt.Errorf("script adapter requires --hook-dir"))
		}
		if st, err := os.Stat(hookDir); err != nil || !st.IsDir() {
			return c.fail(fmt.Errorf("hook dir %q is not a directory", hookDir))
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
	h, err := s.LoadHandover(f.pos[0])
	if err != nil {
		return c.fail(err)
	}
	// Who may execute depends on the mode. Plain execution is an admin
	// act. Execution that accepts residual risks is an act of the two
	// parties who bear the risk — the successor and the approver —
	// who are normally not admins. Gating risk acceptance on the admin
	// role would make the partial flow unusable.
	if f.bools["accept-residual-risk"] {
		if actor != h.ToSuccessorID && (h.ApproverID == nil || actor != *h.ApproverID) {
			return c.fail(fmt.Errorf("only the successor or the approver may accept residual risks"))
		}
	} else if err := requireRole(ap, "admin"); err != nil {
		return c.fail(err)
	}
	// Execute re-validates the record: forged approvals fail here.
	if err := c.validateExecutable(s, h); err != nil {
		_ = c.auditEvent(s, actor, "handover.execute-refused", h.AgentID, h.ID, map[string]any{"reason": err.Error()})
		return c.fail(err)
	}
	agent, err := s.LoadAgent(h.AgentID)
	if err != nil {
		return c.fail(err)
	}
	if agent.Status == "archived" {
		_ = c.auditEvent(s, actor, "handover.execute-refused", h.AgentID, h.ID, map[string]any{"reason": "agent is archived"})
		return c.fail(fmt.Errorf("agent %s is archived", h.AgentID))
	}
	h.Adapter = adapterName
	h.HookDir = hookDir
	es := &executeState{
		agent: agent, result: map[string]*credResult{},
	}
	// Seed risks already recorded on the handover (from a prior run).
	for _, r := range h.ResidualRisks {
		es.addRisk(r)
	}

	if adapterName == "manual" {
		for _, it := range h.Checklist {
			if it.Status == "pending" {
				_ = c.auditEvent(s, actor, "handover.execute-refused", h.AgentID, h.ID, map[string]any{"reason": "checklist incomplete"})
				return c.fail(fmt.Errorf("checklist incomplete: sign off every item (successor handover checklist %s) before executing", h.ID))
			}
			if it.Kind == "reissue" && it.Status == "done" && it.NewRef == "" {
				_ = c.auditEvent(s, actor, "handover.execute-refused", h.AgentID, h.ID, map[string]any{"reason": "re-issue item done without a new reference"})
				return c.fail(fmt.Errorf("re-issue item %q is done without a new reference", it.Item))
			}
		}
		for i, it := range h.Checklist {
			computeItemOutcome(it, es)
			if i >= h.EventsEmitted {
				if err := c.emitItemOutcome(s, actor, h, it, es); err != nil {
					return c.fail(err)
				}
				// Persist per item, like the script path: if the
				// process dies mid-loop, a retry skips the events
				// already written instead of duplicating them.
				h.EventsEmitted = i + 1
				if err := s.SaveHandover(h); err != nil {
					return c.fail(err)
				}
			}
		}
		if err := s.SaveHandover(h); err != nil {
			return c.fail(err)
		}
	} else {
		hooks := adapter.ScriptHook{Dir: hookDir}
		for i := range h.Checklist {
			it := &h.Checklist[i]
			if it.Status != "pending" {
				// Already applied by a prior run: fold its outcome in
				// (idempotent resume) without re-emitting its event.
				computeItemOutcome(*it, es)
				continue
			}
			var res adapter.Result
			switch it.Kind {
			case "schedule-disable":
				target := it.Ref
				if target == "" {
					target = h.AgentID
				}
				res = hooks.DisableSchedule(target)
			case "revoke":
				res = hooks.Revoke(it.Ref)
			case "reissue":
				res = hooks.Reissue(it.Ref, h.ToSuccessorID)
			case "verify-successor":
				res = hooks.Verify(it.Kind, h.ToSuccessorID, h.AgentID)
			case "verify-leaver":
				res = hooks.Verify(it.Kind, h.FromOwnerID, h.AgentID)
			}
			if res.Flagged {
				_ = c.auditEvent(s, actor, "adapter.output-flagged", h.AgentID, h.ID, map[string]any{"kind": it.Kind, "ref": it.Ref, "pattern": res.FlagPattern})
				if err := s.SaveHandover(h); err != nil {
					return c.fail(err)
				}
				return c.fail(fmt.Errorf("execution stopped: %s (hook output flagged, output discarded)", res.Err))
			}
			switch res.Status {
			case "done":
				it.Status = "done"
				it.SignedBy = "script-hook"
				it.SignedAt = store.NowUTC()
				if it.Kind == "reissue" {
					it.NewRef = res.NewRef
				}
				computeItemOutcome(*it, es)
				if err := c.emitItemOutcome(s, actor, h, *it, es); err != nil {
					return c.fail(err)
				}
				h.EventsEmitted = i + 1
				if err := s.SaveHandover(h); err != nil {
					return c.fail(err)
				}
			case "unsupported":
				it.Status = "waived"
				it.Reason = res.Err
				it.SignedBy = "script-hook"
				it.SignedAt = store.NowUTC()
				computeItemOutcome(*it, es)
				if err := c.emitItemOutcome(s, actor, h, *it, es); err != nil {
					return c.fail(err)
				}
				h.EventsEmitted = i + 1
				if err := s.SaveHandover(h); err != nil {
					return c.fail(err)
				}
			default: // failed
				if err := s.SaveHandover(h); err != nil {
					return c.fail(err)
				}
				_ = c.auditEvent(s, actor, "handover.execute-refused", h.AgentID, h.ID, map[string]any{"reason": res.Err, "kind": it.Kind, "ref": it.Ref})
				return c.fail(fmt.Errorf("execution stopped at %q: %s (state stays accepted; retries resume from this step)", it.Item, res.Err))
			}
		}
	}

	// Rebuild the agent's credential list from outcomes.
	var newCreds []store.CredentialRef
	for _, cr := range agent.CredentialRefs {
		r, inScope := es.result[cr.Ref]
		if !inScope {
			newCreds = append(newCreds, cr) // untouched by this handover
			continue
		}
		if r.rotationRequired {
			// Old grant still live and stuck; a new grant created
			// alongside it is recorded too — the two are not the same
			// credential and must not collapse.
			cr.Status = "rotation-required"
			newCreds = append(newCreds, cr)
			if r.newRef != "" {
				newCreds = append(newCreds, store.CredentialRef{Ref: r.newRef, Kind: r.kind, Status: "reissued"})
			}
			continue
		}
		if r.revoked {
			if r.newRef != "" {
				newCreds = append(newCreds, store.CredentialRef{Ref: r.newRef, Kind: r.kind, Status: "reissued"})
			}
			// Revoked with no replacement: the grant is dead, so it
			// leaves the record.
			continue
		}
		// Neither outcome recorded (defensive: execute requires every
		// item signed or processed, so this should not happen).
		newCreds = append(newCreds, cr)
	}
	agent.CredentialRefs = newCreds

	// Capture the config hash at handover time when the config reference
	// resolves to a local file. Other references stay references.
	if agent.ConfigRef != nil {
		if b, err := os.ReadFile(*agent.ConfigRef); err == nil {
			sum := sha256.Sum256(b)
			agent.ConfigHash = strptr(hex.EncodeToString(sum[:]))
		}
	}

	now := store.NowUTC()
	if len(es.risks) > 0 {
		// Partial requires explicit acceptance of the named risks by
		// BOTH the successor and the approver.
		if f.bools["accept-residual-risk"] {
			if actor != h.ToSuccessorID && (h.ApproverID == nil || actor != *h.ApproverID) {
				return c.fail(fmt.Errorf("only the successor or the approver may accept residual risks"))
			}
			found := false
			for _, a := range h.RiskAcceptedBy {
				if a == actor {
					found = true
				}
			}
			if !found {
				h.RiskAcceptedBy = append(h.RiskAcceptedBy, actor)
			}
		}
		hasSuccessor, hasApprover := false, false
		for _, a := range h.RiskAcceptedBy {
			if a == h.ToSuccessorID {
				hasSuccessor = true
			}
			if h.ApproverID != nil && a == *h.ApproverID {
				hasApprover = true
			}
		}
		h.ResidualRisks = es.risks
		if !hasSuccessor || !hasApprover {
			if err := s.SaveHandover(h); err != nil {
				return c.fail(err)
			}
			var missing []string
			if !hasSuccessor {
				missing = append(missing, "successor "+h.ToSuccessorID)
			}
			if !hasApprover {
				missing = append(missing, "approver")
			}
			return c.fail(fmt.Errorf("handover has residual risks and stays accepted; still needs acceptance from: %s (re-run execute with --accept-residual-risk as each)", strings.Join(missing, ", ")))
		}
		// Both accepted: land in partial, never silently complete.
		agent.OwnerID = h.ToSuccessorID
		agent.Status = "active"
		if err := s.SaveAgent(agent); err != nil {
			return c.fail(err)
		}
		h.State = "partial"
		h.ExecutedAt = strptr(now)
		if err := s.SaveHandover(h); err != nil {
			return c.fail(err)
		}
		if err := c.auditEvent(s, actor, "handover.partial", h.AgentID, h.ID, map[string]any{
			"to_owner_id": h.ToSuccessorID, "residual_risks": es.risks, "accepted_by": h.RiskAcceptedBy,
		}); err != nil {
			return c.fail(err)
		}
		if err := c.auditEvent(s, actor, "agent.updated", h.AgentID, "", map[string]any{"owner_id": h.ToSuccessorID}); err != nil {
			return c.fail(err)
		}
		if err := s.BumpGeneration(); err != nil {
			return c.fail(err)
		}
		return c.print(map[string]any{"id": h.ID, "state": "partial", "to_owner_id": h.ToSuccessorID, "residual_risks": es.risks},
			fmt.Sprintf("handover %s PARTIAL: agent %s now owned by %s, with residual risks:\n  - %s", h.ID, h.AgentID, h.ToSuccessorID, strings.Join(es.risks, "\n  - ")))
	}

	// Clean completion.
	agent.OwnerID = h.ToSuccessorID
	agent.Status = "active"
	if err := s.SaveAgent(agent); err != nil {
		return c.fail(err)
	}
	h.State = "executed"
	h.ExecutedAt = strptr(now)
	h.ResidualRisks = nil
	if err := s.SaveHandover(h); err != nil {
		return c.fail(err)
	}
	counts := map[string]int{}
	for _, cr := range agent.CredentialRefs {
		counts[cr.Status]++
	}
	var parts []string
	for _, st := range []string{"reissued", "revoked", "rotation-required", "current", "unknown"} {
		if counts[st] > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", st, counts[st]))
		}
	}
	if err := c.auditEvent(s, actor, "handover.executed", h.AgentID, h.ID, map[string]any{
		"to_owner_id": h.ToSuccessorID, "credential_status": strings.Join(parts, ","),
	}); err != nil {
		return c.fail(err)
	}
	if err := c.auditEvent(s, actor, "agent.updated", h.AgentID, "", map[string]any{"owner_id": h.ToSuccessorID}); err != nil {
		return c.fail(err)
	}
	if err := s.BumpGeneration(); err != nil {
		return c.fail(err)
	}
	return c.print(map[string]any{"id": h.ID, "state": "executed", "to_owner_id": h.ToSuccessorID},
		fmt.Sprintf("handover %s executed: agent %s now owned by %s", h.ID, h.AgentID, h.ToSuccessorID))
}
