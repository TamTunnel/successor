// Report commands: orphans and stale.
//
// Reports are read-only views over the store. They exist because the
// handover story does not end at execution: orphans (agents whose
// owner left or whose handover expired) and stale items (credentials
// stuck rotation-required, handovers awaiting risk acceptance) are
// exactly the residue a leaver handover program must keep visible,
// or the next departure inherits an unowned agent with live grants.
package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"successor/internal/audit"
	"successor/internal/store"
)

func (c *ctx) cmdReport(args []string) int {
	if len(args) == 0 {
		return c.fail(fmt.Errorf("usage: successor report <orphans|stale>"))
	}
	switch args[0] {
	case "orphans":
		return c.cmdReportOrphans(args[1:])
	case "stale":
		return c.cmdReportStale(args[1:])
	default:
		return c.fail(fmt.Errorf("unknown report subcommand %q", args[0]))
	}
}

// cmdReportOrphans lists agents with no live owner: owner record
// missing, owner departed, or an expired handover that never completed.
func (c *ctx) cmdReportOrphans(args []string) int {
	if _, err := parseFlags(args, nil); err != nil {
		return c.fail(err)
	}
	s, err := c.openRead()
	if err != nil {
		return c.fail(err)
	}
	agents, handovers, persons, err := s.LoadAll()
	if err != nil {
		return c.fail(err)
	}
	byID := map[string]store.Person{}
	for _, p := range persons {
		byID[p.ID] = p
	}
	expiredFor := map[string]bool{}
	for _, h := range handovers {
		if h.State == "expired" {
			expiredFor[h.AgentID] = true
		}
	}
	type orphan struct {
		agentID, agentName, reason string
	}
	var rows []orphan
	for _, a := range agents {
		if a.Status == "archived" {
			continue
		}
		owner, ok := byID[a.OwnerID]
		switch {
		case !ok:
			rows = append(rows, orphan{a.ID, a.Name, fmt.Sprintf("owner %s is not a registered person", a.OwnerID)})
		case owner.Departed:
			rows = append(rows, orphan{a.ID, a.Name, fmt.Sprintf("owner %s has departed", a.OwnerID)})
		case expiredFor[a.ID]:
			rows = append(rows, orphan{a.ID, a.Name, "handover expired before completion"})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].agentID < rows[j].agentID })
	var out []map[string]any
	var lines []string
	for _, r := range rows {
		out = append(out, map[string]any{"agent_id": r.agentID, "agent_name": r.agentName, "reason": r.reason})
		lines = append(lines, fmt.Sprintf("%s (%s): %s", r.agentID, r.agentName, r.reason))
	}
	if len(lines) == 0 {
		lines = []string{"no orphaned agents"}
	}
	return c.print(map[string]any{"orphans": out}, strings.Join(lines, "\n"))
}

// cmdReportStale lists residue that needs a human: credentials stuck
// rotation-required, expired handovers, and accepted handovers waiting
// on residual-risk acceptance.
func (c *ctx) cmdReportStale(args []string) int {
	if _, err := parseFlags(args, nil); err != nil {
		return c.fail(err)
	}
	s, err := c.openRead()
	if err != nil {
		return c.fail(err)
	}
	agents, handovers, _, err := s.LoadAll()
	if err != nil {
		return c.fail(err)
	}
	// Accepted handovers with a recorded failed execution are stuck:
	// execution stopped (e.g. a hook failed) and the handover never
	// completed, but nothing else in the stale report names them.
	// The audit log is the record of failures; a log that cannot be
	// read fails the report rather than silently omitting them.
	failedExecution := map[string]bool{}
	log := &audit.Log{Path: s.AuditPath()}
	if events, err := log.Load(); err != nil {
		return c.fail(err)
	} else {
		for _, e := range events {
			if e.Action == "handover.execute-refused" && e.HandoverID != "" {
				failedExecution[e.HandoverID] = true
			}
		}
	}
	var lines []string
	var items []map[string]any
	for _, a := range agents {
		for _, cr := range a.CredentialRefs {
			if cr.Status == "rotation-required" {
				lines = append(lines, fmt.Sprintf("credential %s on agent %s (%s) is rotation-required", cr.Ref, a.ID, a.Name))
				items = append(items, map[string]any{"type": "credential-rotation-required", "agent_id": a.ID, "ref": cr.Ref})
			}
		}
	}
	now := time.Now()
	for _, h := range handovers {
		switch h.State {
		case "expired":
			lines = append(lines, fmt.Sprintf("handover %s for agent %s expired", h.ID, h.AgentID))
			items = append(items, map[string]any{"type": "handover-expired", "handover_id": h.ID, "agent_id": h.AgentID})
		case "accepted":
			if failedExecution[h.ID] {
				lines = append(lines, fmt.Sprintf("handover %s for agent %s has a recorded failed execution and is still accepted (fix the failure and re-run execute)", h.ID, h.AgentID))
				items = append(items, map[string]any{"type": "handover-failed-execution", "handover_id": h.ID, "agent_id": h.AgentID})
			}
			if len(h.ResidualRisks) > 0 {
				missing := []string{}
				hasS, hasA := false, false
				for _, a := range h.RiskAcceptedBy {
					if a == h.ToSuccessorID {
						hasS = true
					}
					if h.ApproverID != nil && a == *h.ApproverID {
						hasA = true
					}
				}
				if !hasS {
					missing = append(missing, "successor "+h.ToSuccessorID)
				}
				if !hasA {
					missing = append(missing, "approver")
				}
				lines = append(lines, fmt.Sprintf("handover %s for agent %s awaits residual-risk acceptance from: %s", h.ID, h.AgentID, strings.Join(missing, ", ")))
				items = append(items, map[string]any{"type": "handover-awaits-risk-acceptance", "handover_id": h.ID, "agent_id": h.AgentID, "missing": missing})
			}
		case "requested", "approved":
			if exp, err := time.Parse(time.RFC3339, h.ExpiresAt); err == nil && exp.Before(now.Add(24*time.Hour)) {
				lines = append(lines, fmt.Sprintf("handover %s for agent %s expires within 24h (%s)", h.ID, h.AgentID, h.ExpiresAt))
				items = append(items, map[string]any{"type": "handover-expiring-soon", "handover_id": h.ID, "agent_id": h.AgentID, "expires_at": h.ExpiresAt})
			}
		}
	}
	if len(lines) == 0 {
		lines = []string{"nothing stale"}
	}
	return c.print(map[string]any{"stale": items}, strings.Join(lines, "\n"))
}
