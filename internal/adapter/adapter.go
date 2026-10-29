// Package adapter implements the two MVP credential adapters.
//
// Manual adapter (default): the handover checklist is signed off by a
// human with confirmation commands. The CLI applies signed-off outcomes;
// this package performs no credential operation for manual handovers.
//
// Script-hook adapter: the org supplies one executable per action in a
// hook directory:
//
//	revoke <ref>                  exit 0 = revoked
//	reissue <ref> <owner-id>      exit 0 = re-issued; stdout must be exactly
//	                              the new reference on a single line
//	disable-schedule <target>     exit 0 = schedule disabled
//	verify <owner-id> <agent-id>  exit 0 = checked state holds (successor
//	                              HAS access / leaver has NO access — the
//	                              hook author implements the check)
//
// Exit code 3 from any hook means "unsupported": the target system cannot
// perform this action, which routes the credential to rotation-required
// (honest partial) instead of failing the whole execution. Any other
// non-zero exit means failure: execution stops, state stays accepted.
//
// Security contract, enforced here, not by convention:
//   - Hooks receive references only, never secret material.
//   - Hook stdout/stderr is NEVER logged verbatim. Only the exit status
//     and a reference are recorded.
//   - Output is scanned for secret-shaped material. If found, the run is
//     flagged, the output is discarded, and the step fails. The flag is
//     audited (pattern name only, never the output).
//   - Each hook runs with a 60-second timeout.
package adapter

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"successor/internal/scan"
)

// Result is the outcome of one adapter action.
type Result struct {
	// Status: "done", "unsupported", or "failed".
	Status string
	// NewRef is set by a successful reissue: the replacement reference.
	NewRef string
	// Flagged reports secret-shaped material in hook output. The output
	// itself is discarded and never returned.
	Flagged bool
	// FlagPattern names the detected pattern, never the matched text.
	FlagPattern string
	// Err describes a failure without including hook output.
	Err string
}

// ScriptHook invokes executables from a hook directory.
type ScriptHook struct {
	Dir string
}

func (s ScriptHook) run(script string, args ...string) (string, string, int, error) {
	path := filepath.Join(s.Dir, script)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			return "", "", -1, fmt.Errorf("hook %s timed out after 60s", script)
		} else {
			return "", "", -1, fmt.Errorf("hook %s could not run: %w", script, err)
		}
	}
	return stdout.String(), stderr.String(), code, nil
}

// scrub checks combined hook output for secret-shaped material. It
// returns the pattern name when found, or "" when clean. Output is never
// returned to callers.
func scrub(stdout, stderr string) string {
	if name := scan.Match(stdout); name != "" {
		return name
	}
	if name := scan.Match(stderr); name != "" {
		return name
	}
	return ""
}

// Revoke runs the revoke hook for a credential reference.
func (s ScriptHook) Revoke(ref string) Result {
	stdout, stderr, code, err := s.run("revoke", ref)
	if err != nil {
		return Result{Status: "failed", Err: err.Error()}
	}
	if name := scrub(stdout, stderr); name != "" {
		return Result{Status: "failed", Flagged: true, FlagPattern: name, Err: "hook output contained secret-shaped material; output discarded"}
	}
	switch code {
	case 0:
		return Result{Status: "done"}
	case 3:
		return Result{Status: "unsupported", Err: "target system cannot revoke this grant"}
	default:
		return Result{Status: "failed", Err: fmt.Sprintf("revoke hook exited %d", code)}
	}
}

// Reissue runs the reissue hook. On success the hook prints exactly the
// new reference on a single line; anything else fails the step.
func (s ScriptHook) Reissue(ref, ownerID string) Result {
	stdout, stderr, code, err := s.run("reissue", ref, ownerID)
	if err != nil {
		return Result{Status: "failed", Err: err.Error()}
	}
	if name := scrub(stdout, stderr); name != "" {
		return Result{Status: "failed", Flagged: true, FlagPattern: name, Err: "hook output contained secret-shaped material; output discarded"}
	}
	switch code {
	case 0:
		lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
		if len(lines) != 1 || !scan.IsReference(strings.TrimSpace(lines[0])) {
			return Result{Status: "failed", Err: "reissue hook must print exactly one reference on a single line"}
		}
		return Result{Status: "done", NewRef: strings.TrimSpace(lines[0])}
	case 3:
		return Result{Status: "unsupported", Err: "target system cannot re-issue this grant"}
	default:
		return Result{Status: "failed", Err: fmt.Sprintf("reissue hook exited %d", code)}
	}
}

// DisableSchedule runs the disable-schedule hook.
func (s ScriptHook) DisableSchedule(target string) Result {
	stdout, stderr, code, err := s.run("disable-schedule", target)
	if err != nil {
		return Result{Status: "failed", Err: err.Error()}
	}
	if name := scrub(stdout, stderr); name != "" {
		return Result{Status: "failed", Flagged: true, FlagPattern: name, Err: "hook output contained secret-shaped material; output discarded"}
	}
	switch code {
	case 0:
		return Result{Status: "done"}
	case 3:
		return Result{Status: "unsupported", Err: "target system cannot disable this schedule"}
	default:
		return Result{Status: "failed", Err: fmt.Sprintf("disable-schedule hook exited %d", code)}
	}
}

// Verify runs the verify hook: exit 0 means the checked state holds.
func (s ScriptHook) Verify(ownerID, agentID string) Result {
	stdout, stderr, code, err := s.run("verify", ownerID, agentID)
	if err != nil {
		return Result{Status: "failed", Err: err.Error()}
	}
	if name := scrub(stdout, stderr); name != "" {
		return Result{Status: "failed", Flagged: true, FlagPattern: name, Err: "hook output contained secret-shaped material; output discarded"}
	}
	switch code {
	case 0:
		return Result{Status: "done"}
	case 3:
		return Result{Status: "unsupported", Err: "target system cannot verify this access"}
	default:
		return Result{Status: "failed", Err: fmt.Sprintf("verify hook exited %d", code)}
	}
}
