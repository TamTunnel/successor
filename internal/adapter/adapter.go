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
//	verify-successor <emp-id> <agent-id>
//	                              exit 0 = successor's access holds
//	verify-leaver <emp-id> <agent-id>
//	                              exit 0 = leaver's access is gone
//
// The two verify hooks are separate scripts on purpose. An earlier
// design called one `verify` script for both directions with only the
// employee ID to tell them apart, which made the exit-0 meaning
// ambiguous: a truthful presence-check hook (exit 0 iff the employee
// holds access) was read inverted for the leaver, and a handover
// completed while leaver access was intact. Direction is now part of
// the script name, so a hook can never confuse the two checks. A hook
// directory with only the old single `verify` script fails loudly
// (missing executable) instead of silently misbehaving.
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
//   - Each hook runs with a 60-second timeout, and the timeout bounds
//     wall-clock time: hook output goes to temp files, not pipes, so a
//     hook that spawns descendants holding stdout open cannot stall
//     execution past the timeout, and the whole process group is
//     killed on timeout. A hook that daemonizes (setsid) escapes the
//     group kill but still cannot stall execution, because nothing
//     waits on its output handles.
//   - Hooks run as the invoking user and can therefore read anything
//     that user can read — including the store's audit.key (0600,
//     same UID). A malicious hook that copies the key can sign
//     checkpoints for rewritten history after the last exported
//     checkpoint. Treat hooks as trusted code; see ADAPTERS.md.
package adapter

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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

// maxHookOutput caps captured hook output per stream. A hook that
// prints unbounded output fails the step instead of filling the disk
// or memory; 1 MiB is far above any legitimate hook's output (a
// reference line, a short status message).
const maxHookOutput = 1 << 20

func (s ScriptHook) run(script string, args ...string) (string, string, int, error) {
	return s.runTimeout(script, 60*time.Second, args...)
}

// runTimeout runs one hook with a wall-clock deadline. Output goes to
// temp files, never pipes: with pipes, exec.Cmd.Wait blocks until every
// process holding the pipe ends, so a hook that spawns a descendant
// holding stdout open stalls execution past the timeout (and stalls
// every concurrent store writer behind the store lock). With files,
// Wait returns when the hook process itself exits or is killed, and
// descendants cannot stall anything. On timeout the whole process
// group is killed, so non-daemonized descendants die with the hook.
func (s ScriptHook) runTimeout(script string, timeout time.Duration, args ...string) (string, string, int, error) {
	path := filepath.Join(s.Dir, script)
	outFile, err := os.CreateTemp("", "successor-hook-out-*")
	if err != nil {
		return "", "", -1, fmt.Errorf("hook %s could not run: %w", script, err)
	}
	defer os.Remove(outFile.Name())
	defer outFile.Close()
	errFile, err := os.CreateTemp("", "successor-hook-err-*")
	if err != nil {
		return "", "", -1, fmt.Errorf("hook %s could not run: %w", script, err)
	}
	defer os.Remove(errFile.Name())
	defer errFile.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = outFile
	cmd.Stderr = errFile
	// Own process group so a timeout kill reaches descendants too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		// The context already killed the hook itself; kill the group
		// so descendants do not linger. Best-effort: the group may
		// already be gone, and a setsid escapee is out of reach.
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return "", "", -1, fmt.Errorf("hook %s timed out after %s", script, timeout)
	}
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			stdout, stderr, rerr := readHookOutput(outFile, errFile)
			if rerr != nil {
				return "", "", -1, fmt.Errorf("hook %s output unreadable: %w", script, rerr)
			}
			return stdout, stderr, exitErr.ExitCode(), nil
		}
		return "", "", -1, fmt.Errorf("hook %s could not run: %w", script, runErr)
	}
	stdout, stderr, rerr := readHookOutput(outFile, errFile)
	if rerr != nil {
		return "", "", -1, fmt.Errorf("hook %s output unreadable: %w", script, rerr)
	}
	return stdout, stderr, 0, nil
}

// readHookOutput reads back both temp files, enforcing the per-stream
// cap. Files are read after the hook exits, so a descendant still
// writing to them cannot block the read of what is there.
func readHookOutput(outFile, errFile *os.File) (string, string, error) {
	readCapped := func(f *os.File) (string, error) {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
		b, err := io.ReadAll(io.LimitReader(f, maxHookOutput+1))
		if err != nil {
			return "", err
		}
		if len(b) > maxHookOutput {
			return "", fmt.Errorf("hook output exceeded %d bytes", maxHookOutput)
		}
		return string(b), nil
	}
	stdout, err := readCapped(outFile)
	if err != nil {
		return "", "", err
	}
	stderr, err := readCapped(errFile)
	if err != nil {
		return "", "", err
	}
	return stdout, stderr, nil
}

// scrub checks combined hook output for secret-shaped material. It
// returns the pattern name when found, or "" when clean. Output is never
// returned to callers. The strict scan applies: hook output never
// legitimately contains a bare hash-shaped token.
func scrub(stdout, stderr string) string {
	if name := scan.MatchStrict(stdout); name != "" {
		return name
	}
	if name := scan.MatchStrict(stderr); name != "" {
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

// Verify runs the direction-specific verify hook. kind is the
// checklist item kind and therefore the script name: "verify-successor"
// (exit 0 = the successor's access holds) or "verify-leaver" (exit 0 =
// the leaver's access is gone). The caller passes the item kind
// through unchanged, so the direction can never be confused.
func (s ScriptHook) Verify(kind, ownerID, agentID string) Result {
	stdout, stderr, code, err := s.run(kind, ownerID, agentID)
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
		return Result{Status: "failed", Err: fmt.Sprintf("%s hook exited %d", kind, code)}
	}
}
