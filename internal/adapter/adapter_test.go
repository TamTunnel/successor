package adapter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeHook(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
}

func TestRunTimeoutDirectHang(t *testing.T) {
	// A hook that hangs must fail at the timeout, not at its own
	// sleep's end: the timeout bounds wall-clock time.
	dir := t.TempDir()
	writeHook(t, dir, "revoke", "sleep 30")
	h := ScriptHook{Dir: dir}
	start := time.Now()
	_, _, _, err := h.runTimeout("revoke", 2*time.Second)
	elapsed := time.Since(start)
	if elapsed > 20*time.Second {
		t.Fatalf("hanging hook returned after %s, want near the 2s timeout", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("hanging hook error = %v, want a timeout error", err)
	}
}

func TestRunTimeoutGrandchildCannotStall(t *testing.T) {
	// A hook that spawns a descendant holding stdout open must not
	// stall execution: output goes to files, not pipes, so Wait
	// returns when the hook itself exits.
	dir := t.TempDir()
	writeHook(t, dir, "revoke", "sleep 20 &\nexit 0")
	h := ScriptHook{Dir: dir}
	start := time.Now()
	_, _, code, err := h.runTimeout("revoke", 60*time.Second)
	elapsed := time.Since(start)
	if elapsed > 15*time.Second {
		t.Fatalf("grandchild-holding-stdout hook returned after %s, want prompt return", elapsed)
	}
	if err != nil || code != 0 {
		t.Fatalf("grandchild hook result code=%d err=%v, want done", code, err)
	}
}

func TestVerifyDirectionScripts(t *testing.T) {
	// Verify-successor and verify-leaver are distinct scripts with
	// distinct exit-0 meanings; the old single "verify" script no
	// longer exists as a hook name.
	dir := t.TempDir()
	writeHook(t, dir, "verify-successor", "exit 0")
	writeHook(t, dir, "verify-leaver", "exit 1")
	h := ScriptHook{Dir: dir}
	if res := h.Verify("verify-successor", "E-1002", "agent-1"); res.Status != "done" {
		t.Fatalf("verify-successor result = %+v, want done", res)
	}
	if res := h.Verify("verify-leaver", "E-1001", "agent-1"); res.Status != "failed" {
		t.Fatalf("verify-leaver result = %+v, want failed", res)
	}
	// A directory with only the legacy single verify script fails
	// loudly instead of silently misbehaving.
	legacy := t.TempDir()
	writeHook(t, legacy, "verify", "exit 0")
	hl := ScriptHook{Dir: legacy}
	if res := hl.Verify("verify-leaver", "E-1001", "agent-1"); res.Status != "failed" {
		t.Fatalf("legacy verify dir result = %+v, want failed (missing script)", res)
	}
}
