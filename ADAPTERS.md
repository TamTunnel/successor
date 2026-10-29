# ADAPTERS.md — credential adapters

Successor orchestrates revoke + re-issue; it never performs them on
secret material itself. Adapters are the two ways outcomes get
recorded: a human working a checklist, or scripts that talk to the
org's real systems. Both paths emit the same audit events and land in
the same states.

## The manual adapter (default)

`handover execute` with no `--adapter` flag uses the checklist the
request generated:

1. `disable schedule` — when the agent has a schedule reference.
2. Per credential, in order: `revoke`, then `re-issue`.
3. `verify successor access`, then `verify leaver access is gone`.

Sign-off rules (`handover checklist <id> --item <n> ...`):

- Exactly one of `--done` or `--waived`.
- `--waived` requires `--reason` (the reason is recorded and, for
  revoke/schedule/verify items, becomes part of the residual risk).
- Signing a re-issue `--done` requires `--new-ref`: the replacement
  reference. `--new-ref` is refused on any other item kind.
- Only an admin who is not the handover's from-owner may sign. The
  person whose access is being revoked cannot attest that it was
  revoked, and neither can an arbitrary bystander: sign-off is a
  trust-bearing attestation, and the audit trail says who attested
  what.
- Execute refuses while any item is still pending, and refuses a
  re-issue marked done without a new reference.
- Outcome semantics at execute time:
  - Revoke done + re-issue done: old grant replaced by the new
    reference (`reissued`).
  - Revoke done + re-issue waived: old grant dead, no replacement.
    Not a security risk; the waiver is recorded.
  - Revoke waived: old grant stays `rotation-required` and the risk is
    named. If a re-issue was still signed done, the new grant is
    recorded alongside the old one — they are different grants.
  - Waived schedule-disable, verify-successor, or verify-leaver each
    add a named residual risk.
  - Any residual risk forces `partial`, never `executed`, and
    `partial` requires explicit acceptance by both the successor and
    the approver (`handover execute --accept-residual-risk`, run by
    each).

The manual adapter makes the record trustworthy. It does not make the
revocation happen by itself — a human must do the checklist items.
That is honest limit 3 in the README.

## The script-hook adapter

`handover execute --adapter script --hook-dir <dir>` runs executables
from the hook directory, one per step. The directory must exist; hooks
must be executable by the invoking user.

| Hook file | Arguments | Exit 0 | Exit 3 | Other non-zero |
| --- | --- | --- | --- | --- |
| `disable-schedule` | `<schedule-ref>` (or agent ID when no ref) | schedule disabled | cannot disable here | step failed, execution stops |
| `revoke` | `<credential-ref>` | grant revoked | cannot revoke here | step failed, execution stops |
| `reissue` | `<credential-ref> <successor-emp-id>` | print the new reference, exactly one line | cannot re-issue here | step failed, execution stops |
| `verify-successor` | `<emp-id> <agent-id>` | the successor's access holds | cannot verify here | step failed, execution stops |
| `verify-leaver` | `<emp-id> <agent-id>` | the leaver's access is gone | cannot verify here | step failed, execution stops |

Contract details:

- **Exit 3 means "unsupported", not "failed".** The item is waived
  with the hook's unsupported reason, and execution continues. A
  waived revoke produces `rotation-required` and a residual risk
  (hence `partial`); a waived re-issue after a successful revoke does
  not. This is how a legacy system with no rotation API is handled
  honestly instead of blocking every handover.
- **Re-issue output must be exactly one reference line.** Anything
  else (empty, multiple lines, a non-reference) fails the step. The
  reference is validated as a reference: single line, no whitespace,
  not secret-shaped.
- **Verify semantics are fixed per script, not per item.** For
  `verify-successor`, exit 0 means the successor's access holds. For
  `verify-leaver`, exit 0 means the leaver's access is gone. The two
  checks are separate scripts precisely so a hook can never confuse
  them: an earlier single-`verify` design passed only the employee ID,
  which made exit 0 ambiguous, and a truthful presence-check hook
  (exit 0 iff the employee holds access) was read inverted for the
  leaver — a handover completed while leaver access was intact. A
  hook directory with only the old single `verify` script fails
  loudly (missing executable) instead of silently misbehaving.
- **Timeout.** Each hook is killed after 60 seconds, and the timeout
  bounds wall-clock execution time: hook output goes to temp files,
  not pipes, so a hook that spawns descendants holding stdout open
  cannot stall execution past the timeout, and the whole process
  group is killed on timeout. A hook that daemonizes (setsid) escapes
  the group kill but still cannot stall execution, because nothing
  waits on its output handles. Captured output is capped at 1 MiB per
  stream; beyond that the step fails.
- **Output is never logged verbatim.** Stdout and stderr are scanned
  for secret-shaped material. If any is found, the step fails, the
  output is discarded, and an `adapter.output-flagged` event records
  only the pattern name — never the output. A hook that prints a
  secret is a hook bug: fix it, then re-run execute.
- **Resume.** Execution stops at the first failed step with state
  still `accepted`. Already-completed items are not re-run on retry;
  their outcomes are folded in and their events are not duplicated.
  Fix the hook (or the target system) and re-run execute.
- **Hooks run as the invoking user.** They inherit that user's
  permissions and nothing else. Successor adds no privilege, no
  sandbox, and no credential handling around them — that boundary is
  the hook author's responsibility. This has one sharp consequence
  worth stating plainly: a hook can read anything the invoking user
  can read, including the store's audit signing key (0600, same UID).
  A malicious hook that copies the key can sign checkpoints for
  rewritten history after the last checkpoint exported before the
  copy — previously exported checkpoints still pin history up to
  their sequence, but nothing after. Treat hooks as trusted code:
  review them before installing, and keep checkpoint exports current.
  Running hooks as a separate user, or moving the key out of hook
  reach, is planned for v1.1.
- **Idempotency for retries.** On a risk-acceptance execute, hooks run
  before both risk acceptances are collected (rotation-required is
  only learned by trying). If the approver never accepts, grants
  changed while ownership did not transfer. Hooks must therefore be
  idempotent: re-running execute after a partial or failed run must
  be safe, and a hook that cannot run twice safely must refuse the
  second run cleanly (exit 3, unsupported, is the honest answer for
  "already done elsewhere").

Minimal example (fake refs, no real systems):

```sh
#!/bin/sh
# hooks/revoke — exit 0 when the grant is revoked, 3 when the target
# system has no revocation API for this grant.
echo "revoking $1 in the example system" >&2
exit 0
```

```sh
#!/bin/sh
# hooks/reissue — print exactly one replacement reference.
echo "vault:example/$1-reissued"
```

## Which adapter when

- Manual: the org's systems have no scriptable revoke/re-issue, or
  the handover is rare enough that a human checklist is the honest
  control. The audit trail records who attested each step.
- Script: the org has APIs or CLIs for its credential systems and
  wants execution to be real instead of attested. The same states,
  risks, and audit events apply; only the source of the outcome
  changes.
