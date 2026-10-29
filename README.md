# Successor

## The problem

When an employee who built internal agents leaves, those agents don't
leave with them. They keep running — on schedules, with credentials,
under an owner who is gone. Somebody has to answer for what they do
next, and somebody has to make sure the leaver's access to them is
actually dead. In most orgs that handover is a ticket, a chat message,
and hope. There is no record of who approved it, no proof the
credentials were rotated, and no way to tell afterward whether the
leaver can still get in.

## The solution, in plain terms

Successor is a small command-line tool that governs the handover and
records it. An admin registers each agent — what it is, who owns it,
where its config and runbook live, and references to its credentials
(never the credentials themselves). When the owner leaves, an admin
requests a handover to a named successor. A different person, holding
the approver role, approves it. The successor accepts with a one-time
token delivered outside the tool. Then the credentials are revoked and
re-issued under the successor (by a human checklist or by scripts),
the schedule is disabled, and both the successor's and the leaver's
access are verified. Every step lands in a hash-chained audit log, and
signed checkpoints can be stored off the machine so that even a full
rewrite of the log is detectable.

The one rule the whole tool is built around: **Successor never sees,
stores, logs, or transmits secret material.** It records references
and outcomes only. If a credential cannot be re-issued, the handover
lands in `partial` with the residual risk named and explicitly
accepted by both the successor and the approver — never silently
`complete`.

## Honest limits

Read these before trusting the tool. They are the product's real
boundaries, not fine print.

1. Successor cannot hand over agents it does not know about. Inventory
   completeness is the org's responsibility; `report orphans` helps
   find gaps but cannot prove there are none.
2. Successor cannot un-know a secret the leaver copied. Rotation is
   the only cure; where rotation is impossible, the risk is named, not
   hidden.
3. Without an adapter that can actually revoke, re-issue, and disable,
   a handover is a governed record, not enforcement. The manual adapter
   makes the record trustworthy; it does not make the revocation happen
   by itself — a human must do the checklist items.
4. The audit trail detects tampering against an independently held
   checkpoint. Without exported checkpoints, a full-store rewrite is
   undetectable. Export checkpoints off-box.
5. Actor identity is asserted, not authenticated, in v1. On a shared
   admin box, `--actor` is only as trustworthy as the box's own access
   control. Do not deploy Successor on a box where untrusted users can
   invoke it as arbitrary actors.
6. A successor who accepts an agent accepts responsibility for its
   future actions, not omniscience about its past. Knowledge transfer
   is human work; the tool records that it was accepted, not that it
   was understood.
7. The audit signing key lives on the box at mode 0600. Anyone who
   fully compromises the admin box gets the key along with the log and
   could rewrite history and re-sign checkpoints — unless a checkpoint
   was already exported off-box before the compromise, in which case
   the rewrite is still detectable. Treat the signing key as sensitive.
   External-key custody (key held outside the store) is planned for
   v1.1.

## Quick start

Build once, copy the binary to the admin box. No runtime to install.

```sh
go build -o dist/successor .
```

All examples below use clearly fake data from the worked example: org
"Example Internal", admin E-1009, leaver E-1001, successor E-1002,
approver E-1010.

```sh
# 1. Create the store (one Ed25519 audit keypair, on-box at 0600).
successor --store ~/.successor init --admin E-1009 --admin-name "Admin Example"

# 2. Register people and the agent (credential REFERENCES only).
successor --store ~/.successor person add --actor E-1009 --id E-1001 --name "Alex Example"
successor --store ~/.successor person add --actor E-1009 --id E-1002 --name "Sam Sample"
successor --store ~/.successor person add --actor E-1009 --id E-1010 --name "Approver Example" --approver
successor --store ~/.successor agent register --actor E-1009 \
  --name deploy-bot --owner E-1001 --runtime cron \
  --credential-ref "iam:prod-key-1" --credential-ref "vendor:legacy-key" \
  --schedule-ref "cron:nightly-deploy"
```

Mutating commands need an actor: `--actor <emp-id>` or the
`SUCCESSOR_ACTOR` environment variable. There is no anonymous mode.

```sh
# 3. Request, approve, accept. The token is printed once and must be
#    delivered to the successor through the org's secure channel —
#    the tool never messages it.
successor --store ~/.successor handover request --actor E-1009 \
  --agent <agent-id> --to E-1002 --reason "E-1001 departing"
successor --store ~/.successor handover approve <handover-id> --actor E-1010 --approver E-1010
successor --store ~/.successor handover accept <handover-id> \
  --actor E-1002 --successor E-1002 --token <one-time-token>

# 4. Work the checklist (manual adapter): disable the schedule, revoke
#    and re-issue each credential, verify both sides' access.
successor --store ~/.successor handover checklist <handover-id>
successor --store ~/.successor handover checklist <handover-id> --item 1 --done --actor E-1009
successor --store ~/.successor handover checklist <handover-id> --item 2 --done --actor E-1009
successor --store ~/.successor handover checklist <handover-id> --item 3 --done \
  --new-ref "iam:prod-key-2" --actor E-1009
# ... sign every item. Waiving needs a reason:
successor --store ~/.successor handover checklist <handover-id> --item 4 --waived \
  --reason "legacy vendor key has no rotation API" --actor E-1009

# 5. Execute. With a waived revoke, this stops and names the residual
#    risks; the successor and then the approver each accept them.
successor --store ~/.successor handover execute <handover-id> --actor E-1009
successor --store ~/.successor handover execute <handover-id> --actor E-1002 --accept-residual-risk
successor --store ~/.successor handover execute <handover-id> --actor E-1010 --accept-residual-risk
# -> PARTIAL: agent owned by E-1002, legacy-key rotation-required, risk named.

# 6. Prove the log is intact, and export a checkpoint off-box.
successor --store ~/.successor audit verify
successor --store ~/.successor audit checkpoint --actor E-1009 --out /secure/off-box/cp.json
successor --store ~/.successor audit verify --checkpoint /secure/off-box/cp.json
```

The script adapter replaces step 4 with hooks; see ADAPTERS.md.

```sh
successor --store ~/.successor handover execute <handover-id> --actor E-1009 \
  --adapter script --hook-dir ./hooks
```

## Architecture

Single static Go binary, standard library only. No database server,
no dependencies to audit or go stale. The store is a directory of
JSON files plus a hash-chained JSONL audit log:

```
<store>/
  meta.json            # version, created_at, key_id, generation
  audit.key            # Ed25519 private key, 0600
  audit.pub            # Ed25519 public key
  audit.jsonl          # hash-chained events
  agents/<ulid>.json
  handovers/<ulid>.json
  persons/<emp-id>.json
  keys/<key-id>.pub    # archived public keys after rotation
  .lock                # exclusive lockfile; writers serialize
```

Writes are temp file + fsync + rename under the exclusive lock.
Records are validated strictly on load and never auto-repaired: a
malformed record fails loud. Timestamps that record when something
happened must not be in the future; deadlines (handover expiry, token
expiry) may be. See FORMAT.md for the full schemas and chain format.

### The state machine

```
requested -> approved -> accepted -> executed
                                    \-> partial (named risks)
requested/approved -> rejected
requested/approved/accepted -> expired (7-day handover TTL, swept on
  the next mutating command)
```

- Request requires an admin actor. One pending handover per agent;
  concurrent requests serialize on the lock, so exactly one wins.
- Approve requires the actor to be the named approver, hold the
  approver role, and differ from the requester. Re-approval from
  `approved` regenerates the token. Approval mints a 32-hex-character
  one-time token (72h TTL); only its SHA-256 hash is stored, and the
  hash is cleared on successful acceptance.
- Accept requires the actor to equal the successor, the successor to
  equal the handover's named successor, and a valid unexpired token.
  Every failure reports the identical message ("acceptance refused")
  and audits a generic refusal — no oracle for which part was wrong.
- Execute re-validates every invariant at run time (approver role,
  approver != requester, acceptance recorded, not expired, agent not
  archived), so a forged record is refused even if the file claims
  otherwise. Execution applies checklist outcomes in order, emits one
  audit event per credential outcome, transfers ownership, and bumps
  the store generation. Retries resume idempotently and never
  duplicate per-item events.
- Partial requires explicit acceptance of the named risks by BOTH the
  successor and the approver, via `handover execute
  --accept-residual-risk` run by each. Risk acceptance is deliberately
  not an admin act: the parties who bear the risk accept it.

### Design decisions the assessment left open

- **Risk acceptance command.** The assessment requires acceptance by
  successor and approver but names no command; this build uses
  `handover execute --accept-residual-risk`, run once by each party.
- **Quarantine is admin-command-only** (`agent quarantine` /
  `unquarantine`). The assessment's "quarantine at execution if the
  successor has not yet accepted" contradicts execute requiring
  acceptance, so quarantine is an explicit admin act instead.
- **Departed actors cannot act.** After `person depart`, that employee
  ID is refused for every mutation, which is what makes "leaver access
  is gone" hold inside the tool as well as in the grants.
- **Waived re-issue after a successful revoke is not a security risk.**
  The old grant is dead; the waiver is recorded, and `executed` is
  still reachable. A waived revoke is what creates residual risk.
- **A waived revoke plus a done re-issue keeps both credentials.** The
  old grant stays `rotation-required` and the new grant is recorded as
  `reissued`; they are not the same credential and must not collapse.
- **The checklist covers the inventory at request time.** Credentials
  added to the agent after the request are not covered by that
  handover.
- **Schedule re-enable is not automated in v1.** No hook or checklist
  item exists for it; the successor re-enables the schedule per the
  runbook after verifying access.
- **Extra audit events** beyond the assessment's catalog, all in the
  same chain: `audit.genesis`, `person.added`, `person.departed`,
  `agent.quarantined`, `agent.unquarantined`,
  `handover.checklist-signed`, `handover.execute-refused`,
  `handover.accept-refused`, `audit.checkpoint`, `audit.key-rotated`,
  `audit.verified`, `adapter.output-flagged`.

### Commands

```
successor init [--admin <emp-id>] [--admin-name <name>]
successor person add --id <emp-id> --name <name> [--admin] [--approver]
successor person list
successor person depart <emp-id>
successor agent register --name <n> --owner <emp-id> --runtime <desc>
  [--config-ref <ref>] [--runbook-ref <ref>] [--schedule-ref <ref>]
  [--credential-ref <kind:ref>]...
successor agent list [--owner <emp-id>] [--status <s>]
successor agent show <agent-id>
successor agent archive <agent-id>
successor agent quarantine <agent-id>
successor agent unquarantine <agent-id>
successor handover request --agent <id> --to <emp-id> [--reason <text>]
successor handover list [--status <s>] [--agent <id>]
successor handover show <handover-id>
successor handover approve <handover-id> --approver <emp-id>
successor handover reject <handover-id> --approver <emp-id> --reason <text>
successor handover accept <handover-id> --token <token> --successor <emp-id>
successor handover execute <handover-id> [--adapter manual|script]
  [--hook-dir <dir>] [--accept-residual-risk]
successor handover checklist <handover-id> [--item <n> --done|--waived
  [--reason <text>] [--new-ref <ref>]]
successor audit verify [--checkpoint <file>] [--actor <emp-id>]
successor audit export --out <file>
successor audit checkpoint [--out <file>]
successor audit rotate-key
successor report orphans
successor report stale
```

Global flags, anywhere in the argument list: `--store <dir>` (default
`~/.successor`), `--json` (machine-readable output). Exit code is 0 on
success, 1 on any refusal or error; refusals never echo secret-shaped
input.

## FAQs

**Why not just hand the vault over to the successor?**
Because the leaver may hold a copy. Vault handoff moves access; it
does not kill the leaver's copy. Only revoke + re-issue does that, and
where re-issue is impossible the honest answer is `partial` with the
risk named — not a quiet `complete`.

**Why a CLI and not a web UI?**
The users run it on hardened admin boxes where installing a runtime
is restricted or forbidden. Distribution is copying one static
binary. There is no built-in auth in v1 by design; the box's own
access control is the boundary (see honest limit 5).

**Why is the audit key on the box at all?**
Because v1 has no external-key option yet. The key at 0600 plus
regular off-box checkpoints is the honest v1 answer: a compromise
after a checkpoint export is still detectable. External-key custody
is v1.1.

**What happens if a hook prints a secret?**
The run stops, the output is discarded (never logged, never shown),
and an `adapter.output-flagged` event records only the pattern name.
Fix the hook, then re-run execute; it resumes from the failed step.

**What happens if two admins race to request a handover?**
The store lock serializes writers; the second request sees the
pending handover and is refused. Exactly one wins.

**Can a handover be re-run after it completes?**
No. `executed` and `partial` are terminal. A new handover can be
requested later (for example, to retry a `rotation-required`
credential — it re-enters the checklist).

## Best practices (repo hygiene)

```sh
go build -o dist/successor .   # build output lives in dist/ only
go vet ./...
gofmt -l internal/ main.go     # must print nothing
go test ./...                  # 29 top-level tests, 33 with subtests
```

- Never leave compiled artifacts next to sources.
- Never commit real identifiers, real credential references, or
  secret-shaped material — examples in code, tests, and docs are
  clearly fake, and `TestZeroSecretGrep` proves no shipped file
  contains secret-shaped content (it runs the tool's own detector over
  every file).
- `ASSESSMENT.md` is the input spec and stays untracked; it is never
  committed.
- License: Apache 2.0 (see LICENSE).

## License

Apache 2.0. See LICENSE.
