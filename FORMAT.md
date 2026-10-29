# FORMAT.md — store, record, and audit formats

This is the wire format contract. Anything that reads or verifies a
Successor store without the binary — an auditor's script, a future
version — should be able to rely on this document.

## Store layout

```
<store>/
  meta.json            # Meta record (below)
  audit.key            # Ed25519 private key, hex, 0600
  audit.pub            # Ed25519 public key, hex, 0644
  audit.jsonl          # hash-chained events, one JSON object per line
  agents/<ulid>.json
  handovers/<ulid>.json
  persons/<emp-id>.json
  keys/<key-id>.pub    # archived public keys (hex) after rotation
  .lock                # exclusive lockfile
```

All JSON records are pretty-printed with two-space indent and a
trailing newline. All writes are temp file + fsync + rename under the
exclusive lock. Backups are a plain directory copy; restore is copying
it back (see the generation tripwire below).

## IDs and timestamps

- Agent and handover IDs are ULIDs: 26 Crockford base32 characters,
  48-bit millisecond timestamp + 80-bit cryptographic randomness, first
  character 0–7. They sort chronologically.
- Person IDs are employee IDs as the org already uses them (example
  data uses `E-1001`): letters, digits, `-`, `_`, `.`, never `.`/`..`
  or containing `..` (so an ID can never escape its directory).
- Timestamps are UTC RFC3339 (`2026-10-29T00:11:00Z`).
  - Recorded timestamps (created, updated, requested, approved,
    accepted, executed, checklist signed) must not be in the future
    (one minute of clock-skew allowance). A future recorded timestamp
    fails validation.
  - Deadline timestamps (`expires_at`, `token_expires_at`) may be in
    the future; they are validated for shape only.
- Records are validated strictly on load (ULID validity, ID == file
  name, enum values, timestamp rules, token-hash shape, duplicate-ID
  refusal). Validation never repairs: a malformed record fails loud
  and every command refuses to open the store until it is fixed.

## Records

### Meta (`meta.json`)

```json
{"version": 1, "created_at": "2026-10-29T00:11:00Z", "key_id": "8f953aaa92fb8a58", "generation": 1}
```

- `key_id`: first 16 hex characters of SHA-256 over the current audit
  public key bytes.
- `generation`: starts at 1; increments on every executed or partial
  handover and on every audit key rotation. Checkpoints carry the
  generation they were signed at; a checkpoint newer than the store
  means the store predates it (for example, a restored backup), and
  verification fails.

### Person (`persons/<emp-id>.json`)

```json
{"id": "E-1001", "display_name": "Alex Example", "roles": ["approver"],
 "departed": false, "created_at": "2026-10-29T00:11:00Z"}
```

Roles are a subset of `admin`, `approver`. A departed person cannot
act: every mutating command refuses a departed actor.

### Agent (`agents/<ulid>.json`)

```json
{
  "id": "01M62FXSK9ZDRD9AZGZRA2BKXC", "name": "deploy-bot",
  "owner_id": "E-1001", "status": "active", "runtime": "cron",
  "config_ref": "s3://example-configs/deploy-bot.yaml",
  "config_hash": "4f3c... (sha256 hex, captured at handover time, when the config reference resolves to a local file)",
  "runbook_ref": null, "schedule_ref": "cron:nightly-deploy",
  "credential_refs": [
    {"ref": "prod-key-1", "kind": "iam", "status": "current"}
  ],
  "created_at": "2026-10-29T00:11:00Z", "updated_at": "2026-10-29T00:11:00Z"
}
```

- `status`: `active` | `quarantined` | `archived`.
- Credential `status`: `current` | `reissued` | `revoked` |
  `rotation-required` | `unknown`. (`revoked` grants leave the record
  on execution — a dead grant is not inventory.)
- `config_hash` is captured at handover execution time, only when the
  config reference resolves to a readable local file. Other references
  stay references: the tool never fetches remote config.
- Credential references are references, never secret material: a
  reference is non-empty, single-line, whitespace-free, and not
  secret-shaped. Anything else is refused at input.

### Checklist item (embedded in a handover)

```json
{"item": "revoke credential: prod-key-1", "kind": "revoke", "ref": "prod-key-1",
 "status": "done", "reason": "", "signed_by": "E-1009",
 "signed_at": "2026-10-29T00:12:00Z", "new_ref": ""}
```

- `kind`: `schedule-disable` | `revoke` | `reissue` |
  `verify-successor` | `verify-leaver`.
- `status`: `pending` | `done` | `waived`. Waiving requires a reason;
  signing a re-issue done requires `--new-ref`.
- Checklist indices as printed by `handover checklist` are 1-based.

### Handover (`handovers/<ulid>.json`)

```json
{
  "id": "01M62FXSNHQC6HMC8SVWR5C634", "agent_id": "01M62FXSK9ZDRD9AZGZRA2BKXC",
  "from_owner_id": "E-1001", "to_successor_id": "E-1002",
  "requester_id": "E-1009", "approver_id": "E-1010",
  "state": "accepted",
  "acceptance_token_hash": "9f2a... (64 hex chars, SHA-256 of the token; null after acceptance)",
  "token_expires_at": "2026-11-01T00:11:00Z",
  "checklist": ["<items above>"],
  "residual_risks": [], "risk_accepted_by": [],
  "requested_at": "2026-10-29T00:11:00Z", "approved_at": null,
  "accepted_at": null, "executed_at": null,
  "expires_at": "2026-11-05T00:11:00Z",
  "adapter": "manual", "hook_dir": "",
  "events_emitted": 0, "reason": "E-1001 departing"
}
```

- `state`: `requested` | `approved` | `accepted` | `executed` |
  `partial` | `rejected` | `expired`.
- `acceptance_token_hash` is the one documented exception to "hashes
  of references only": it is the hash of a single-use random value,
  not of credential material, and it is what makes token verification
  possible without storing the token. The token itself (32 hex
  characters, 16 cryptographic random bytes) is printed once at
  approval and never stored.
- `events_emitted` counts checklist items whose outcome audit events
  were already written. Execute retries fold in all outcomes but skip
  those events, so a retry never duplicates per-item events.
- Handover TTL is 7 days from request; the acceptance token TTL is
  72 hours from approval. Overdue handovers in `requested`, `approved`,
  or `accepted` transition to `expired` (audited) at the start of the
  next mutating command.

## Audit log (`audit.jsonl`)

One JSON object per line, in chain order. Field order is fixed: it is
part of the canonical hash input.

```json
{"seq": 7, "ts": "2026-10-29T00:12:00Z", "actor_id": "E-1009",
 "action": "credential.revoked", "agent_id": "01M62FXSK9ZDRD9AZGZRA2BKXC",
 "handover_id": "01M62FXSNHQC6HMC8SVWR5C634",
 "detail": {"ref": "prod-key-1"},
 "prev_hash": "a91f...", "hash": "c44d..."}
```

- `seq` starts at 1 and increments by exactly 1 per event; the first
  event is the genesis event (`actor_id` `system`, action
  `audit.genesis`, `prev_hash` 64 zeros).
- `hash` is SHA-256 over the canonical JSON of the event with the
  `hash` field removed (struct field order as above, map keys sorted
  — Go's `encoding/json` on the event struct). `prev_hash` is the
  previous event's `hash`.
- Verification recomputes the chain from genesis and reports the first
  bad sequence number. A chain that verifies proves this copy of the
  log has not been altered since it was written. It does NOT prove a
  full-store rewrite did not happen — only a checkpoint does.
- Detail values are references, statuses, counts, and reasons only.
  Writes are refused when a detail contains secret-shaped material
  (well-known secret shapes: private-key blocks, vendor API key
  formats, bearer tokens, password assignments) or a forbidden field
  name (`secret`, `password`, `passwd`, `private_key`,
  `credential_value`). A refused write appends nothing, and the error
  names the rule violated, never the matched material.

### Event catalog

Assessment catalog (all recorded, no sampling): `agent.registered`,
`agent.updated`, `agent.archived`, `handover.requested`,
`handover.approved`, `handover.rejected`, `handover.accepted`,
`handover.executed` (per-credential outcome summary),
`handover.partial` (rotation-required credentials, risk acceptors),
`handover.expired`, `credential.revoked`, `credential.reissued`,
`credential.rotation-required`, `schedule.disabled`,
`schedule.re-enabled` (reserved: no v1 flow emits it, because
schedule re-enable is not automated in v1).

V1 extensions in the same chain: `audit.genesis`, `person.added`,
`person.departed`, `agent.quarantined`, `agent.unquarantined`,
`handover.checklist-signed`, `handover.execute-refused`,
`handover.accept-refused` (generic detail, no oracle),
`audit.checkpoint` (seq/hash/key_id/generation — never the signature),
`audit.key-rotated` (old/new key IDs), `audit.verified` (pass/fail of
a verification run, only when `--actor` is given),
`adapter.output-flagged` (kind/ref/pattern name only).

### Checkpoints

A checkpoint is a signed `(seq, hash)` pair meant to be stored
off-box:

```json
{"seq": 42, "hash": "c44d...", "signature": "1a2b... (hex Ed25519)",
 "key_id": "8f953aaa92fb8a58", "generation": 2}
```

- Signed message, exactly: `successor-checkpoint-v1:<seq>:<hash>:<generation>`.
- Verification checks, in order: checkpoint generation is not newer
  than the store generation; the signature verifies against the
  public key for `key_id` (current key, or an archived key from
  `keys/<key-id>.pub` after rotation); the chain passes through
  `(seq, hash)` — the event at that sequence number carries that hash.
- `audit checkpoint` prints the checkpoint as JSON (and to `--out`
  when given) and records an `audit.checkpoint` event carrying
  seq/hash/key_id/generation, never the signature — the signature
  lives off-box.
- `audit export` is a byte copy of the log, not a re-render: the
  exported file hashes identically to the on-disk log.
- Key rotation (`audit rotate-key`, admin-only) generates a new
  keypair, archives the old public key to `keys/<old-key-id>.pub`,
  updates meta, and bumps generation. Checkpoints signed under the
  old key remain verifiable against the archived key.
