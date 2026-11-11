# finding-port (KAP-07b)

- Engram topic: `odd/finding-port/tasks` (project: `nmap-service`)
- Branch: `feature/finding_port` (off origin/develop)
- Status: done (2026-11-11)
- Sibling repos, same feature id: `broker` (contract), `gateway`, `user-service`.

## Objective

`VulnFinding` carries the port and protocol where it was detected, so `finding.critical` stops sending `port: 0, protocol: "tcp"` and reports can say where a vulnerability is.

## Scope

- `VulnFinding.port: Option<u16>`, `VulnFinding.protocol: Option<Protocol>` (omitted when `None`; absent = host-level/unknown).
- Parser fills them for port-scoped scripts, leaves `None` for `<hostscript>`; enrichers and patch verification leave/keep them.
- `SecurityEvent::finding_critical` takes `Option<u16>`/`Option<Protocol>` and emits `null` for host-level findings.
- Contract parity against the updated broker schemas (`security_event_contract.rs`, new `scan_outcome_contract.rs`).
- Out of scope: attributing enrichment findings to a port; gateway, user-service, front.

## Constraints

- Backward compatible: old Mongo documents and consumers without the fields keep working (`serde(default)`).
- No env mutation in unit tests, no waits. Comments in neutral Spanish, identifiers in English.

## Tooling

- TDD mode: on (source: user global config "Strict TDD Mode: enabled"); runner `make verify`.
- Route: delegated direct, single writer.

## Decisions

- D1 Dedupe: the parser never merges findings across ports (same CVE on two ports = two findings and two events). `merge_enrichment_findings` still dedupes by CVE and drops a port-less enrichment finding when the CVE exists on any port.
- D2 `port: Some(0)` is not produced by the parser; the event schema keeps `minimum: 0` so a not-yet-migrated producer stays valid.
- D3 Enrichment (Exploit-DB/NVD) findings stay port-less: the match is by product/CPE, not by a single port.

## Checklist

| ID | Task | Done |
|---|---|---|
| FP-01 | Feature document | [x] cc599bd |
| FP-02 | RED: tests for the domain fields, parser scoping, patch verification, event payload | [x] `cargo test --lib`: 39 compile errors (fields and signature missing) |
| FP-03 | GREEN: domain, parser, event, contract parity tests | [x] `cargo test --lib`: 258 passed; parity tests pass against broker `feature/finding_port`  09d902d |
| FP-04 | Docs: architecture, ADR-18 | [x] |
| FP-05 | `make verify` | [x] exit 0 |

## Compatibility note

Merge order is free. Against an old broker schema, `scan_outcome_contract.rs` fails only if findings carry a port (the old schema has `additionalProperties: false`), so merge the broker first or together; the `finding.critical` schema change is also required for `null` ports.
