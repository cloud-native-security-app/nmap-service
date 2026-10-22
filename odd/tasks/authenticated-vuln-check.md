# authenticated-vuln-check

- Engram topic: `odd/authenticated-vuln-check/tasks` (project: `nmap-service`)
- Branch: `feature/authenticated_vuln_check` (off origin/develop)
- Status: in progress (2026-10-22) — core slice (nmap-service) first; plumbing (gateway/user-service/front) follows
- Spans: nmap-service (core), gateway + user-service + front (additive field plumbing)

## Objective

Turn noisy version-match "posibles" into honest results by asking the target
itself whether each matched CVE is actually unpatched or already fixed by a
distro backport, over the SSH session the scan already uses.

## Key architecture note (2026-10-22)

nmap-service is ALREADY an authenticated scanner. `ScanRequest` carries
`network_user` + `ssh_credentials_ref` + `has_sudo`; `src/ssh.rs` provides
`connect` (host-key TOFU) and `RemoteSession::run_command`; `pipeline.rs
run_stages` does connect → scanner.run_scan (nmap over SSH) → parser::parse →
enricher.enrich (best-effort) → repository.save. The SSH session is open and
`run_command(&self)` is reusable AFTER the scan. So this feature is a NEW
best-effort stage, not new SSH/credential work.

## Decision (user, 2026-10-22): "Filtrar las corregidas"

Per version_match ("posible") finding with a CVE id, after the authenticated check:
- **unpatched** → promote to Confirmadas (`confidence: Confirmed`) and mark `patch_state: Unpatched`.
- **backport-fixed / not-pending** → mark `patch_state: Fixed`; KEEP it in the stored/exported data, but the front HIDES it from the report and shows a "N descartadas por backport" count.
- **unverified** (no package manager, unknown distro, command failed/timed out) → leave as-is (`version_match`, posible). Best-effort: NEVER fail the scan (same contract as enrichment).

`patch_state` is a NEW additive optional field on `VulnFinding`
(`#[serde(default, skip_serializing_if = "Option::is_none")]`), mirroring how
`confidence` was shipped. Deploy order: gateway first (its types deny unknown
fields), then nmap-service, then front; user-service stores it verbatim.

## Reconciliation strategy (RPM-first)

1. Detect distro once: `cat /etc/os-release`, read `ID`/`ID_LIKE`. RPM family =
   amzn/rhel/fedora/centos/rocky/almalinux. Non-RPM (debian/ubuntu) → unverified
   for now (apt/dpkg is a later slice); unknown → unverified.
2. One bounded command for the pending-CVE set: `dnf updateinfo list cves`
   (fallback `yum updateinfo list cves`). It lists CVEs with an AVAILABLE
   (unapplied) security update. Parse the CVE ids out.
3. Classify each version_match CVE: in the pending set → **unpatched**; not in
   the set → **fixed** (the installed package already carries the fix, or the
   CVE does not apply). CVEs without a CVE id are left unverified.
4. Everything read-only; `has_sudo` not required. Reuse the session's configured
   timeouts. A non-zero exit / empty / error output → unverified (never invent a
   verdict).

## Tasks

- [x] AVC-01 (nmap-service, CORE) `patch_state: Option<PatchState>` on `VulnFinding` (`Unpatched` | `Fixed`, snake_case, additive/optional). Old documents deserialize unchanged.
- [x] AVC-02 (nmap-service, CORE) A `PatchVerifier` port + an RPM adapter: detect distro via `/etc/os-release`, run `dnf updateinfo list cves` once, parse the pending-CVE set, and reconcile the `version_match` findings per the decision above. Pure parsing/classification unit-tested against recorded command outputs (AL2023/RHEL shapes); the distro-detect + command orchestration tested with a fake `RemoteSession`.
- [x] AVC-03 (nmap-service, CORE) Wire it as a best-effort stage in `run_stages` AFTER parse+enrichment and BEFORE save, reusing the open `session`. A failure/timeout logs (no credentials) and leaves findings untouched; never turns the scan into `Failed`. Save/publish carries the reconciled findings.
- [x] AVC-04 (gateway) Accept `patch_state` on its `VulnFinding` (deny_unknown_fields) and relay it untouched. Deploy BEFORE nmap-service. DONE: commit 07a196b (domain.rs field + PatchState enum + OpenAPI; 3 tests incl. unknown-value rejection). Branch feature/patch_state_plumbing.
- [x] AVC-05 (user-service) Confirm it stores the reconciled result verbatim (JSONB) — likely no code change; add a guard test if cheap. DONE: commit 37937c0. Verbatim JSONB (StoredScanResult.result = serde_json::Value), no prod change; added testcontainers round-trip guard.
- [x] AVC-06 (front) Hide `patch_state == "fixed"` findings from the report lists, show a "N descartadas por backport" count (expandable or a note); show `patch_state == "unpatched"` confirmed findings with a "sin parche" note. Export keeps everything. DONE: commit d1d2480. Filter before dedupe/counts; dismissedByBackportNote; "· sin parche" qualifier; export untouched; 64 report+guard tests green.

## Acceptance criteria

- A version_match CVE present in `dnf updateinfo list cves` becomes Confirmed/unpatched; one absent from it becomes `fixed` and is hidden in the report but present in the export; with no dnf / unknown distro / command failure every version_match stays a "posible". The scan never fails because of this stage.

## Checks

Strict TDD (recorded `os-release` + `dnf updateinfo list cves` outputs; fake `RemoteSession`); `make verify` (nmap-service), `make verify` (gateway/user-service), `npm run verify` (front). Live validation against an RPM target (e.g. the weak-config EC2 / an AL2023 host) is a follow-up once deployed.

## Risks / notes

- `dnf updateinfo` only reflects configured repos; an air-gapped or
  repo-less host yields an empty set → everything would look "fixed". Guard:
  if the pending-set command errors OR the distro has no usable repo metadata,
  treat as UNVERIFIED, not "fixed". (Document the heuristic's limits.)
- The fixture shapes are modeled from dnf/os-release docs unless captured from a
  live AL2023 host; flag which in the evidence.
- Keep credentials out of logs (ssh.rs already guarantees this; the new stage
  must not log command output that could contain sensitive data).

## Evidence

### nmap-service CORE (AVC-01..03), 2026-10-22

- AVC-01: `PatchState { Unpatched, Fixed }` + `VulnFinding.patch_state` (`serde(default, skip_serializing_if)`). Tests: omit-when-none/snake_case round-trip, and a pre-field document deserializes with `None`. RED was compile-level (types did not exist); all existing constructors got `patch_state: None`.
- AVC-02: `src/patch_verify.rs` (`PatchVerifier` port, `RpmPatchVerifier`, pure `is_rpm_family` / `parse_pending_cves` / `reconcile`). RED observed: 14 tests failing on `todo!()` stubs; GREEN: 14/14.
- AVC-03: `ServicePorts.patch_verifier` wired in `run_stages` after the enrichment merge and before `repository.save`, reusing `session`; concrete `RpmPatchVerifier` wired in `src/wiring.rs`. RED was compile-level (trait not imported / field missing); GREEN: 2 new pipeline tests (reconciled findings are saved; verifier error never fails the scan and leaves findings untouched).
- `make verify`: exit 0; 212 lib tests passed; Docker integration suites (`--ignored`) also ran and passed.
- Fixture provenance: MODELED, not captured live. `/etc/os-release` shapes follow `os-release(5)`; `dnf updateinfo list cves` lines (`CVE-... Severity/Sec. nevra`) follow the DNF updateinfo docs. Revalidate against a real AL2023 / RHEL 9 capture before relying on it in production.
- Empty-output decision: `dnf` exit 0 with NO CVEs is treated as UNVERIFIED (`SkipReason::EmptyPendingSet`), never mass-marked `Fixed`, because an air-gapped / repo-less host answers identically to a fully patched one. Known limitation: a fully patched host therefore gets no `Fixed` verdicts.
- Best-effort: the stage only logs counts (`unpatched/fixed/unverified/skipped`) or a warn with the error and correlation_id; no stdout/stderr/credentials are logged; it never returns `Err` from `run_stages`.
