# misconfig-findings

- Engram topic: `odd/misconfig-findings/tasks` (project: `nmap-service`)
- Branch: `feature/misconfig_findings` (off origin/develop)
- Status: planned (2026-10-21)

## Objective

Surface common service misconfigurations that nmap's `vuln` scripts detect directly but that the current parser drops because they carry no `State: VULNERABLE` line.

## Problem (spike, 2026-10-21)

`nmap -sV --script vuln` (what nmap-service runs) against a deliberately weak nginx reported `http-git` as "Potential Git repository found" and would also report `http-trace`, `ftp-anon` and `http-cookie-flags` — all WITHOUT `State: VULNERABLE`. `parse` (`src/parser.rs::vulns_from_script`) only keeps findings with `State: VULNERABLE` or a CVE, so these real, directly-observed weaknesses are silently discarded. Only `ssl-dh-params` (which does emit `State: VULNERABLE`) survives.

## Scope

Add a small, explicit allowlist of misconfiguration scripts whose presence (a non-empty, non-"NOT VULNERABLE", non-"ERROR" output) is itself the finding, with a fixed severity and `confidence = confirmed` (nmap observed it directly, not by version match). Keep everything else unchanged.

## Tasks

- [x] MCF-01 Recognize an allowlist of misconfiguration scripts. For each, when the script produced real output (not empty, not "NOT VULNERABLE", not "ERROR"/"Couldn't"), emit one `VulnFinding { id: None, severity: <fixed>, confidence: Some(Confirmed), source: NmapNse, nse_script, description: <short, from the output, truncated> }`:
  - `http-git` → Medium ("repositorio Git expuesto")
  - `ftp-anon` → Medium ("acceso FTP anónimo permitido")
  - `http-trace` → Low ("método HTTP TRACE habilitado")
  - `http-cookie-flags` → Low ("cookie sin flags HttpOnly/Secure") — only when the output names a missing flag
  Do not double-count: if a script also emits `State: VULNERABLE` or a CVE (existing paths), keep the existing path and do not add a duplicate from the allowlist.
  `ftp-anon` is category auth/default/safe (not `vuln`); confirm whether nmap-service's `--script vuln` run actually invokes it. If it does NOT run under `--script vuln`, document that MCF needs the scan flags to also request `ftp-anon` (a separate config decision) and implement only the scripts that do run under `vuln` (http-git, http-trace, http-cookie-flags), leaving ftp-anon as a follow-up.

## Acceptance criteria

- A `vuln`-script XML with an `http-git` "Potential Git repository found" block yields one Medium confirmed finding.
- `State: UNKNOWN (unable to test)` and empty/NOT VULNERABLE outputs yield nothing.
- Existing `State: VULNERABLE` (ssl-dh-params) and CVE (vulners) behavior is unchanged; no duplicate findings.

## Checks

Strict TDD with real nmap XML fixtures captured from the 2026-10-21 spike shapes; `make verify`.

## Deploy / integration

No contract change (reuses `VulnFinding` + `confidence`). The gateway, user-service and front already carry the confidence field. These are new findings, so no ordering constraint beyond the normal deploy.

## Evidence

### MCF-01 (2026-10-21)

- Route: delegated writer (single), inline tests in `src/parser.rs` (no new files).
- Strict TDD: RED = 3 failed / 22 passed (`cargo test --lib parser`; http-git, http-trace, http-cookie-flags). GREEN = 25 passed, 0 failed.
- Implemented: `misconfig_finding` in `src/parser.rs`, invoked only when the existing paths (CVE / `State: VULNERABLE` / per-entry vulners) yield nothing, so no double counting.
  - `http-git` Medium "Repositorio Git expuesto"; `http-trace` Low "Método HTTP TRACE habilitado"; `http-cookie-flags` Low "Cookie sin flags de seguridad (HttpOnly/Secure)" (only if a line has "not set" + httponly/secure).
  - Empty output, "NOT VULNERABLE", "ERROR", "Couldn't", "unable to test" yield nothing.
- Fixtures: `http-git` block is the REAL shape from the spike. `http-trace` ("TRACE is enabled") and `http-cookie-flags` ("httponly flag not set") are ASSUMED from the NSE script docs (`nmap --script-help` / `.nse` @output), not captured from a live scan.
- Follow-up (not implemented): `ftp-anon` is category `auth/default/safe`, not `vuln`. The scanner runs `-sV --script vuln` (`src/scanner.rs`), so it never executes. Surfacing it needs the scan flags to also request `ftp-anon` (a separate config decision).
