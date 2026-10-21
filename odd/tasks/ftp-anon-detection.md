# ftp-anon-detection

- Engram topic: `odd/ftp-anon-detection/tasks` (project: `nmap-service`)
- Branch: not created yet
- Status: backlog (planned 2026-10-21, deferred by the user)

## Objective

Report anonymous FTP access as a confirmed misconfiguration finding, the same way `http-git` / `http-trace` / `http-cookie-flags` are reported (feature `misconfig-findings`, MCF-01).

## Problem

`ftp-anon` is an NSE script of category `auth`/`default`/`safe`, NOT `vuln`. The scanner runs `-sV --script vuln` (`src/scanner.rs`, `detection_flags`), so `ftp-anon` never executes and anonymous FTP is never surfaced, even though the misconfig allowlist in `src/parser.rs::misconfig_finding` already knows how to classify it (`ftp-anon` → Medium "acceso FTP anónimo permitido").

## Scope / decision to take

This is a scan-configuration decision, not just a parser change: the scan has to request the script.

- Option A: extend `detection_flags` to `-sV --script "vuln,ftp-anon"` (or `vuln or ftp-anon`). Smallest change; adds one known-safe script. Confirm it stays inside the authorized, non-intrusive script policy documented in `src/scanner.rs` (no brute/dos/exploit categories).
- Option B: a separate, explicit "service checks" script set distinct from the `vuln` category, if more auth/default checks are wanted later (e.g. `ftp-anon`, `smb-enum-shares`). Larger surface; revisit only if the catalog grows.

## Tasks

- [ ] FAD-01 Decide and apply the scan-flag change (likely Option A).
- [ ] FAD-02 Enable the `ftp-anon` branch in `misconfig_finding` (allowlist entry already designed in `misconfig-findings.md`) and cover it with a real `ftp-anon` XML fixture.
- [ ] FAD-03 Confirm no duplicate finding when a target also triggers a `vuln`-category FTP script.

## Acceptance criteria

- A scan of a target allowing anonymous FTP yields one Medium confirmed finding "acceso FTP anónimo permitido".
- The scan flags stay within the authorized non-intrusive script policy.

## Checks

Strict TDD with a real `ftp-anon` XML fixture; `make verify`.
