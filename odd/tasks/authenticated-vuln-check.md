# authenticated-vuln-check

- Engram topic: `odd/authenticated-vuln-check/tasks` (project: `nmap-service`)
- Branch: not created yet
- Status: backlog (planned 2026-10-21, deferred by the user — large)

## Objective

Turn "posibles" (version_match) CVEs into confirmed/dismissed by checking, from inside the target, whether the distro package actually has the fix, instead of guessing from the upstream version.

## Problem

`vulners` matches CVEs by product version (CPE). Distros (Amazon Linux, RHEL, Debian) backport security fixes WITHOUT bumping the upstream version, so a `version_match` finding can already be patched — a false positive. The only rigorous way to know is to ask the package manager on the host.

## Scope (large — needs credentials and SSH)

The project already stores per-target network credentials (user-service / NetworkCredentials; the weak-target spike used russh). This feature would:

- SSH into the target with the stored credentials.
- Query the package manager (`rpm -q --changelog`, `dnf updateinfo`, `apt-get -s`, or the distro's security advisory feed) for the installed package and the CVE.
- Mark the finding `confirmed` (pending patch) or drop/annotate it (already backport-fixed).

## Decisions to take (product + security)

- Credential handling and blast radius: read-only commands only, timeouts, no privilege escalation beyond what is authorized. Reuse the existing authorization boundary; never probe hosts without stored, authorized credentials.
- Where it runs: inside nmap-service after the scan, or a separate authenticated-check stage.
- Failure mode: no credentials / SSH fails → leave the finding as `version_match` (never silently upgrade to confirmed).

## Tasks

- [ ] AVC-01 Design the authenticated-check stage and credential flow (product + security review).
- [ ] AVC-02 Implement read-only package/advisory queries per supported distro, with strict timeouts.
- [ ] AVC-03 Reconcile results into the finding's `confidence` honestly (confirmed vs version_match vs dismissed).

## Acceptance criteria

- A CVE already backport-fixed on the target is dismissed/annotated; a genuinely unpatched CVE is marked confirmed; no credentials means the finding stays `version_match`.

## Checks

Strict TDD against recorded package-manager outputs; integration against a controlled target; `make verify`.
