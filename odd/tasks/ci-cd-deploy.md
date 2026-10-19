# Feature: ci-cd-deploy (nmap-service)

- **Master plan:** repo `infra`, `odd/tasks/cloud-native-deploy.md` (Engram `odd/cloud-native-deploy/tasks`)
- **Engram topic:** `odd/ci-cd-deploy/tasks` (project: `nmap-service`)
- **Branch:** `feature/ci_cd`
- **Status:** implemented locally; live checks pending

## Objective

Give `nmap-service` (`ms-nmap`) a GitHub Actions pipeline: CI on every pull
request and an automatic deploy of the container image to the existing ECS
Fargate service on every push to `main` (plus manual `workflow_dispatch`).

> 2026-10-17: RabbitMQ / Amazon MQ replaced by AWS SNS + SQS. The messaging adapter rewrite is the separate feature repo `nmap-service`, path `odd/tasks/sqs-sns-adapter.md` (MSG-NM-*). Amazon MQ items below are superseded.

## Why

The master plan moves the whole platform to AWS (ECS Fargate, ECR, SNS + SQS;
Amazon MQ for RabbitMQ was the original target and is superseded). Today the image is built by hand from `infra`
(`deploy/aws/05-build-push-core-images.sh`) and the task definition lives in
`infra/deploy/aws/task-defs/nmap-service.json` with `__PLACEHOLDER__` tokens.
Each service repo must own its build, test and deploy path.

## Scope

In:
- CI owns only the image revision (Decision D1): deploy downloads the task
  definition the ECS service currently runs, swaps the `nmap-service`
  container image to `<ECR repo>:${{ github.sha }}`, registers it and updates
  the service.
- `.github/workflows/ci.yml` (pull requests) and `deploy.yml` (main + manual).
- README / docs updates.

Out:
- Task definition content (env, SSM secrets, roles, logging): Terraform in
  `infra` is the single source of truth; nothing is committed here.
- Terraform resources (ECS service, ECR, cluster, IAM): owned by `infra`.
- Messaging topology design (`broker`) and its Terraform (`infra` TF-10); adapter code (`sqs-sns-adapter`).
- Changes to scanning logic or `docs/security-scope.md` limits.

## Constraints

- AWS Academy Learner Lab: no OIDC. Temporary credentials are stored as
  GitHub secrets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN`, refreshed with `infra`'s `refresh-gh-secrets.sh`.
  Role in use: `LabRole`.
- Terraform owns the ECS service (`nmap-service` in cluster
  `security-app-cluster-v2`, bootstrap task definition,
  `ignore_changes = [task_definition]`); CI only registers revisions that
  differ from the current one in the image (D1).
- Messaging is AWS SNS + SQS over HTTPS; credentials come from the ECS task role (`LabRole`, shared by all services).
- Secrets never committed; no task definition is versioned in this repo.
- Artifacts in English; existing Spanish docs keep being edited in Spanish.

## Tooling

- TDD: Strict (source: user global config). Runner: `cargo test`
  (Makefile `verify` target; integration tests with `-- --ignored` need Docker).
- Workflows validated with `actionlint`.
- Per-task commits are Conventional Commits; no push/PR without user decision.

## Checklist

- [x] **CI-01** Repo-owned `.aws/task-definition.json`: superseded by D1
      (done-by-design). The task definition lives in Terraform.
- [x] **CI-02** Messaging env vars in the task definition: superseded by D1
      (done-by-design). Env comes from the Terraform task definition; code
      changes stay in `sqs-sns-adapter`.
- [x] **CI-03** `.github/workflows/ci.yml` on `pull_request` and push to
      `develop`: `make verify` (fmt, clippy `-D warnings`, tests, ignored
      integration suites, doc) and `docker build` without push or extra
      build contexts. `actionlint` clean.
- [x] **CI-04** `.github/workflows/deploy.yml` on push to `main` +
      `workflow_dispatch`: configure-aws-credentials -> ECR login -> build and
      push `:${{ github.sha }}` (+ `:latest`) -> download current task
      definition -> render (image swap) -> deploy with
      `wait-for-service-stability`; cluster `security-app-cluster-v2`,
      service `nmap-service`.
- [x] **CI-05** Docs: README CI/CD section (secrets, refresh flow, manual
      redeploy, rollback, no-load-balancer stability note).

## Decisions

- D1 (2026-10-19, user, same as gateway): Terraform (`infra`) owns the task
  definition (env, SSM secrets, roles, logging). CI owns only the image:
  `deploy.yml` fetches the service's current task definition, strips read-only
  fields with jq, swaps the image of container `nmap-service` to
  `${{ github.sha }}` and deploys. Supersedes CI-01 and CI-02. `:latest` is
  also pushed because the bootstrap task definition may point at it.

## Acceptance criteria

- A pull request runs fmt, clippy, unit tests and a Docker build, all green,
  with no cross-repo checkout.
- A merge to `main` pushes `:<sha>` to ECR, registers a new task definition
  revision (image swap only) and the ECS service reaches a stable state
  (task stays RUNNING; no load balancer).
- The running task consumes and publishes through SQS/SNS over HTTPS with the task role.
- `docker compose` locally still works (with LocalStack, per `sqs-sns-adapter`).
- `actionlint` reports no errors on both workflows.

## Checks

- `make verify` (fmt, clippy, tests, ignored integration suites, doc).
- `actionlint .github/workflows/*.yml`.
- `docker build` of the image without extra build contexts.
- Post-deploy: `aws ecs describe-services` shows `runningCount == desiredCount`.

## Dependencies

- `infra`: TF-07, TF-10, TF-12 (ECR/cluster/service and secret refresh script).
- `broker`: `odd/tasks/sqs-sns-migration.md` (topology sign-off MSG-01, LabRole spike MSG-02).
- `nmap-service`: `odd/tasks/sqs-sns-adapter.md` (MSG-NM-01..05).

## Progress

CI-01/02 superseded by D1. CI-03..05 implemented locally (workflows, README
CI/CD section); local checks passed. Not committed yet. Live checks pending:
green PR run and real deploy (need the user to open a PR / merge to `main`
with repo secrets and variable set).

## CI/CD evidence

Route: delegated writer (single bounded writer). Strict TDD = observable checks first.

- Baseline (before): `mise exec actionlint@1.7.12 shellcheck@latest -- actionlint .github/workflows/*.yml` -> `could not read ".github/workflows/*.yml": no such file or directory` (workflow dir absent).
- After: same command -> clean, exit 0.
- `make verify` -> exit 0.
- `docker build -t nmap-service:ci-check .` -> exit 0; image removed afterwards.
- `git status --short` -> ` M README.md`, `?? .github/` (plus this feature doc).
- Pinned actions (full SHA, same as gateway): configure-aws-credentials v6.3.0, amazon-ecr-login v2.1.7, amazon-ecs-render-task-definition v1.9.1, amazon-ecs-deploy-task-definition v2.6.4, Swatinem/rust-cache v2.9.2; `actions/checkout@v4`.
- Pending (needs user): green PR run of `ci.yml`; real `deploy.yml` rollout.

## Next step

Commit (user), push and open a PR to verify CI live; run infra
`refresh-gh-secrets.sh` before the first deploy.
