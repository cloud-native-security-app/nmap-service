# Feature: ci-cd-deploy (nmap-service)

- **Master plan:** repo `infra`, `odd/tasks/cloud-native-deploy.md` (Engram `odd/cloud-native-deploy/tasks`)
- **Engram topic:** `odd/ci-cd-deploy/tasks` (project: `nmap-service`)
- **Branch:** `v1`
- **Status:** planned

## Objective

Give `nmap-service` (`ms-nmap`) a GitHub Actions pipeline: CI on every pull
request and an automatic deploy of the container image to the existing ECS
Fargate service on every push to `main` (plus manual `workflow_dispatch`).

## Why

The master plan moves the whole platform to AWS (ECS Fargate, ECR, Amazon MQ
for RabbitMQ). Today the image is built by hand from `infra`
(`deploy/aws/05-build-push-core-images.sh`) and the task definition lives in
`infra/deploy/aws/task-defs/nmap-service.json` with `__PLACEHOLDER__` tokens.
Each service repo must own its build, test and deploy path.

## Scope

In:
- Task definition owned by this repo (`.aws/task-definition.json`).
- Configurable AMQP endpoint and TLS trust so the AWS image uses Amazon MQ
  with system root CAs, without the baked lab CA; local compose keeps working.
- `.github/workflows/ci.yml` (pull requests) and `deploy.yml` (main + manual).
- README / docs updates.

Out:
- Terraform resources (ECS service, ECR, cluster, IAM): owned by `infra`.
- Broker topology and Amazon MQ provisioning: owned by `broker` / `infra`.
- Changes to scanning logic or `docs/security-scope.md` limits.

## Constraints

- AWS Academy Learner Lab: no OIDC. Temporary credentials are stored as
  GitHub secrets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN`, refreshed with `infra`'s `refresh-gh-secrets.sh`.
  Role in use: `LabRole`.
- Terraform owns the ECS service (`nmap-service` in cluster
  `security-app-cluster-v2`); CI owns task definition revisions only (the
  service ignores `task_definition` drift).
- Broker moves to Amazon MQ for RabbitMQ, AMQPS on port 5671.
- Secrets never committed; the lab password in the old task def must not be
  copied into `.aws/task-definition.json` (use ECS `secrets` / injected value).
- Artifacts in English; existing Spanish docs keep being edited in Spanish.

## Tooling

- TDD: Strict (source: user global config). Runner: `cargo test`
  (Makefile `verify` target; integration tests with `-- --ignored` need Docker).
- Workflows validated with `actionlint`.
- Per-task commits are Conventional Commits; no push/PR without user decision.

## Checklist

- [ ] **CI-01** Move the task definition to `.aws/task-definition.json`
      (placeholders for image, execution role, region, secrets).
- [ ] **CI-02** Make the AMQP endpoint and TLS trust configurable so AWS uses
      Amazon MQ with system root CAs. Depends on the broker spike
      "MQ AMQPS public CA". Drop the baked lab CA from the AWS image path
      (remove `SSL_CERT_FILE` from the task def) while local compose keeps
      mounting the lab CA. Add tests first (config / adapter) per Strict TDD.
- [ ] **CI-03** `ci.yml` on `pull_request`: `cargo fmt --check`, `clippy -D
      warnings`, `cargo test`, `docker build` without push. Open problem: the
      Dockerfile requires the `tls` build context (`broker/rabbitmq/tls`), a
      different repo. Proposal: make the CA stage optional (`ARG
      INCLUDE_LAB_CA=false`, default stage copies nothing; local compose and
      lab builds pass the `tls` context and set it to true). CI and AWS builds
      then need no cross-repo context. Depends on CI-02.
- [ ] **CI-04** `deploy.yml` on push to `main` + `workflow_dispatch`:
      `aws-actions/configure-aws-credentials` -> `amazon-ecr-login` ->
      build and push `:${{ github.sha }}` -> `amazon-ecs-render-task-definition`
      -> `amazon-ecs-deploy-task-definition` with `wait-for-service-stability`;
      cluster `security-app-cluster-v2`, service `nmap-service`.
- [ ] **CI-05** Docs: README section for CI/CD (secrets, refresh flow, how to
      trigger a deploy, rollback by redeploying a previous SHA).

## Acceptance criteria

- A pull request runs fmt, clippy, unit tests and a Docker build, all green,
  with no cross-repo checkout.
- A merge to `main` pushes `:<sha>` to ECR, registers a new task definition
  revision and the ECS service reaches a stable state.
- The running task connects to Amazon MQ over AMQPS 5671 using system CAs.
- `docker compose` locally still works with the lab CA.
- `actionlint` reports no errors on both workflows.

## Checks

- `make verify` (fmt, clippy, tests, doc).
- `actionlint .github/workflows/*.yml`.
- `docker build` of the image without the lab CA context.
- Post-deploy: `aws ecs describe-services` shows `runningCount == desiredCount`.

## Dependencies

- `infra`: TF-07, TF-10, TF-12 (ECR/cluster/service and secret refresh script).
- `broker`: Amazon MQ spikes (AMQPS with public CA).

## Progress

Planned. No task started.

## Next step

CI-01: move the task definition into `.aws/task-definition.json`.
