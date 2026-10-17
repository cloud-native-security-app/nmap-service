# Feature: ci-cd-deploy (nmap-service)

- **Master plan:** repo `infra`, `odd/tasks/cloud-native-deploy.md` (Engram `odd/cloud-native-deploy/tasks`)
- **Engram topic:** `odd/ci-cd-deploy/tasks` (project: `nmap-service`)
- **Branch:** `v1`
- **Status:** planned

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
- Task definition owned by this repo (`.aws/task-definition.json`).
- Messaging env config in the task definition (queue URLs, topic ARN,
  region) from `infra` outputs; the code is `sqs-sns-adapter`. The baked lab
  CA is not needed on AWS (public-CA HTTPS).
- `.github/workflows/ci.yml` (pull requests) and `deploy.yml` (main + manual).
- README / docs updates.

Out:
- Terraform resources (ECS service, ECR, cluster, IAM): owned by `infra`.
- Messaging topology design (`broker`) and its Terraform (`infra` TF-10); adapter code (`sqs-sns-adapter`).
- Changes to scanning logic or `docs/security-scope.md` limits.

## Constraints

- AWS Academy Learner Lab: no OIDC. Temporary credentials are stored as
  GitHub secrets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN`, refreshed with `infra`'s `refresh-gh-secrets.sh`.
  Role in use: `LabRole`.
- Terraform owns the ECS service (`nmap-service` in cluster
  `security-app-cluster-v2`); CI owns task definition revisions only (the
  service ignores `task_definition` drift).
- Messaging is AWS SNS + SQS over HTTPS; credentials come from the ECS task role (`LabRole`, shared by all services).
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
- [ ] **CI-02** Messaging env vars in the task definition (queue URLs, topic
      ARN, region) and removal of `SSL_CERT_FILE` from the AWS task def.
      Code changes are tracked in `sqs-sns-adapter` (MSG-NM-01..05); depends on
      MSG-NM-01. (Superseded: the Amazon MQ / AMQPS public-CA variant.)
- [ ] **CI-03** `ci.yml` on `pull_request`: `cargo fmt --check`, `clippy -D
      warnings`, `cargo test`, `docker build` without push. The Dockerfile
      `tls` build context (`broker/rabbitmq/tls`) is a cross-repo dependency;
      it disappears when `sqs-sns-adapter` MSG-NM-05 drops the lab CA.
      **The `ARG INCLUDE_LAB_CA` proposal is OBSOLETE for AWS** (2026-10-17):
      with SNS + SQS there is no lab CA to include. Depends on MSG-NM-05.
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
- The running task consumes and publishes through SQS/SNS over HTTPS with the task role.
- `docker compose` locally still works (with LocalStack, per `sqs-sns-adapter`).
- `actionlint` reports no errors on both workflows.

## Checks

- `make verify` (fmt, clippy, tests, doc).
- `actionlint .github/workflows/*.yml`.
- `docker build` of the image without extra build contexts.
- Post-deploy: `aws ecs describe-services` shows `runningCount == desiredCount`.

## Dependencies

- `infra`: TF-07, TF-10, TF-12 (ECR/cluster/service and secret refresh script).
- `broker`: `odd/tasks/sqs-sns-migration.md` (topology sign-off MSG-01, LabRole spike MSG-02).
- `nmap-service`: `odd/tasks/sqs-sns-adapter.md` (MSG-NM-01..05).

## Progress

Planned. No task started.

## Next step

CI-01: move the task definition into `.aws/task-definition.json`.
