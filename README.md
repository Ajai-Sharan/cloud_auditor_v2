---
title: CloudSecurityAuditor-v1
colorFrom: red
colorTo: blue
sdk: docker
base_path: /web
tags:
  - openenv
  - security
  - devsecops
---

# Cloud Auditor Environment

CloudSecurityAuditor-v1 is a deterministic OpenEnv simulation where an AI agent acts as a DevSecOps engineer, investigates cloud misconfigurations, and performs CLI-style remediations.

## Why this environment is strong for hackathons

- Real utility: tasks mirror common breach paths (public ingress, stale IAM keys, bucket exposure, metadata abuse).
- Deterministic grading: reproducible scores with continuous shaping in `(0, 1)`.
- Clear API contract: typed action/observation models and standard OpenEnv reset/step/state endpoints.
- Learnability: each task emits dense milestones so LLM/RL training receives intermediate feedback.

## What the agent is expected to do

See `TASKS_REWARDS_AND_EXPECTATIONS.md` for the full breakdown of:

- task-by-task goals and completion conditions
- reward and scoring signals
- expected agent behaviors and common failure modes

## Task set (12 total)

Difficulty labels are intentionally retained because they help judges and participants understand coverage and learning progression. They are metadata only and do not constrain training behavior.

Easy:
- `task_easy_ssh`: revoke `0.0.0.0/0` on port `22` from `sg-web`.
- `task_easy_http`: revoke `0.0.0.0/0` on port `80` from `sg-web`.
- `task_easy_encryption`: enable encryption on `customer-backup-prod`.

Medium:
- `task_medium_s3`: disable public read on `customer-backup-prod`.
- `task_medium_iam`: disable `bob-ops` active key.
- `task_medium_network`: restrict internal HTTPS ingress to `10.0.0.0/16`.
- `task_medium_imdsv2`: enforce IMDSv2 by requiring metadata tokens.

Hard:
- `task_hard_iam`: disable all active keys for stale admin user `alice-admin`.
- `task_hard_iam_policy`: disable stale key and detach wildcard policy from vulnerable role.
- `task_hard_chain`: chained S3 + IAM remediation.
- `task_hard_s3_guardrails`: account-level S3 public block + bucket encryption.
- `task_hard_compliance`: enable CloudTrail and encrypt audit logs bucket.

Reset rotates through tasks deterministically using `TASK_ORDER`.

## Scope decisions (what was added vs excluded)

- Added now: outbreak-inspired AWS tasks that fit this simulator architecture (IMDSv2 hardening, wildcard IAM policy detachment, account-level S3 guardrails).
- Not added in this repo: Azure, GCP, Kubernetes, and GitHub-secret-scanning tasks. Those are valuable, but they expand this project into multi-platform orchestration instead of a focused deterministic AWS-style environment.

## Simulated CLI commands

- `describe_instances`
- `describe_instance_metadata_options`
- `modify_instance_metadata_options --instance-id <id> --http-tokens <required|optional> --http-endpoint <enabled|disabled>`
- `describe_security_groups [--group-id <id>]`
- `revoke_security_group_ingress --group-id <id> --port <int> --cidr <cidr>`
- `authorize_security_group_ingress --group-id <id> --port <int> --cidr <cidr>`
- `describe_buckets`
- `put_public_access_block --bucket <name> --block-public-read <true|false>`
- `put_bucket_encryption --bucket <name> --algorithm <algo>`
- `describe_account_public_access_block`
- `put_account_public_access_block`
- `describe_iam_users`
- `list_roles`
- `list_attached_user_policies --user-name <name>`
- `detach_role_policy --role-name <name> --policy-arn <arn>`
- `list_access_keys --user-name <name>`
- `update_access_key --user-name <name> --access-key-id <id> --status <Active|Inactive>`
- `describe_trail`
- `start_trail`

All behavior is pure in-memory Python simulation.

## Reward design

- Continuous task score in `(0.02, 0.99)` with milestone-based progression.
- Step-level shaping reward from command milestones.
- Score-delta reward component from the active task grader.
- Mild per-step penalty to pressure efficiency.
- Penalties for malformed or unrecognized commands.
- Episode ends at `MAX_STEPS=15` or task completion.

## Quick start

```python
from cloud_auditor import CloudAuditorAction, CloudAuditorEnv

with CloudAuditorEnv(base_url="http://localhost:8000") as env:
    result = env.reset()
    print(result.observation.task_id)
    print(result.observation.task_description)

    step = env.step(CloudAuditorAction(command="describe_instances"))
    print(step.observation.command_output)
    print("reward:", step.reward, "score:", step.observation.task_score)
```

## Run locally

```bash
uv sync
uvicorn server.app:app --reload --host 0.0.0.0 --port 8000
```

## Baseline + evaluation run

```bash
python inference.py > baseline_cloud_auditor.txt
```

## Training evidence (live environment)

Judges require evidence that learning improves against the environment loop itself.

1. Run training:

```bash
uv run --extra train python -m train_live_policy --episodes 400 --out-dir artifacts/training
```

2. Produced artifacts:

- `artifacts/training/training_metrics.csv`
- `artifacts/training/training_curves.png` (reward and loss plots with labeled axes)

3. Colab-friendly notebook:

- `training_colab.ipynb`

## Build Docker image

```bash
docker build -t cloudsecurityauditor-v1:latest -f server/Dockerfile .
```

## Key files

- `models.py`: action and observation schemas.
- `server/cloud_auditor_environment.py`: simulator, command handlers, task grading, reward logic.
- `server/graders.py`: grader wrappers for `openenv.yaml` tasks.
- `openenv.yaml`: OpenEnv task manifest.
- `train_live_policy.py`: live environment training loop with curve generation.
- `training_colab.ipynb`: reproducible notebook version for judges.
