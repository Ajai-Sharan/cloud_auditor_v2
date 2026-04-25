# Tasks, Rewards, and Agent Expectations (CloudSecurityAuditor-v1)

This document describes:

- **Tasks we added / support** (the full task set this environment rotates through)
- **Rewards and scoring** (what the agent gets credit for, and how)
- **What we expect the agent to do** (behavioral expectations and success criteria)

The task rotation and grading are deterministic and defined by:

- `openenv.yaml` (task manifest / grader mapping)
- `server/cloud_auditor_environment.py` (task specs, command handlers, reward shaping, completion checks)

---

## Environment contract (what the agent sees)

Each episode is a single task. On reset, the observation includes:

- **`task_id`**: one of the task IDs listed below
- **`task_description`**: a natural language description of the remediation goal
- **`supported_commands`**: the CLI-like commands the agent may issue
- **`task_score`**: continuous task score strictly inside \(0, 1\)
- **`reward`**: step reward (shaped) also clipped into \([-1, 1]\)
- **`done` / `status`**: episode termination and status

Episodes end when:

- **task is complete**, or
- **`MAX_STEPS = 15`** is reached.

---

## Supported task set (12 total)

Reset rotates deterministically through all tasks in `TASK_ORDER`.

### Easy

#### `task_easy_ssh`
- **Goal**: Revoke `0.0.0.0/0` ingress on **port 22** from `sg-web`.
- **Typical flow**:
  - `describe_instances`
  - `describe_security_groups --group-id sg-web`
  - `revoke_security_group_ingress --group-id sg-web --port 22 --cidr 0.0.0.0/0`
- **Completion condition**: `sg-web` has **no** ingress rule with `{port: 22, cidr: 0.0.0.0/0}`.

#### `task_easy_http`
- **Goal**: Revoke `0.0.0.0/0` ingress on **port 80** from `sg-web`.
- **Typical flow**:
  - `describe_instances`
  - `describe_security_groups --group-id sg-web`
  - `revoke_security_group_ingress --group-id sg-web --port 80 --cidr 0.0.0.0/0`
- **Completion condition**: `sg-web` has **no** ingress rule with `{port: 80, cidr: 0.0.0.0/0}`.

#### `task_easy_encryption`
- **Goal**: Enable server-side encryption (KMS-style) on S3 bucket `customer-backup-prod`.
- **Typical flow**:
  - `describe_buckets`
  - `put_bucket_encryption --bucket customer-backup-prod --algorithm aws:kms`
- **Completion condition**: `customer-backup-prod.kms_encrypted == True`.

### Medium

#### `task_medium_s3`
- **Goal**: Disable public read access on `customer-backup-prod`.
- **Typical flow**:
  - `describe_buckets`
  - `put_public_access_block --bucket customer-backup-prod --block-public-read true`
- **Completion condition**: `customer-backup-prod.public_read == False`.

#### `task_medium_iam`
- **Goal**: Disable `bob-ops` active access key.
- **Typical flow**:
  - `describe_iam_users`
  - `list_access_keys --user-name bob-ops`
  - `update_access_key --user-name bob-ops --access-key-id AKIABOB001 --status Inactive`
- **Completion condition**: `bob-ops.access_keys[0].status == Inactive`.

#### `task_medium_network`
- **Goal**: Restrict internal HTTPS ingress to **only** `10.0.0.0/16` on `sg-internal`.
- **Typical flow**:
  - `describe_security_groups --group-id sg-internal`
  - `authorize_security_group_ingress --group-id sg-internal --port 443 --cidr 10.0.0.0/16`
- **Completion condition**:
  - `sg-internal` has **no** `{port: 443, cidr: 0.0.0.0/0}`, and
  - `sg-internal` has `{port: 443, cidr: 10.0.0.0/16}`.

#### `task_medium_imdsv2`
- **Goal**: Enforce IMDSv2 (require metadata tokens) on instances using IMDSv1 (`http_tokens=optional`).
- **Typical flow**:
  - `describe_instance_metadata_options`
  - `modify_instance_metadata_options --instance-id i-web-01 --http-tokens required --http-endpoint enabled`
- **Completion condition**: all instances have `metadata_options.http_tokens == "required"`.

### Hard

#### `task_hard_iam`
- **Goal**: Disable **all active** keys for stale admin user `alice-admin`.
- **Typical flow**:
  - `describe_iam_users`
  - `list_attached_user_policies --user-name alice-admin` (helps identify admin)
  - `list_access_keys --user-name alice-admin`
  - `update_access_key ... --status Inactive` (repeat until all are inactive)
- **Completion condition**: `alice-admin` has **2** inactive keys (`AKIAALICE001`, `AKIAALICE002`).

#### `task_hard_iam_policy`
- **Goal**: Remediate credential + privilege risk by:
  - disabling `bob-ops` active key, and
  - detaching the wildcard policy from role `app-runtime-role`.
- **Typical flow**:
  - `describe_iam_users`
  - `list_access_keys --user-name bob-ops`
  - `list_roles`
  - `detach_role_policy --role-name app-runtime-role --policy-arn arn:aws:iam::123456789012:policy/WildcardAdminPolicy`
  - `update_access_key --user-name bob-ops --access-key-id AKIABOB001 --status Inactive`
- **Completion condition**:
  - `bob-ops` key is inactive, and
  - `app-runtime-role` no longer has `WildcardAdminPolicy` attached.

#### `task_hard_chain`
- **Goal**: Chained remediation:
  - disable S3 public read on `customer-backup-prod`, and
  - disable all keys for `alice-admin`.
- **Typical flow**:
  - `describe_buckets`
  - `put_public_access_block --bucket customer-backup-prod --block-public-read true`
  - `list_access_keys --user-name alice-admin`
  - `update_access_key ... --status Inactive` (repeat)
- **Completion condition**: `task_medium_s3` and `task_hard_iam` are both complete.

#### `task_hard_s3_guardrails`
- **Goal**: Harden S3 with:
  - **account-level** S3 Block Public Access enabled, and
  - encryption configured on `customer-backup-prod`.
- **Typical flow**:
  - `describe_account_public_access_block`
  - `put_account_public_access_block`
  - `describe_buckets`
  - `put_bucket_encryption --bucket customer-backup-prod --algorithm AES256`
- **Completion condition**:
  - all four account flags are `True` (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`), and
  - `customer-backup-prod.kms_encrypted == True` (encryption enabled in simulator state).

#### `task_hard_compliance`
- **Goal**: Enable CloudTrail and encrypt the audit logs bucket.
- **Typical flow**:
  - `describe_trail`
  - `start_trail`
  - `put_bucket_encryption --bucket audit-logs-trail --algorithm aws:kms`
- **Completion condition**:
  - `cloudtrail.enabled == True`, and
  - `audit-logs-trail.kms_encrypted == True`.

---

## Rewards and scoring (what “good” looks like)

### Task score (primary performance signal)

- **`task_score` is continuous** and strictly inside \(0, 1\).
- In practice:
  - **incomplete tasks** usually sit in roughly **0.02 → 0.97/0.98** depending on progress,
  - **completed tasks** return **0.98 or 0.99** (varies by task).
- Score increases with **meaningful progress flags** and/or **state changes** that move the world toward a secure configuration.

### Step reward (training signal)

Every `step()` returns a shaped reward with these components:

- **Efficiency pressure**: a small per-step penalty (encourages solving within fewer commands).
- **Milestone rewards**: positive rewards for investigation and remediation milestones (task-dependent).
- **Score-delta shaping**: additional reward proportional to the increase in `task_score`.
- **Completion bonus**: an extra one-time bonus when the task completes.
- **Errors are penalized**:
  - empty command
  - malformed CLI options
  - unrecognized command name

### Practical implications for agents

- **Don’t spam commands**: the step penalty makes random exploration costly.
- **Do reconnaissance, then act**: “describe → identify target → remediate” is consistently rewarded.
- **Use exact option names**: commands require `--kebab-case` options (e.g., `--group-id`, `--user-name`).

---

## What we expect the agent to do (behavioral expectations)

### Core expectation

Act like a careful DevSecOps engineer: **investigate**, **identify the vulnerable asset**, then **apply the minimal remediation** that satisfies the task’s secure end state.

### Expected agent behaviors

- **Read the task**: use `task_description` to pick the right command sequence.
- **Use supported CLI only**: only issue commands listed in `supported_commands`.
- **Target the correct resource**:
  - correct security group (`sg-web`, `sg-internal`)
  - correct S3 bucket (`customer-backup-prod`, `audit-logs-trail`)
  - correct IAM principal (`bob-ops`, `alice-admin`, `app-runtime-role`)
  - correct instance (`i-web-01`)
- **Make changes that persist in state**: remediations should reflect in subsequent `describe_*` output.
- **Stop when done**: once `done=True` / task completes, no additional commands are needed.

### Common failure modes (what we *don’t* want)

- **Skipping reconnaissance** and guessing IDs/options (often leads to penalties).
- **Wrong option names** (e.g., missing `--group-id` or `--user-name`) causing parse errors.
- **Partial remediation** on “hard” tasks (e.g., disabling only one `alice-admin` key).
- **Fixing the wrong bucket / SG** (e.g., encrypting `analytics-private` instead of the target).

---

## Quick mapping: task → primary remediation command

- `task_easy_ssh`: `revoke_security_group_ingress`
- `task_easy_http`: `revoke_security_group_ingress`
- `task_easy_encryption`: `put_bucket_encryption`
- `task_medium_s3`: `put_public_access_block`
- `task_medium_iam`: `update_access_key`
- `task_medium_network`: `authorize_security_group_ingress` (also removes the open rule for this task)
- `task_medium_imdsv2`: `modify_instance_metadata_options`
- `task_hard_iam`: `update_access_key` (repeat for both keys)
- `task_hard_iam_policy`: `detach_role_policy` + `update_access_key`
- `task_hard_chain`: `put_public_access_block` + `update_access_key` (repeat)
- `task_hard_s3_guardrails`: `put_account_public_access_block` + `put_bucket_encryption`
- `task_hard_compliance`: `start_trail` + `put_bucket_encryption`

