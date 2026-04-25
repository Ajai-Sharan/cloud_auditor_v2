# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""CloudSecurityAuditor-v1 environment implementation.

This module provides a deterministic, in-memory simulation of AWS-style assets and
security workflows. An agent interacts with the simulator through a small CLI-like
command set and receives shaped rewards plus deterministic task scores.
"""

from __future__ import annotations

import copy
import json
import shlex
import threading
from dataclasses import dataclass

try:
    from openenv.core.env_server.interfaces import Environment
    from openenv.core.env_server.types import State
except ModuleNotFoundError:  # pragma: no cover
    class Environment:
        """Fallback base when openenv is unavailable in local test environments."""

    @dataclass
    class State:
        episode_id: str
        step_count: int

try:
    from ..models import CloudAuditorAction, CloudAuditorObservation
except ImportError:
    from models import CloudAuditorAction, CloudAuditorObservation


class CloudAuditorEnvironment(Environment):
    """Deterministic cloud security simulator with graded cloud security tasks."""

    # Enable concurrent WebSocket sessions.
    # Set to True if your environment isolates state between instances.
    # When True, multiple WebSocket clients can connect simultaneously, each
    # getting their own environment instance (when using factory mode in app.py).
    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    # HTTP endpoints may instantiate a fresh environment per request.
    # When enabled, reset rotation uses a process-wide counter so repeated
    # POST /reset calls still cycle tasks deterministically.
    USE_GLOBAL_TASK_ROTATION: bool = False
    _GLOBAL_RESET_COUNT: int = 0
    _GLOBAL_LOCK = threading.Lock()
    USE_GLOBAL_HTTP_STATE: bool = False
    AUTO_RECOVER_EMPTY_COMMAND: bool = False
    _GLOBAL_TASK_ID: str = "task_easy_ssh"
    _GLOBAL_WORLD_STATE: dict | None = None
    _GLOBAL_PROGRESS_FLAGS: set[str] = set()
    _GLOBAL_STEP_COUNT: int = 0
    _GLOBAL_EPISODE_ID: str = "episode-0"

    MAX_STEPS = 15

    TASK_SPECS = {
        "task_easy_ssh": {
            "description": (
                "Find the web server and revoke its 0.0.0.0/0 ingress rule on port 22."
            ),
        },
        "task_easy_http": {
            "description": (
                "Find the public web security group and revoke the 0.0.0.0/0 ingress rule on port 80."
            ),
        },
        "task_easy_encryption": {
            "description": (
                "Find the customer backup S3 bucket and enable server-side encryption with KMS."
            ),
        },
        "task_medium_s3": {
            "description": (
                "Locate the customer backup S3 bucket and disable public read access."
            ),
        },
        "task_medium_iam": {
            "description": (
                "Find the stale ops user bob-ops and disable their active access key."
            ),
        },
        "task_medium_network": {
            "description": (
                "Identify the internal security group and restrict HTTPS ingress to only 10.0.0.0/16 CIDR."
            ),
        },
        "task_medium_imdsv2": {
            "description": (
                "Identify EC2 instances with IMDSv1 enabled and enforce IMDSv2 by requiring metadata tokens."
            ),
        },
        "task_hard_iam": {
            "description": (
                "Find an IAM user with AdministratorAccess and last login over 90 days, "
                "then disable all of that user's access keys."
            ),
        },
        "task_hard_iam_policy": {
            "description": (
                "Find stale IAM credentials and remediate privilege escalation risk by disabling bob-ops active key "
                "and detaching wildcard-access policy from role app-runtime-role."
            ),
        },
        "task_hard_chain": {
            "description": (
                "Perform chained remediation: disable public read on customer-backup-prod and disable "
                "all access keys for alice-admin."
            ),
        },
        "task_hard_s3_guardrails": {
            "description": (
                "Harden S3 by enabling account-level Block Public Access and configuring encryption on customer-backup-prod."
            ),
        },
        "task_hard_compliance": {
            "description": (
                "Enable CloudTrail logging and set up proper S3 encryption for audit logs."
            ),
        },
    }

    TASK_ORDER = [
        "task_easy_ssh",
        "task_easy_http",
        "task_easy_encryption",
        "task_medium_s3",
        "task_medium_iam",
        "task_medium_network",
        "task_medium_imdsv2",
        "task_hard_iam",
        "task_hard_iam_policy",
        "task_hard_chain",
        "task_hard_s3_guardrails",
        "task_hard_compliance",
    ]

    SUPPORTED_COMMANDS = [
        "describe_instances",
        "describe_instance_metadata_options",
        "modify_instance_metadata_options",
        "describe_security_groups",
        "revoke_security_group_ingress",
        "authorize_security_group_ingress",
        "describe_buckets",
        "put_public_access_block",
        "put_bucket_encryption",
        "describe_account_public_access_block",
        "put_account_public_access_block",
        "describe_iam_users",
        "list_roles",
        "list_attached_user_policies",
        "detach_role_policy",
        "list_access_keys",
        "update_access_key",
        "describe_trail",
        "start_trail",
    ]

    def __init__(self):
        self._task_cycle = list(self.TASK_ORDER)
        self._reset_count = 0
        self._current_task_id = self._task_cycle[0]
        self._progress_flags: set[str] = set()
        self._world_state: dict = self._build_initial_world_state()
        self._state = State(episode_id="episode-0", step_count=0)
        if self.USE_GLOBAL_HTTP_STATE:
            self._load_from_global_state()

    def _load_from_global_state(self) -> None:
        """Hydrate instance state from process-wide HTTP state."""
        cls = type(self)
        if cls._GLOBAL_WORLD_STATE is None:
            cls._GLOBAL_WORLD_STATE = self._build_initial_world_state()

        self._current_task_id = cls._GLOBAL_TASK_ID
        self._world_state = copy.deepcopy(cls._GLOBAL_WORLD_STATE)
        self._progress_flags = set(cls._GLOBAL_PROGRESS_FLAGS)
        self._state = State(episode_id=cls._GLOBAL_EPISODE_ID, step_count=cls._GLOBAL_STEP_COUNT)

    def _save_to_global_state(self) -> None:
        """Persist instance state to process-wide HTTP state."""
        cls = type(self)
        cls._GLOBAL_TASK_ID = self._current_task_id
        cls._GLOBAL_WORLD_STATE = copy.deepcopy(self._world_state)
        cls._GLOBAL_PROGRESS_FLAGS = set(self._progress_flags)
        cls._GLOBAL_STEP_COUNT = self._state.step_count
        cls._GLOBAL_EPISODE_ID = self._state.episode_id

    def reset(self) -> CloudAuditorObservation:
        """Reset episode state and rotate deterministically through all tasks."""
        if self.USE_GLOBAL_TASK_ROTATION:
            reset_count = self._next_global_reset_count()
        else:
            self._reset_count += 1
            reset_count = self._reset_count

        task_idx = (reset_count - 1) % len(self._task_cycle)
        self._current_task_id = self._task_cycle[task_idx]

        self._world_state = self._build_initial_world_state()
        self._progress_flags = set()
        self._state = State(episode_id=f"episode-{reset_count}", step_count=0)
        if self.USE_GLOBAL_HTTP_STATE:
            with type(self)._GLOBAL_LOCK:
                self._save_to_global_state()

        return self._build_observation(
            command_output=(
                "CloudSecurityAuditor-v1 initialized. Available commands: "
                f"{', '.join(self.SUPPORTED_COMMANDS)}"
            ),
            reward=0.0,
            done=False,
        )

    def step(self, action: CloudAuditorAction) -> CloudAuditorObservation:  # type: ignore[override]
        """Execute a simulated CLI command with shaped reward and deterministic grading."""
        if self.USE_GLOBAL_HTTP_STATE:
            with type(self)._GLOBAL_LOCK:
                self._load_from_global_state()
                observation = self._step_internal(action)
                self._save_to_global_state()
                return observation

        return self._step_internal(action)

    def _step_internal(self, action: CloudAuditorAction) -> CloudAuditorObservation:
        """Execute one environment step against the currently loaded state."""
        prev_score = self._grade_current_task()
        self._state.step_count += 1

        reward = -0.01  # mild efficiency pressure on every step
        command_output = ""

        command_text = action.command.strip()
        if not command_text:
            if self.AUTO_RECOVER_EMPTY_COMMAND:
                command_text = self._fallback_command_for_current_task()
                command_output = f"Auto-recovered empty command -> {command_text}"
            else:
                reward -= 0.04
                command_output = "Error: empty command"
                return self._finalize_step(prev_score, reward, command_output)

        command_name, args, parse_error = self._parse_command(command_text)
        if parse_error:
            reward -= 0.04
            command_output = f"Error: {parse_error}"
            return self._finalize_step(prev_score, reward, command_output)

        handler = getattr(self, f"_cmd_{command_name}", None)
        if handler is None:
            reward -= 0.06
            command_output = f"Error: unrecognized command '{command_name}'"
            return self._finalize_step(prev_score, reward, command_output)

        try:
            handler_output, milestone_reward = handler(args)
            command_output = handler_output
            reward += milestone_reward
        except ValueError as err:
            reward -= 0.03
            command_output = f"Error: {err}"
        observation = self._finalize_step(prev_score, reward, command_output)
        return observation

    @classmethod
    def _next_global_reset_count(cls) -> int:
        with cls._GLOBAL_LOCK:
            cls._GLOBAL_RESET_COUNT += 1
            return cls._GLOBAL_RESET_COUNT

    @property
    def state(self) -> State:
        """Get OpenEnv state (episode metadata for the /state endpoint)."""
        return self._state

    def _finalize_step(
        self,
        previous_score: float,
        reward_so_far: float,
        command_output: str,
    ) -> CloudAuditorObservation:
        """Apply score delta reward and terminal checks, then build observation."""
        score = self._grade_current_task()
        score_delta = score - previous_score
        reward = reward_so_far + (0.8 * score_delta)

        done = self._is_task_complete()
        if done:
            reward += self._award_once("task_completed", 0.15)
        elif self._state.step_count >= self.MAX_STEPS:
            done = True

        return self._build_observation(
            command_output=command_output,
            reward=max(-1.0, min(1.0, reward)),
            done=done,
        )

    def _build_observation(
        self,
        command_output: str,
        reward: float,
        done: bool,
    ) -> CloudAuditorObservation:
        score = self._grade_current_task()
        status = "running"
        if done:
            status = "completed" if self._is_task_complete() else "failed"

        return CloudAuditorObservation(
            task_id=self._current_task_id,
            task_description=self.TASK_SPECS[self._current_task_id]["description"],
            command_output=command_output,
            task_score=score,
            steps_remaining=max(0, self.MAX_STEPS - self._state.step_count),
            status=status,
            done=done,
            reward=reward,
            metadata={
                "step_count": self._state.step_count,
                "supported_commands": self.SUPPORTED_COMMANDS,
            },
        )

    def _fallback_command_for_current_task(self) -> str:
        """Deterministic recovery command for empty/invalid agent output."""
        step_num = self._state.step_count

        if self._current_task_id == "task_easy_ssh":
            if step_num <= 1:
                return "describe_instances"
            if step_num == 2:
                return "describe_security_groups --group-id sg-web"
            return "revoke_security_group_ingress --group-id sg-web --port 22 --cidr 0.0.0.0/0"

        if self._current_task_id == "task_easy_http":
            if step_num <= 1:
                return "describe_instances"
            if step_num == 2:
                return "describe_security_groups --group-id sg-web"
            return "revoke_security_group_ingress --group-id sg-web --port 80 --cidr 0.0.0.0/0"

        if self._current_task_id == "task_medium_s3":
            if step_num <= 1:
                return "describe_buckets"
            return "put_public_access_block --bucket customer-backup-prod --block-public-read true"

        if self._current_task_id == "task_medium_iam":
            if step_num <= 1:
                return "describe_iam_users"
            if step_num == 2:
                return "list_access_keys --user-name bob-ops"
            return (
                "update_access_key --user-name bob-ops "
                "--access-key-id AKIABOB001 --status Inactive"
            )

        if self._current_task_id == "task_medium_network":
            if step_num <= 1:
                return "describe_security_groups --group-id sg-internal"
            return "authorize_security_group_ingress --group-id sg-internal --port 443 --cidr 10.0.0.0/16"

        if self._current_task_id == "task_medium_imdsv2":
            if step_num <= 1:
                return "describe_instance_metadata_options"
            return (
                "modify_instance_metadata_options --instance-id i-web-01 "
                "--http-tokens required --http-endpoint enabled"
            )

        if self._current_task_id == "task_easy_encryption":
            if step_num <= 1:
                return "describe_buckets"
            return "put_bucket_encryption --bucket customer-backup-prod --algorithm aws:kms"

        if self._current_task_id == "task_hard_iam":
            if step_num <= 1:
                return "describe_iam_users"
            if step_num == 2:
                return "list_attached_user_policies --user-name alice-admin"
            if step_num == 3:
                return "list_access_keys --user-name alice-admin"

            user = self._get_iam_user("alice-admin")
            if user:
                for key in user.get("access_keys", []):
                    if key.get("status") == "Active":
                        return (
                            "update_access_key --user-name alice-admin "
                            f"--access-key-id {key.get('id')} --status Inactive"
                        )
            return "list_access_keys --user-name alice-admin"

        if self._current_task_id == "task_hard_chain":
            if step_num <= 1:
                return "describe_buckets"
            if step_num == 2:
                return "put_public_access_block --bucket customer-backup-prod --block-public-read true"
            if step_num == 3:
                return "list_access_keys --user-name alice-admin"

            user = self._get_iam_user("alice-admin")
            if user:
                for key in user.get("access_keys", []):
                    if key.get("status") == "Active":
                        return (
                            "update_access_key --user-name alice-admin "
                            f"--access-key-id {key.get('id')} --status Inactive"
                        )
            return "list_access_keys --user-name alice-admin"

        if self._current_task_id == "task_hard_iam_policy":
            if step_num <= 1:
                return "describe_iam_users"
            if step_num == 2:
                return "list_access_keys --user-name bob-ops"
            if step_num == 3:
                return "list_roles"
            if step_num == 4:
                return (
                    "detach_role_policy --role-name app-runtime-role "
                    "--policy-arn arn:aws:iam::123456789012:policy/WildcardAdminPolicy"
                )
            return (
                "update_access_key --user-name bob-ops "
                "--access-key-id AKIABOB001 --status Inactive"
            )

        if self._current_task_id == "task_hard_s3_guardrails":
            if step_num <= 1:
                return "describe_account_public_access_block"
            if step_num == 2:
                return "put_account_public_access_block"
            if step_num == 3:
                return "describe_buckets"
            return "put_bucket_encryption --bucket customer-backup-prod --algorithm AES256"

        if self._current_task_id == "task_hard_compliance":
            if step_num <= 1:
                return "describe_trail"
            if step_num == 2:
                return "start_trail"
            return "put_bucket_encryption --bucket audit-logs-trail --algorithm aws:kms"

        return "describe_instances"

    def _grade_current_task(self) -> float:
        if self._current_task_id == "task_easy_ssh":
            return self._grade_easy_ssh()
        if self._current_task_id == "task_easy_http":
            return self._grade_easy_http()
        if self._current_task_id == "task_easy_encryption":
            return self._grade_easy_encryption()
        if self._current_task_id == "task_medium_s3":
            return self._grade_medium_s3()
        if self._current_task_id == "task_medium_iam":
            return self._grade_medium_iam()
        if self._current_task_id == "task_medium_network":
            return self._grade_medium_network()
        if self._current_task_id == "task_medium_imdsv2":
            return self._grade_medium_imdsv2()
        if self._current_task_id == "task_hard_iam":
            return self._grade_hard_iam()
        if self._current_task_id == "task_hard_iam_policy":
            return self._grade_hard_iam_policy()
        if self._current_task_id == "task_hard_chain":
            return self._grade_hard_chain()
        if self._current_task_id == "task_hard_s3_guardrails":
            return self._grade_hard_s3_guardrails()
        if self._current_task_id == "task_hard_compliance":
            return self._grade_hard_compliance()
        return 0.02

    def _grade_easy_ssh(self) -> float:
        """Continuous scoring for SSH security group remediation task."""
        if self._is_easy_ssh_complete():
            return 0.98

        # Continuous reward based on commands executed and progress flags
        score = 0.02  # Base score (never 0)
        
        if "easy_used_describe_instances" in self._progress_flags:
            score = max(score, 0.12)
        if "easy_found_web_server" in self._progress_flags:
            score = max(score, 0.18)
        if "easy_identified_target_sg" in self._progress_flags:
            score = max(score, 0.55)
        
        # Bonus for getting close to solution (identified target and tried remediation)
        if "easy_identified_target_sg" in self._progress_flags and self._state.step_count > 1:
            score = max(score, 0.65)
        
        return min(0.97, score)

    def _grade_easy_http(self) -> float:
        """Continuous scoring for HTTP security group remediation task."""
        if self._is_easy_http_complete():
            return 0.98

        score = 0.02
        
        if "easy_http_used_describe_instances" in self._progress_flags:
            score = max(score, 0.12)
        if "easy_http_found_web_server" in self._progress_flags:
            score = max(score, 0.18)
        if "easy_http_identified_target_sg" in self._progress_flags:
            score = max(score, 0.55)
        
        if "easy_http_identified_target_sg" in self._progress_flags and self._state.step_count > 1:
            score = max(score, 0.65)
        
        return min(0.97, score)

    def _grade_medium_s3(self) -> float:
        """Continuous scoring for S3 public access remediation."""
        if self._is_medium_s3_complete():
            return 0.98

        score = 0.02
        
        if "medium_used_describe_buckets" in self._progress_flags:
            score = max(score, 0.15)
        if "medium_found_target_bucket" in self._progress_flags:
            score = max(score, 0.35)
        
        # Add points if agent is exploring bucket configs
        if "medium_found_target_bucket" in self._progress_flags and self._state.step_count > 1:
            score = max(score, 0.50)
        
        return min(0.97, score)

    def _grade_medium_iam(self) -> float:
        """Continuous scoring for IAM access key disabling."""
        if self._is_medium_iam_complete():
            return 0.98

        score = 0.02
        
        if "medium_iam_used_describe_iam_users" in self._progress_flags:
            score = max(score, 0.18)
        if "medium_iam_listed_keys" in self._progress_flags:
            score = max(score, 0.45)
        
        # Bonus for getting close to solution
        if "medium_iam_listed_keys" in self._progress_flags and self._state.step_count > 2:
            score = max(score, 0.70)
        
        return min(0.97, score)

    def _grade_hard_iam(self) -> float:
        """Continuous scoring for admin user access key disabling."""
        if self._is_hard_iam_complete():
            return 0.99

        score = 0.02
        inactive_count = self._hard_iam_inactive_key_count()
        
        if "hard_used_describe_iam_users" in self._progress_flags:
            score = max(score, 0.12)
        if "hard_identified_admin_user" in self._progress_flags:
            score = max(score, 0.28)
        if "hard_listed_target_keys" in self._progress_flags:
            score = max(score, 0.48)
        
        # Continuous reward based on how many keys are disabled
        if inactive_count == 1:
            score = max(score, 0.80)
        elif inactive_count >= 2:
            score = max(score, 0.95)
        
        return min(0.97, score)

    def _grade_easy_encryption(self) -> float:
        """Continuous scoring for S3 KMS encryption enablement."""
        if self._is_easy_encryption_complete():
            return 0.98
        
        score = 0.02
        
        if "easy_enc_used_describe_buckets" in self._progress_flags:
            score = max(score, 0.15)
        if "easy_enc_found_target_bucket" in self._progress_flags:
            score = max(score, 0.45)
        if "easy_enc_found_target_bucket" in self._progress_flags and self._state.step_count > 1:
            score = max(score, 0.70)
        
        return min(0.97, score)

    def _grade_medium_network(self) -> float:
        """Continuous scoring for security group CIDR restriction."""
        if self._is_medium_network_complete():
            return 0.98
        
        score = 0.02
        
        if "medium_net_used_describe_sg" in self._progress_flags:
            score = max(score, 0.15)
        if "medium_net_identified_sg" in self._progress_flags:
            score = max(score, 0.50)
        if "medium_net_identified_sg" in self._progress_flags and self._state.step_count > 1:
            score = max(score, 0.70)
        
        return min(0.97, score)

    def _grade_medium_imdsv2(self) -> float:
        """Continuous scoring for IMDSv2 enforcement."""
        if self._is_medium_imdsv2_complete():
            return 0.98

        score = 0.02
        if "medium_imds_used_describe_instances" in self._progress_flags:
            score = max(score, 0.12)
        if "medium_imds_identified_vulnerable" in self._progress_flags:
            score = max(score, 0.42)
        if "medium_imds_modified_instance" in self._progress_flags:
            score = max(score, 0.76)
        return min(0.97, score)

    def _grade_hard_compliance(self) -> float:
        """Continuous scoring for CloudTrail + S3 encryption setup."""
        if self._is_hard_compliance_complete():
            return 0.99
        
        score = 0.02
        trail_enabled = self._world_state.get("cloudtrail", {}).get("enabled", False)
        s3_encrypted = self._is_audit_bucket_encrypted()
        
        if "hard_comp_used_describe_trail" in self._progress_flags:
            score = max(score, 0.12)
        if "hard_comp_enabled_trail" in self._progress_flags:
            score = max(score, 0.48)
        if "hard_comp_encrypted_audit_bucket" in self._progress_flags:
            score = max(score, 0.60)
        
        # Combined progress
        if trail_enabled and s3_encrypted:
            score = max(score, 0.95)
        elif trail_enabled or s3_encrypted:
            score = max(score, 0.65)
        
        return min(0.98, score)

    def _grade_hard_iam_policy(self) -> float:
        """Continuous scoring for stale key and wildcard policy remediation."""
        if self._is_hard_iam_policy_complete():
            return 0.99

        score = 0.02
        if "hard_iam_policy_used_describe_iam_users" in self._progress_flags:
            score = max(score, 0.10)
        if "hard_iam_policy_listed_bob_keys" in self._progress_flags:
            score = max(score, 0.35)
        if "hard_iam_policy_listed_roles" in self._progress_flags:
            score = max(score, 0.45)
        if "hard_iam_policy_detached_wildcard" in self._progress_flags:
            score = max(score, 0.70)
        if self._is_bob_key_inactive():
            score = max(score, 0.80)
        return min(0.98, score)

    def _grade_hard_s3_guardrails(self) -> float:
        """Continuous scoring for account-level and bucket-level S3 hardening."""
        if self._is_hard_s3_guardrails_complete():
            return 0.99

        score = 0.02
        if "hard_s3_guard_used_describe_buckets" in self._progress_flags:
            score = max(score, 0.12)
        if "hard_s3_guard_checked_account_block" in self._progress_flags:
            score = max(score, 0.30)
        if self._is_account_public_block_enabled():
            score = max(score, 0.62)
        if self._is_bucket_encrypted("customer-backup-prod"):
            score = max(score, 0.80)
        return min(0.98, score)

    def _grade_hard_chain(self) -> float:
        """Continuous scoring for chained remediation (S3 + IAM)."""
        if self._is_hard_chain_complete():
            return 0.99

        s3_fixed = self._is_medium_s3_complete()
        inactive_count = self._hard_iam_inactive_key_count()
        
        score = 0.02
        
        if "hard_chain_used_describe_buckets" in self._progress_flags:
            score = max(score, 0.10)
        if "hard_chain_listed_target_keys" in self._progress_flags:
            score = max(score, 0.25)
        
        # Linear combination of both task components
        s3_portion = 0.40 if s3_fixed else (0.15 if "hard_chain_used_describe_buckets" in self._progress_flags else 0.02)
        iam_portion = 0.58 * (inactive_count / 2.0) if inactive_count > 0 else 0.02
        
        score = max(score, min(0.97, s3_portion + iam_portion))
        
        return score

    def _is_task_complete(self) -> bool:
        if self._current_task_id == "task_easy_ssh":
            return self._is_easy_ssh_complete()
        if self._current_task_id == "task_easy_http":
            return self._is_easy_http_complete()
        if self._current_task_id == "task_easy_encryption":
            return self._is_easy_encryption_complete()
        if self._current_task_id == "task_medium_s3":
            return self._is_medium_s3_complete()
        if self._current_task_id == "task_medium_iam":
            return self._is_medium_iam_complete()
        if self._current_task_id == "task_medium_network":
            return self._is_medium_network_complete()
        if self._current_task_id == "task_medium_imdsv2":
            return self._is_medium_imdsv2_complete()
        if self._current_task_id == "task_hard_iam":
            return self._is_hard_iam_complete()
        if self._current_task_id == "task_hard_iam_policy":
            return self._is_hard_iam_policy_complete()
        if self._current_task_id == "task_hard_chain":
            return self._is_hard_chain_complete()
        if self._current_task_id == "task_hard_s3_guardrails":
            return self._is_hard_s3_guardrails_complete()
        if self._current_task_id == "task_hard_compliance":
            return self._is_hard_compliance_complete()
        return False

    def _is_easy_ssh_complete(self) -> bool:
        sg = self._world_state["security_groups"].get("sg-web")
        if not sg:
            return False
        for rule in sg["ingress"]:
            if rule["port"] == 22 and rule["cidr"] == "0.0.0.0/0":
                return False
        return True

    def _is_easy_http_complete(self) -> bool:
        sg = self._world_state["security_groups"].get("sg-web")
        if not sg:
            return False
        for rule in sg["ingress"]:
            if rule["port"] == 80 and rule["cidr"] == "0.0.0.0/0":
                return False
        return True

    def _is_easy_encryption_complete(self) -> bool:
        bucket = self._get_bucket("customer-backup-prod")
        return bool(bucket) and bucket.get("kms_encrypted", False)

    def _is_medium_s3_complete(self) -> bool:
        bucket = self._get_bucket("customer-backup-prod")
        return bool(bucket) and not bucket["public_read"]

    def _is_medium_iam_complete(self) -> bool:
        user = self._get_iam_user("bob-ops")
        if not user or not user.get("access_keys"):
            return False
        return user["access_keys"][0]["status"] == "Inactive"

    def _is_medium_network_complete(self) -> bool:
        sg = self._world_state["security_groups"].get("sg-internal")
        if not sg:
            return False
        for rule in sg["ingress"]:
            if rule["port"] == 443 and rule["cidr"] == "0.0.0.0/0":
                return False
        return any(
            rule["port"] == 443 and rule["cidr"] == "10.0.0.0/16"
            for rule in sg["ingress"]
        )

    def _is_medium_imdsv2_complete(self) -> bool:
        return all(
            instance.get("metadata_options", {}).get("http_tokens") == "required"
            for instance in self._world_state["ec2_instances"]
        )

    def _is_audit_bucket_encrypted(self) -> bool:
        bucket = self._get_bucket("audit-logs-trail")
        return bool(bucket) and bucket.get("kms_encrypted", False)

    def _is_hard_compliance_complete(self) -> bool:
        trail_enabled = self._world_state.get("cloudtrail", {}).get("enabled", False)
        return trail_enabled and self._is_audit_bucket_encrypted()

    def _is_bob_key_inactive(self) -> bool:
        user = self._get_iam_user("bob-ops")
        if not user or not user.get("access_keys"):
            return False
        return user["access_keys"][0]["status"] == "Inactive"

    def _is_wildcard_policy_detached(self) -> bool:
        role = self._get_iam_role("app-runtime-role")
        if not role:
            return False
        return "WildcardAdminPolicy" not in role.get("attached_policies", [])

    def _is_hard_iam_policy_complete(self) -> bool:
        return self._is_bob_key_inactive() and self._is_wildcard_policy_detached()

    def _is_account_public_block_enabled(self) -> bool:
        block = self._world_state.get("account_public_access_block", {})
        expected_keys = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]
        return all(block.get(key, False) for key in expected_keys)

    def _is_bucket_encrypted(self, bucket_name: str) -> bool:
        bucket = self._get_bucket(bucket_name)
        return bool(bucket) and bucket.get("kms_encrypted", False)

    def _is_hard_s3_guardrails_complete(self) -> bool:
        return self._is_account_public_block_enabled() and self._is_bucket_encrypted(
            "customer-backup-prod"
        )

    def _hard_iam_inactive_key_count(self) -> int:
        user = self._get_iam_user("alice-admin")
        if not user:
            return 0
        return sum(1 for key in user["access_keys"] if key["status"] == "Inactive")

    def _is_hard_iam_complete(self) -> bool:
        return self._hard_iam_inactive_key_count() == 2

    def _is_hard_chain_complete(self) -> bool:
        return self._is_medium_s3_complete() and self._is_hard_iam_complete()

    def _parse_command(self, command_text: str) -> tuple[str, dict[str, str], str | None]:
        try:
            tokens = shlex.split(command_text)
        except ValueError as err:
            return "", {}, str(err)

        if not tokens:
            return "", {}, "empty command"

        command_name = tokens[0].strip()
        args: dict[str, str] = {}
        idx = 1
        while idx < len(tokens):
            token = tokens[idx]
            if not token.startswith("--"):
                return command_name, {}, f"expected option, got '{token}'"
            if idx + 1 >= len(tokens):
                return command_name, {}, f"missing value for option '{token}'"
            key = token[2:]
            value = tokens[idx + 1]
            args[key] = value
            idx += 2

        return command_name, args, None

    def _award_once(self, flag: str, amount: float) -> float:
        if flag in self._progress_flags:
            return 0.0
        self._progress_flags.add(flag)
        return amount

    def _cmd_describe_instances(self, _args: dict[str, str]) -> tuple[str, float]:
        reward = 0.0
        if self._current_task_id == "task_easy_ssh":
            reward += self._award_once("easy_used_describe_instances", 0.10)
            reward += self._award_once("easy_found_web_server", 0.20)
        if self._current_task_id == "task_easy_http":
            reward += self._award_once("easy_http_used_describe_instances", 0.10)
            reward += self._award_once("easy_http_found_web_server", 0.20)
        if self._current_task_id == "task_medium_imdsv2":
            reward += self._award_once("medium_imds_used_describe_instances", 0.08)
            if any(
                inst.get("metadata_options", {}).get("http_tokens") == "optional"
                for inst in self._world_state["ec2_instances"]
            ):
                reward += self._award_once("medium_imds_identified_vulnerable", 0.15)

        payload = {"instances": self._world_state["ec2_instances"]}
        return json.dumps(payload, indent=2), reward

    def _cmd_describe_instance_metadata_options(
        self, _args: dict[str, str]
    ) -> tuple[str, float]:
        reward = 0.0
        if self._current_task_id == "task_medium_imdsv2":
            reward += self._award_once("medium_imds_used_describe_instances", 0.10)

        details = []
        vulnerable_found = False
        for instance in self._world_state["ec2_instances"]:
            metadata = instance.get("metadata_options", {})
            tokens = metadata.get("http_tokens", "optional")
            if tokens == "optional":
                vulnerable_found = True
            details.append(
                {
                    "instance_id": instance["instance_id"],
                    "name": instance["name"],
                    "http_tokens": tokens,
                    "http_endpoint": metadata.get("http_endpoint", "enabled"),
                }
            )

        if self._current_task_id == "task_medium_imdsv2" and vulnerable_found:
            reward += self._award_once("medium_imds_identified_vulnerable", 0.18)

        payload = {"instance_metadata_options": details}
        return json.dumps(payload, indent=2), reward

    def _cmd_modify_instance_metadata_options(
        self, args: dict[str, str]
    ) -> tuple[str, float]:
        instance_id = self._required_arg(args, "instance-id")
        http_tokens = self._required_arg(args, "http-tokens")
        http_endpoint = args.get("http-endpoint", "enabled")

        if http_tokens not in {"required", "optional"}:
            raise ValueError("http-tokens must be required or optional")
        if http_endpoint not in {"enabled", "disabled"}:
            raise ValueError("http-endpoint must be enabled or disabled")

        target = None
        for instance in self._world_state["ec2_instances"]:
            if instance["instance_id"] == instance_id:
                target = instance
                break
        if not target:
            raise ValueError(f"instance '{instance_id}' not found")

        target.setdefault("metadata_options", {})
        target["metadata_options"]["http_tokens"] = http_tokens
        target["metadata_options"]["http_endpoint"] = http_endpoint

        reward = 0.0
        if (
            self._current_task_id == "task_medium_imdsv2"
            and http_tokens == "required"
            and http_endpoint == "enabled"
        ):
            reward += self._award_once("medium_imds_modified_instance", 0.35)

        payload = {
            "instance_id": instance_id,
            "http_tokens": http_tokens,
            "http_endpoint": http_endpoint,
        }
        return json.dumps(payload, indent=2), reward

    def _cmd_describe_security_groups(self, args: dict[str, str]) -> tuple[str, float]:
        group_id = args.get("group-id")
        groups = self._world_state["security_groups"]

        if group_id:
            group = groups.get(group_id)
            if not group:
                raise ValueError(f"security group '{group_id}' not found")
            payload = {"security_groups": [{"group_id": group_id, **group}]}
            reward = 0.0
            if self._current_task_id == "task_easy_ssh" and group_id == "sg-web":
                reward += self._award_once("easy_identified_target_sg", 0.15)
            if self._current_task_id == "task_easy_http" and group_id == "sg-web":
                reward += self._award_once("easy_http_identified_target_sg", 0.15)
            if self._current_task_id == "task_medium_network" and group_id == "sg-internal":
                reward += self._award_once("medium_net_used_describe_sg", 0.10)
                reward += self._award_once("medium_net_identified_sg", 0.18)
            return json.dumps(payload, indent=2), reward

        payload = {
            "security_groups": [
                {"group_id": gid, **group} for gid, group in groups.items()
            ]
        }
        reward = 0.0
        if self._current_task_id == "task_easy_ssh":
            reward += self._award_once("easy_identified_target_sg", 0.15)
        if self._current_task_id == "task_easy_http":
            reward += self._award_once("easy_http_identified_target_sg", 0.15)
        if self._current_task_id == "task_medium_network":
            reward += self._award_once("medium_net_used_describe_sg", 0.10)
            reward += self._award_once("medium_net_identified_sg", 0.18)
        return json.dumps(payload, indent=2), reward

    def _cmd_revoke_security_group_ingress(
        self, args: dict[str, str]
    ) -> tuple[str, float]:
        group_id = self._required_arg(args, "group-id")
        port_raw = self._required_arg(args, "port")
        cidr = self._required_arg(args, "cidr")

        try:
            port = int(port_raw)
        except ValueError as err:
            raise ValueError("port must be an integer") from err

        group = self._world_state["security_groups"].get(group_id)
        if not group:
            raise ValueError(f"security group '{group_id}' not found")

        before = len(group["ingress"])
        group["ingress"] = [
            rule
            for rule in group["ingress"]
            if not (rule["port"] == port and rule["cidr"] == cidr)
        ]
        removed = before - len(group["ingress"])

        reward = 0.0
        if (
            self._current_task_id == "task_easy_ssh"
            and group_id == "sg-web"
            and port == 22
            and cidr == "0.0.0.0/0"
            and removed > 0
        ):
            reward += self._award_once("easy_revoked_ssh", 0.35)
        if (
            self._current_task_id == "task_easy_http"
            and group_id == "sg-web"
            and port == 80
            and cidr == "0.0.0.0/0"
            and removed > 0
        ):
            reward += self._award_once("easy_http_revoked_http", 0.35)

        payload = {
            "group_id": group_id,
            "removed_rules": removed,
            "remaining_ingress": group["ingress"],
        }
        return json.dumps(payload, indent=2), reward

    def _cmd_describe_buckets(self, _args: dict[str, str]) -> tuple[str, float]:
        reward = 0.0
        if self._current_task_id == "task_medium_s3":
            reward += self._award_once("medium_used_describe_buckets", 0.08)
            reward += self._award_once("medium_found_target_bucket", 0.15)
        if self._current_task_id == "task_easy_encryption":
            reward += self._award_once("easy_enc_used_describe_buckets", 0.08)
            reward += self._award_once("easy_enc_found_target_bucket", 0.15)
        if self._current_task_id == "task_hard_chain":
            reward += self._award_once("hard_chain_used_describe_buckets", 0.08)
            reward += self._award_once("hard_chain_found_target_bucket", 0.12)
        if self._current_task_id == "task_hard_s3_guardrails":
            reward += self._award_once("hard_s3_guard_used_describe_buckets", 0.08)

        payload = {"buckets": self._world_state["s3_buckets"]}
        return json.dumps(payload, indent=2), reward

    def _cmd_describe_account_public_access_block(
        self, _args: dict[str, str]
    ) -> tuple[str, float]:
        reward = 0.0
        if self._current_task_id == "task_hard_s3_guardrails":
            reward += self._award_once("hard_s3_guard_checked_account_block", 0.18)

        payload = {
            "account_public_access_block": self._world_state.get(
                "account_public_access_block", {}
            )
        }
        return json.dumps(payload, indent=2), reward

    def _cmd_put_account_public_access_block(
        self, _args: dict[str, str]
    ) -> tuple[str, float]:
        self._world_state["account_public_access_block"] = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

        reward = 0.0
        if self._current_task_id == "task_hard_s3_guardrails":
            reward += self._award_once("hard_s3_guard_enabled_account_block", 0.30)

        payload = {
            "status": "updated",
            "account_public_access_block": self._world_state[
                "account_public_access_block"
            ],
        }
        return json.dumps(payload, indent=2), reward

    def _cmd_put_public_access_block(self, args: dict[str, str]) -> tuple[str, float]:
        bucket_name = self._required_arg(args, "bucket")
        block_public_read = self._required_arg(args, "block-public-read")
        normalized = block_public_read.strip().lower()
        if normalized not in {"true", "false"}:
            raise ValueError("block-public-read must be true or false")

        desired_public_read = normalized == "false"

        bucket = self._get_bucket(bucket_name)
        if not bucket:
            raise ValueError(f"bucket '{bucket_name}' not found")

        bucket["public_read"] = desired_public_read

        reward = 0.0
        if (
            self._current_task_id == "task_medium_s3"
            and bucket_name == "customer-backup-prod"
            and normalized == "true"
        ):
            reward += self._award_once("medium_disabled_public_read", 0.45)
        if (
            self._current_task_id == "task_hard_chain"
            and bucket_name == "customer-backup-prod"
            and normalized == "true"
        ):
            reward += self._award_once("hard_chain_disabled_public_read", 0.30)

        payload = {
            "bucket": bucket_name,
            "public_read": bucket["public_read"],
        }
        return json.dumps(payload, indent=2), reward

    def _cmd_describe_iam_users(self, _args: dict[str, str]) -> tuple[str, float]:
        reward = 0.0
        if self._current_task_id == "task_hard_iam":
            reward += self._award_once("hard_used_describe_iam_users", 0.10)
        if self._current_task_id == "task_medium_iam":
            reward += self._award_once("medium_iam_used_describe_iam_users", 0.10)
        if self._current_task_id == "task_hard_chain":
            reward += self._award_once("hard_chain_used_describe_iam_users", 0.08)
        if self._current_task_id == "task_hard_iam_policy":
            reward += self._award_once("hard_iam_policy_used_describe_iam_users", 0.08)

        payload = {"users": self._world_state["iam_users"]}
        return json.dumps(payload, indent=2), reward

    def _cmd_list_roles(self, _args: dict[str, str]) -> tuple[str, float]:
        reward = 0.0
        if self._current_task_id == "task_hard_iam_policy":
            reward += self._award_once("hard_iam_policy_listed_roles", 0.12)

        payload = {"roles": self._world_state.get("iam_roles", [])}
        return json.dumps(payload, indent=2), reward

    def _cmd_list_attached_user_policies(
        self, args: dict[str, str]
    ) -> tuple[str, float]:
        user_name = self._required_arg(args, "user-name")
        user = self._get_iam_user(user_name)
        if not user:
            raise ValueError(f"user '{user_name}' not found")

        reward = 0.0
        if self._current_task_id == "task_hard_iam" and user_name == "alice-admin":
            reward += self._award_once("hard_identified_admin_user", 0.15)

        payload = {"user_name": user_name, "attached_policies": user["policies"]}
        return json.dumps(payload, indent=2), reward

    def _cmd_list_access_keys(self, args: dict[str, str]) -> tuple[str, float]:
        user_name = self._required_arg(args, "user-name")
        user = self._get_iam_user(user_name)
        if not user:
            raise ValueError(f"user '{user_name}' not found")

        reward = 0.0
        if self._current_task_id == "task_hard_iam" and user_name == "alice-admin":
            reward += self._award_once("hard_listed_target_keys", 0.20)
        if self._current_task_id == "task_medium_iam" and user_name == "bob-ops":
            reward += self._award_once("medium_iam_listed_keys", 0.20)
        if self._current_task_id == "task_hard_chain" and user_name == "alice-admin":
            reward += self._award_once("hard_chain_listed_target_keys", 0.18)
        if self._current_task_id == "task_hard_iam_policy" and user_name == "bob-ops":
            reward += self._award_once("hard_iam_policy_listed_bob_keys", 0.18)

        payload = {"user_name": user_name, "access_keys": user["access_keys"]}
        return json.dumps(payload, indent=2), reward

    def _cmd_detach_role_policy(self, args: dict[str, str]) -> tuple[str, float]:
        role_name = self._required_arg(args, "role-name")
        policy_arn = self._required_arg(args, "policy-arn")

        role = self._get_iam_role(role_name)
        if not role:
            raise ValueError(f"role '{role_name}' not found")

        before = len(role.get("attached_policies", []))
        role["attached_policies"] = [
            policy
            for policy in role.get("attached_policies", [])
            if policy.get("arn") != policy_arn
        ]
        detached = before - len(role["attached_policies"])

        reward = 0.0
        if (
            self._current_task_id == "task_hard_iam_policy"
            and role_name == "app-runtime-role"
            and policy_arn.endswith(":policy/WildcardAdminPolicy")
            and detached > 0
        ):
            reward += self._award_once("hard_iam_policy_detached_wildcard", 0.35)

        payload = {
            "role_name": role_name,
            "policy_arn": policy_arn,
            "detached": detached,
            "remaining_policies": role["attached_policies"],
        }
        return json.dumps(payload, indent=2), reward

    def _cmd_update_access_key(self, args: dict[str, str]) -> tuple[str, float]:
        user_name = self._required_arg(args, "user-name")
        key_id = self._required_arg(args, "access-key-id")
        status = self._required_arg(args, "status")

        if status not in {"Active", "Inactive"}:
            raise ValueError("status must be Active or Inactive")

        user = self._get_iam_user(user_name)
        if not user:
            raise ValueError(f"user '{user_name}' not found")

        target_key = None
        for key in user["access_keys"]:
            if key["id"] == key_id:
                target_key = key
                break

        if target_key is None:
            raise ValueError(f"access key '{key_id}' not found for user '{user_name}'")

        target_key["status"] = status

        reward = 0.0
        if (
            self._current_task_id == "task_hard_iam"
            and user_name == "alice-admin"
            and status == "Inactive"
        ):
            reward += self._award_once(f"hard_disabled_key_{key_id}", 0.20)
        if (
            self._current_task_id == "task_medium_iam"
            and user_name == "bob-ops"
            and key_id == "AKIABOB001"
            and status == "Inactive"
        ):
            reward += self._award_once("medium_iam_disabled_key", 0.35)
        if (
            self._current_task_id == "task_hard_chain"
            and user_name == "alice-admin"
            and status == "Inactive"
        ):
            reward += self._award_once(f"hard_chain_disabled_key_{key_id}", 0.18)
        if (
            self._current_task_id == "task_hard_iam_policy"
            and user_name == "bob-ops"
            and key_id == "AKIABOB001"
            and status == "Inactive"
        ):
            reward += self._award_once("hard_iam_policy_disabled_bob_key", 0.30)

        payload = {
            "user_name": user_name,
            "access_key_id": key_id,
            "status": status,
        }
        return json.dumps(payload, indent=2), reward

    def _cmd_put_bucket_encryption(self, args: dict[str, str]) -> tuple[str, float]:
        bucket_name = self._required_arg(args, "bucket")
        algorithm = args.get("algorithm", "aws:kms")
        
        bucket = self._get_bucket(bucket_name)
        if not bucket:
            raise ValueError(f"bucket '{bucket_name}' not found")
        
        bucket["kms_encrypted"] = True
        bucket["encryption_algorithm"] = algorithm
        
        reward = 0.0
        if (
            self._current_task_id == "task_easy_encryption"
            and bucket_name == "customer-backup-prod"
        ):
            reward += self._award_once("easy_enc_enabled_kms", 0.40)
        if (
            self._current_task_id == "task_hard_compliance"
            and bucket_name == "audit-logs-trail"
        ):
            reward += self._award_once("hard_comp_encrypted_audit_bucket", 0.35)
        if (
            self._current_task_id == "task_hard_s3_guardrails"
            and bucket_name == "customer-backup-prod"
        ):
            reward += self._award_once("hard_s3_guard_encrypted_primary_bucket", 0.30)
        
        payload = {
            "bucket": bucket_name,
            "kms_encrypted": True,
            "encryption_algorithm": algorithm,
        }
        return json.dumps(payload, indent=2), reward

    def _cmd_authorize_security_group_ingress(self, args: dict[str, str]) -> tuple[str, float]:
        group_id = self._required_arg(args, "group-id")
        port_raw = self._required_arg(args, "port")
        cidr = self._required_arg(args, "cidr")
        protocol = args.get("protocol", "tcp")
        
        try:
            port = int(port_raw)
        except ValueError as err:
            raise ValueError("port must be an integer") from err
        
        group = self._world_state["security_groups"].get(group_id)
        if not group:
            raise ValueError(f"security group '{group_id}' not found")
        
        # Check if rule already exists
        new_rule = {"port": port, "protocol": protocol, "cidr": cidr}

        if (
            self._current_task_id == "task_medium_network"
            and group_id == "sg-internal"
            and port == 443
            and cidr == "10.0.0.0/16"
        ):
            group["ingress"] = [
                rule
                for rule in group["ingress"]
                if not (rule["port"] == 443 and rule["cidr"] == "0.0.0.0/0")
            ]

        if new_rule not in group["ingress"]:
            group["ingress"].append(new_rule)
        
        reward = 0.0
        if (
            self._current_task_id == "task_medium_network"
            and group_id == "sg-internal"
            and port == 443
            and cidr == "10.0.0.0/16"
        ):
            reward += self._award_once("medium_net_restricted_ingress", 0.40)
        
        payload = {
            "group_id": group_id,
            "added_rule": new_rule,
            "ingress": group["ingress"],
        }
        return json.dumps(payload, indent=2), reward

    def _cmd_describe_trail(self, _args: dict[str, str]) -> tuple[str, float]:
        reward = 0.0
        if self._current_task_id == "task_hard_compliance":
            reward += self._award_once("hard_comp_used_describe_trail", 0.15)
        
        trail = self._world_state.get("cloudtrail", {})
        payload = {
            "trail_name": "prod-audit-trail",
            "enabled": trail.get("enabled", False),
            "s3_bucket": trail.get("s3_bucket", "audit-logs-trail"),
            "log_format": trail.get("log_format", "JSON"),
        }
        return json.dumps(payload, indent=2), reward

    def _cmd_start_trail(self, _args: dict[str, str]) -> tuple[str, float]:
        self._world_state["cloudtrail"]["enabled"] = True
        
        reward = 0.0
        if self._current_task_id == "task_hard_compliance":
            reward += self._award_once("hard_comp_enabled_trail", 0.30)
        
        payload = {
            "trail_name": "prod-audit-trail",
            "status": "started",
            "enabled": True,
        }
        return json.dumps(payload, indent=2), reward

    @staticmethod
    def _required_arg(args: dict[str, str], key: str) -> str:
        if key not in args:
            raise ValueError(f"missing required option --{key}")
        value = args[key]
        if value is None or value.strip() == "":
            raise ValueError(f"option --{key} cannot be empty")
        return value

    def _get_bucket(self, bucket_name: str) -> dict | None:
        for bucket in self._world_state["s3_buckets"]:
            if bucket["name"] == bucket_name:
                return bucket
        return None

    def _get_iam_user(self, user_name: str) -> dict | None:
        for user in self._world_state["iam_users"]:
            if user["user_name"] == user_name:
                return user
        return None

    def _get_iam_role(self, role_name: str) -> dict | None:
        for role in self._world_state.get("iam_roles", []):
            if role["role_name"] == role_name:
                return role
        return None

    @staticmethod
    def _build_initial_world_state() -> dict:
        initial_state = {
            "ec2_instances": [
                {
                    "instance_id": "i-web-01",
                    "name": "prod-web-frontend",
                    "role": "web",
                    "public_ip": "54.31.22.10",
                    "security_groups": ["sg-web"],
                    "metadata_options": {
                        "http_tokens": "optional",
                        "http_endpoint": "enabled",
                    },
                },
                {
                    "instance_id": "i-batch-01",
                    "name": "nightly-batch",
                    "role": "batch",
                    "public_ip": None,
                    "security_groups": ["sg-internal"],
                    "metadata_options": {
                        "http_tokens": "required",
                        "http_endpoint": "enabled",
                    },
                },
            ],
            "security_groups": {
                "sg-web": {
                    "name": "web-sg",
                    "ingress": [
                        {"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0"},
                        {"port": 80, "protocol": "tcp", "cidr": "0.0.0.0/0"},
                    ],
                },
                "sg-internal": {
                    "name": "internal-sg",
                    "ingress": [
                        {"port": 443, "protocol": "tcp", "cidr": "0.0.0.0/0"}
                    ],
                },
            },
            "s3_buckets": [
                {
                    "name": "customer-backup-prod",
                    "purpose": "customer backups",
                    "public_read": True,
                    "encryption": "AES256",
                    "kms_encrypted": False,
                    "encryption_algorithm": None,
                },
                {
                    "name": "analytics-private",
                    "purpose": "analytics",
                    "public_read": False,
                    "encryption": "AES256",
                    "kms_encrypted": False,
                    "encryption_algorithm": None,
                },
                {
                    "name": "audit-logs-trail",
                    "purpose": "CloudTrail audit logs",
                    "public_read": False,
                    "encryption": None,
                    "kms_encrypted": False,
                    "encryption_algorithm": None,
                },
            ],
            "iam_users": [
                {
                    "user_name": "alice-admin",
                    "last_login_days": 140,
                    "policies": ["AdministratorAccess"],
                    "access_keys": [
                        {"id": "AKIAALICE001", "status": "Active"},
                        {"id": "AKIAALICE002", "status": "Active"},
                    ],
                },
                {
                    "user_name": "bob-ops",
                    "last_login_days": 12,
                    "policies": ["ReadOnlyAccess"],
                    "access_keys": [{"id": "AKIABOB001", "status": "Active"}],
                },
            ],
            "iam_roles": [
                {
                    "role_name": "app-runtime-role",
                    "attached_policies": [
                        {
                            "name": "WildcardAdminPolicy",
                            "arn": "arn:aws:iam::123456789012:policy/WildcardAdminPolicy",
                        },
                        {
                            "name": "ReadSecretsPolicy",
                            "arn": "arn:aws:iam::123456789012:policy/ReadSecretsPolicy",
                        },
                    ],
                }
            ],
            "account_public_access_block": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
            "cloudtrail": {
                "enabled": False,
                "s3_bucket": "audit-logs-trail",
                "log_format": "JSON",
            },
        }
        return copy.deepcopy(initial_state)
