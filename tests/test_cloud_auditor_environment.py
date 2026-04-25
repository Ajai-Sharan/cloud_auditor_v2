import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models import CloudAuditorAction
from server.cloud_auditor_environment import CloudAuditorEnvironment


def _cmd(env: CloudAuditorEnvironment, command: str):
    return env.step(CloudAuditorAction(command=command))


def _reset_until_task(env: CloudAuditorEnvironment, task_id: str, max_attempts: int = 20):
    for _ in range(max_attempts):
        obs = env.reset()
        if obs.task_id == task_id:
            return obs
    raise AssertionError(f"task '{task_id}' not reached within {max_attempts} resets")


def test_reset_rotates_through_all_tasks_deterministically():
    env = CloudAuditorEnvironment()
    observed = [env.reset().task_id for _ in range(len(env.TASK_ORDER) + 1)]

    assert observed[: len(env.TASK_ORDER)] == env.TASK_ORDER
    assert observed[-1] == env.TASK_ORDER[0]


def test_easy_task_revoke_ssh_open_ingress():
    env = CloudAuditorEnvironment()
    reset_obs = env.reset()
    assert reset_obs.task_id == "task_easy_ssh"

    reconnaissance = _cmd(env, "describe_instances")
    assert reconnaissance.reward is not None
    assert reconnaissance.reward > 0.0

    remediation = _cmd(
        env,
        "revoke_security_group_ingress --group-id sg-web --port 22 --cidr 0.0.0.0/0",
    )
    assert remediation.done is True
    assert 0.0 < remediation.task_score < 1.0
    assert remediation.status == "completed"


def test_medium_task_disable_public_read():
    env = CloudAuditorEnvironment()
    reset_obs = _reset_until_task(env, "task_medium_s3")
    assert reset_obs.task_id == "task_medium_s3"

    _cmd(env, "describe_buckets")
    remediation = _cmd(
        env,
        "put_public_access_block --bucket customer-backup-prod --block-public-read true",
    )

    assert remediation.done is True
    assert 0.0 < remediation.task_score < 1.0


def test_hard_task_disable_admin_stale_keys():
    env = CloudAuditorEnvironment()
    reset_obs = _reset_until_task(env, "task_hard_iam")
    assert reset_obs.task_id == "task_hard_iam"

    _cmd(env, "describe_iam_users")
    _cmd(env, "list_attached_user_policies --user-name alice-admin")
    _cmd(env, "list_access_keys --user-name alice-admin")

    partial = _cmd(
        env,
        "update_access_key --user-name alice-admin --access-key-id AKIAALICE001 --status Inactive",
    )
    assert partial.task_score == 0.8
    assert partial.done is False

    final = _cmd(
        env,
        "update_access_key --user-name alice-admin --access-key-id AKIAALICE002 --status Inactive",
    )
    assert 0.0 < final.task_score < 1.0
    assert final.done is True


def test_reset_restores_world_state_to_deterministic_defaults():
    env = CloudAuditorEnvironment()
    env.reset()

    _cmd(env, "revoke_security_group_ingress --group-id sg-web --port 22 --cidr 0.0.0.0/0")

    # Rotate through the full cycle and return to easy task.
    for _ in range(len(env.TASK_ORDER)):
        env.reset()

    sg_obs = _cmd(env, "describe_security_groups --group-id sg-web")
    payload = json.loads(sg_obs.command_output)
    ingress = payload["security_groups"][0]["ingress"]

    assert {"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0"} in ingress


def test_unrecognized_command_is_penalized():
    env = CloudAuditorEnvironment()
    env.reset()

    bad = _cmd(env, "totally_unknown_command")

    assert bad.reward is not None
    assert bad.reward < 0.0
    assert "unrecognized command" in bad.command_output


def test_episode_ends_after_max_steps_even_if_incomplete():
    env = CloudAuditorEnvironment()
    env.reset()

    last = None
    for _ in range(env.MAX_STEPS):
        last = _cmd(env, "describe_security_groups")

    assert last is not None
    assert last.done is True
    assert last.status == "failed"


def test_easy_task_milestones_are_monotonic():
    env = CloudAuditorEnvironment()
    env.reset()

    step_a = _cmd(env, "describe_instances")
    step_b = _cmd(env, "describe_security_groups --group-id sg-web")
    step_c = _cmd(
        env,
        "revoke_security_group_ingress --group-id sg-web --port 22 --cidr 0.0.0.0/0",
    )

    assert step_b.task_score > step_a.task_score
    assert step_c.task_score > step_b.task_score


def test_score_does_not_decrease_after_completion():
    env = CloudAuditorEnvironment()
    env.reset()

    _cmd(
        env,
        "revoke_security_group_ingress --group-id sg-web --port 22 --cidr 0.0.0.0/0",
    )
    after_fix = _cmd(env, "describe_instances")

    assert after_fix.task_score >= 0.95


def test_easy_http_task_revoke_port_80():
    env = CloudAuditorEnvironment()
    reset_obs = _reset_until_task(env, "task_easy_http")
    assert reset_obs.task_id == "task_easy_http"

    _cmd(env, "describe_instances")
    final = _cmd(
        env,
        "revoke_security_group_ingress --group-id sg-web --port 80 --cidr 0.0.0.0/0",
    )
    assert final.done is True
    assert 0.0 < final.task_score < 1.0


def test_medium_iam_task_disable_bob_key():
    env = CloudAuditorEnvironment()
    reset_obs = _reset_until_task(env, "task_medium_iam")
    assert reset_obs.task_id == "task_medium_iam"

    _cmd(env, "describe_iam_users")
    _cmd(env, "list_access_keys --user-name bob-ops")
    final = _cmd(
        env,
        "update_access_key --user-name bob-ops --access-key-id AKIABOB001 --status Inactive",
    )
    assert final.done is True
    assert 0.0 < final.task_score < 1.0


def test_medium_network_requires_restriction_and_not_precompleted():
    env = CloudAuditorEnvironment()
    reset_obs = _reset_until_task(env, "task_medium_network")
    assert reset_obs.task_id == "task_medium_network"
    assert reset_obs.done is False

    before = _cmd(env, "describe_security_groups --group-id sg-internal")
    assert before.done is False

    final = _cmd(
        env,
        "authorize_security_group_ingress --group-id sg-internal --port 443 --cidr 10.0.0.0/16",
    )
    assert final.done is True
    assert 0.0 < final.task_score < 1.0


def test_medium_imdsv2_enforcement_flow():
    env = CloudAuditorEnvironment()
    reset_obs = _reset_until_task(env, "task_medium_imdsv2")
    assert reset_obs.task_id == "task_medium_imdsv2"

    _cmd(env, "describe_instance_metadata_options")
    final = _cmd(
        env,
        "modify_instance_metadata_options --instance-id i-web-01 --http-tokens required --http-endpoint enabled",
    )
    assert final.done is True
    assert 0.0 < final.task_score < 1.0


def test_hard_iam_policy_requires_key_disable_and_policy_detach():
    env = CloudAuditorEnvironment()
    reset_obs = _reset_until_task(env, "task_hard_iam_policy")
    assert reset_obs.task_id == "task_hard_iam_policy"

    _cmd(env, "describe_iam_users")
    _cmd(env, "list_access_keys --user-name bob-ops")
    _cmd(env, "list_roles")

    partial = _cmd(
        env,
        "detach_role_policy --role-name app-runtime-role --policy-arn arn:aws:iam::123456789012:policy/WildcardAdminPolicy",
    )
    assert partial.done is False

    final = _cmd(
        env,
        "update_access_key --user-name bob-ops --access-key-id AKIABOB001 --status Inactive",
    )
    assert final.done is True
    assert 0.0 < final.task_score < 1.0


def test_hard_s3_guardrails_requires_account_block_and_encryption():
    env = CloudAuditorEnvironment()
    reset_obs = _reset_until_task(env, "task_hard_s3_guardrails")
    assert reset_obs.task_id == "task_hard_s3_guardrails"

    _cmd(env, "describe_account_public_access_block")
    _cmd(env, "put_account_public_access_block")

    final = _cmd(
        env,
        "put_bucket_encryption --bucket customer-backup-prod --algorithm aws:kms",
    )
    assert final.done is True
    assert 0.0 < final.task_score < 1.0


def test_hard_chain_requires_s3_and_admin_key_remediation():
    env = CloudAuditorEnvironment()
    reset_obs = _reset_until_task(env, "task_hard_chain")
    assert reset_obs.task_id == "task_hard_chain"

    _cmd(env, "put_public_access_block --bucket customer-backup-prod --block-public-read true")
    partial = _cmd(
        env,
        "update_access_key --user-name alice-admin --access-key-id AKIAALICE001 --status Inactive",
    )
    assert partial.done is False
    assert 0.0 < partial.task_score < 0.95

    final = _cmd(
        env,
        "update_access_key --user-name alice-admin --access-key-id AKIAALICE002 --status Inactive",
    )
    assert final.done is True
    assert 0.0 < final.task_score < 1.0


def test_reset_observation_includes_expected_task_description():
    env = CloudAuditorEnvironment()
    obs = env.reset()

    expected = CloudAuditorEnvironment.TASK_SPECS[obs.task_id]["description"]
    assert obs.task_description == expected
    assert expected


def test_repeated_recon_does_not_farm_bonus():
    env = CloudAuditorEnvironment()
    env.reset()

    first = _cmd(env, "describe_instances")
    second = _cmd(env, "describe_instances")

    assert first.reward > 0.0
    assert second.reward <= 0.0
