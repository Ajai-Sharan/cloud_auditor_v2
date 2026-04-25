#!/usr/bin/env python3
"""Minimal live training loop for CloudSecurityAuditor-v1.

This script trains a simple policy-gradient agent directly against the live environment
class (not a static dataset) and writes reward/loss plots for hackathon evidence.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from models import CloudAuditorAction
from server.cloud_auditor_environment import CloudAuditorEnvironment


COMMAND_POOL = [
    "describe_instances",
    "describe_instance_metadata_options",
    "modify_instance_metadata_options --instance-id i-web-01 --http-tokens required --http-endpoint enabled",
    "describe_security_groups --group-id sg-web",
    "describe_security_groups --group-id sg-internal",
    "revoke_security_group_ingress --group-id sg-web --port 22 --cidr 0.0.0.0/0",
    "revoke_security_group_ingress --group-id sg-web --port 80 --cidr 0.0.0.0/0",
    "authorize_security_group_ingress --group-id sg-internal --port 443 --cidr 10.0.0.0/16",
    "describe_buckets",
    "put_public_access_block --bucket customer-backup-prod --block-public-read true",
    "put_bucket_encryption --bucket customer-backup-prod --algorithm aws:kms",
    "put_bucket_encryption --bucket audit-logs-trail --algorithm aws:kms",
    "describe_account_public_access_block",
    "put_account_public_access_block",
    "describe_iam_users",
    "list_roles",
    "detach_role_policy --role-name app-runtime-role --policy-arn arn:aws:iam::123456789012:policy/WildcardAdminPolicy",
    "list_attached_user_policies --user-name alice-admin",
    "list_access_keys --user-name alice-admin",
    "list_access_keys --user-name bob-ops",
    "update_access_key --user-name alice-admin --access-key-id AKIAALICE001 --status Inactive",
    "update_access_key --user-name alice-admin --access-key-id AKIAALICE002 --status Inactive",
    "update_access_key --user-name bob-ops --access-key-id AKIABOB001 --status Inactive",
    "describe_trail",
    "start_trail",
]


def softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - np.max(logits)
    exps = np.exp(shifted)
    return exps / np.sum(exps)


def discounted_returns(rewards: list[float], gamma: float) -> np.ndarray:
    out = np.zeros(len(rewards), dtype=np.float64)
    running = 0.0
    for i in range(len(rewards) - 1, -1, -1):
        running = rewards[i] + gamma * running
        out[i] = running
    if len(out) > 1:
        std = np.std(out)
        if std > 1e-9:
            out = (out - np.mean(out)) / std
    return out


def train(episodes: int, lr: float, gamma: float, seed: int, out_dir: Path) -> None:
    rng = np.random.default_rng(seed)
    env = CloudAuditorEnvironment()

    tasks = list(env.TASK_ORDER)
    task_to_idx = {task_id: idx for idx, task_id in enumerate(tasks)}

    n_tasks = len(tasks)
    n_cmds = len(COMMAND_POOL)

    # One trainable logits row per task.
    weights = np.zeros((n_tasks, n_cmds), dtype=np.float64)

    episode_rewards: list[float] = []
    episode_losses: list[float] = []
    episode_scores: list[float] = []

    out_dir.mkdir(parents=True, exist_ok=True)

    for ep in range(1, episodes + 1):
        obs = env.reset()
        task_idx = task_to_idx[obs.task_id]

        probs_trace: list[np.ndarray] = []
        cmd_idx_trace: list[int] = []
        rewards_trace: list[float] = []

        final_obs = obs

        for _ in range(env.MAX_STEPS):
            probs = softmax(weights[task_idx])
            cmd_idx = int(rng.choice(n_cmds, p=probs))
            cmd = COMMAND_POOL[cmd_idx]

            final_obs = env.step(CloudAuditorAction(command=cmd))

            probs_trace.append(probs)
            cmd_idx_trace.append(cmd_idx)
            rewards_trace.append(final_obs.reward)

            if final_obs.done:
                break

        returns = discounted_returns(rewards_trace, gamma)

        grad_row = np.zeros(n_cmds, dtype=np.float64)
        loss = 0.0
        for t, cmd_idx in enumerate(cmd_idx_trace):
            probs = probs_trace[t]
            one_hot = np.zeros(n_cmds, dtype=np.float64)
            one_hot[cmd_idx] = 1.0

            # Loss contribution: -G_t * log pi(a_t|s_t)
            logp = np.log(max(1e-9, probs[cmd_idx]))
            loss += -(returns[t] * logp)

            # Gradient of -G_t*log pi wrt logits.
            grad_row += -returns[t] * (one_hot - probs)

        weights[task_idx] -= lr * grad_row

        ep_reward = float(np.sum(rewards_trace))
        ep_score = float(final_obs.task_score)

        episode_rewards.append(ep_reward)
        episode_losses.append(float(loss))
        episode_scores.append(ep_score)

        if ep % 25 == 0 or ep == 1:
            print(
                f"episode={ep:04d} task={obs.task_id:<24} "
                f"steps={len(rewards_trace):02d} reward={ep_reward:+.3f} "
                f"score={ep_score:.3f} loss={loss:+.4f}"
            )

    # Persist metrics for auditability.
    metrics_path = out_dir / "training_metrics.csv"
    with metrics_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["episode", "reward", "loss", "final_score"])
        for i in range(len(episode_rewards)):
            writer.writerow([i + 1, episode_rewards[i], episode_losses[i], episode_scores[i]])

    # Plot reward and loss with explicit axis labels for judges.
    plt.figure(figsize=(12, 5))

    plt.subplot(1, 2, 1)
    plt.plot(range(1, episodes + 1), episode_rewards, label="Episode reward", alpha=0.8)
    if episodes >= 20:
        window = 20
        smooth = np.convolve(episode_rewards, np.ones(window) / window, mode="valid")
        plt.plot(range(window, episodes + 1), smooth, label="Reward (20-ep MA)", linewidth=2)
    plt.xlabel("training step (episode)")
    plt.ylabel("reward")
    plt.title("Live Environment Reward")
    plt.grid(alpha=0.25)
    plt.legend()

    plt.subplot(1, 2, 2)
    plt.plot(range(1, episodes + 1), episode_losses, color="tab:red", label="Policy loss")
    plt.xlabel("training step (episode)")
    plt.ylabel("loss")
    plt.title("Policy Gradient Loss")
    plt.grid(alpha=0.25)
    plt.legend()

    plt.tight_layout()
    plot_path = out_dir / "training_curves.png"
    plt.savefig(plot_path, dpi=180)
    plt.close()

    mean_reward = float(np.mean(episode_rewards[-50:])) if episodes >= 50 else float(np.mean(episode_rewards))
    mean_score = float(np.mean(episode_scores[-50:])) if episodes >= 50 else float(np.mean(episode_scores))

    print("\nTraining complete")
    print(f"metrics: {metrics_path}")
    print(f"plot:    {plot_path}")
    print(f"mean_reward(last_window)={mean_reward:.4f}")
    print(f"mean_score(last_window)={mean_score:.4f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train a lightweight RL policy on Cloud Auditor")
    parser.add_argument("--episodes", type=int, default=400)
    parser.add_argument("--lr", type=float, default=0.07)
    parser.add_argument("--gamma", type=float, default=0.97)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out-dir", type=Path, default=Path("artifacts/training"))
    args = parser.parse_args()

    train(
        episodes=args.episodes,
        lr=args.lr,
        gamma=args.gamma,
        seed=args.seed,
        out_dir=args.out_dir,
    )


if __name__ == "__main__":
    main()
