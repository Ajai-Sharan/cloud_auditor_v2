#!/usr/bin/env python3
"""Test continuous scoring system."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models import CloudAuditorAction
from server.cloud_auditor_environment import CloudAuditorEnvironment


def test_continuous_scoring():
    """Verify scoring is continuous and avoids 0 or 1."""
    env = CloudAuditorEnvironment()
    
    # Test each task
    scores_collected = []
    
    for task_idx in range(len(env.TASK_ORDER)):
        obs = env.reset()
        task_id = obs.task_id
        print(f"\n{'='*60}")
        print(f"Task {task_idx}: {task_id}")
        print(f"{'='*60}")
        
        # Run through task steps and collect scores
        for step in range(5):
            if step == 0:
                cmd = "describe_instances"
            elif step == 1:
                cmd = "describe_security_groups"
            elif step == 2:
                cmd = "describe_buckets"
            elif step == 3:
                cmd = "describe_iam_users"
            else:
                cmd = "describe_instances"
            
            obs = env.step(CloudAuditorAction(command=cmd))
            score = obs.task_score
            scores_collected.append(score)
            
            print(f"Step {step}: score={score:.4f}, reward={obs.reward:.4f}, done={obs.done}")
            
            # Verify score is in valid range
            assert 0.0 < score < 1.0, f"Score {score} not in (0, 1)!"
            
            if obs.done:
                break
    
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Total scores collected: {len(scores_collected)}")
    print(f"Min score: {min(scores_collected):.4f}")
    print(f"Max score: {max(scores_collected):.4f}")
    print(f"Avg score: {sum(scores_collected)/len(scores_collected):.4f}")
    
    # Check for too many discrete values
    unique_scores = set(scores_collected)
    print(f"Unique score values: {len(unique_scores)}")
    
    if len(unique_scores) <= 6:
        print("⚠️  WARNING: Only {} unique scores - may be too discrete!".format(len(unique_scores)))
    else:
        print("✓ Good: {} unique scores shows continuous distribution".format(len(unique_scores)))
    
    # Verify no hard 0 or 1
    assert 0.0 not in scores_collected, "Found score of 0.0!"
    assert 1.0 not in scores_collected, "Found score of 1.0!"
    
    print("\n✓ All tests passed! Scoring is continuous and avoids 0/1.")


if __name__ == "__main__":
    test_continuous_scoring()
