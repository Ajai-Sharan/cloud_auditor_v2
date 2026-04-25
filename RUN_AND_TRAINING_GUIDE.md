# Run And Training Guide: CloudSecurityAuditor-v1

This guide explains:
- how to run the environment locally
- what is required for training
- how to generate training evidence (reward and loss plots)

## 1) Prerequisites

- Python 3.10+
- uv package manager
- Git (optional, for cloning)

Recommended machine:
- 4+ CPU cores
- 8 GB RAM

## 2) Install Dependencies

From the project root:

```bash
uv sync --extra dev --extra train
```

This installs:
- runtime dependencies
- test dependencies
- training dependencies (numpy, matplotlib)

## 3) Run The Environment Server

Start server:

```bash
uv run uvicorn server.app:app --host 127.0.0.1 --port 8000
```

Check it is up:
- Swagger: http://127.0.0.1:8000/docs
- ReDoc: http://127.0.0.1:8000/redoc

## 4) Quick Functional Check

In a new terminal:

```bash
curl -X POST http://127.0.0.1:8000/reset -H "Content-Type: application/json" -d "{}"
```

Then:

```bash
curl -X POST http://127.0.0.1:8000/step -H "Content-Type: application/json" -d '{"action": {"command": "describe_instances"}}'
```

## 5) Run Tests

Recommended validation:

```bash
uv run python -m pytest -q tests
```

## 6) Training: What You Need

For local policy training in this repo, you need:
- running local Python environment
- training extras installed
- no API key required

Why no API key is needed:
- training is done by train_live_policy.py directly against the in-memory environment
- it does not call an external LLM endpoint

## 7) Start Training

Run a full training job:

```bash
uv run --extra train python -m train_live_policy --episodes 400 --out-dir artifacts/training
```

Useful options:

```bash
uv run --extra train python -m train_live_policy --episodes 600 --lr 0.05 --gamma 0.97 --seed 7 --out-dir artifacts/training
```

## 8) Expected Training Outputs

After training completes, you should have:
- artifacts/training/training_metrics.csv
- artifacts/training/training_curves.png

The plot image contains:
- reward vs training step (episode)
- loss vs training step (episode)

These are the primary evidence artifacts judges usually ask for.

## 9) Colab Option

If you prefer notebook execution, use:
- training_colab.ipynb

It runs the same style of live-environment loop and produces equivalent artifacts.

## 10) Baseline Inference (Optional)

To run baseline-style inference script:

```bash
python inference.py > baseline_cloud_auditor.txt
```

Note:
- inference.py may require API_BASE_URL, API_KEY, MODEL_NAME if you use external model calls.
- local train_live_policy.py does not require those variables.

## 11) Common Issues

1. Command not found: uv
- Install uv, then rerun uv sync.

2. Port 8000 already in use
- Stop the existing process or run server on another port.

3. Empty or missing plots
- Verify training finished successfully.
- Re-run with fewer episodes first to smoke test:

```bash
uv run --extra train python -m train_live_policy --episodes 20 --out-dir artifacts/training_smoke
```

## 12) Suggested Submission Evidence Bundle

Include these files in your submission artifacts:
- artifacts/training/training_metrics.csv
- artifacts/training/training_curves.png
- baseline_cloud_auditor.txt (optional, but useful)
- RUN_AND_TRAINING_GUIDE.md
