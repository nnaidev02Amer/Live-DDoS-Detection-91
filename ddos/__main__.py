"""Command line tools (run from the project folder).

    python -m ddos sample  --out data
    python -m ddos train   --data data/synthetic_FlowStatsfile.csv --out models/rf.joblib
    python -m ddos predict --model models/rf.joblib --data data/synthetic_monitor.csv
"""
import argparse
import sys
from pathlib import Path

from . import detection, models, preprocessing, sample_data


def cmd_sample(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    train = out / "synthetic_FlowStatsfile.csv"
    monitor = out / "synthetic_monitor.csv"
    sample_data.training_sample(args.seed).to_csv(train, index=False)
    sample_data.timeline_sample(args.seed).to_csv(monitor, index=False)
    print(f"Wrote SYNTHETIC data: {train} and {monitor}")


def cmd_train(args):
    result = preprocessing.load_flows(args.data, missing=args.missing, require_label=True)
    for reason, count in result.dropped.items():
        print(f"Dropped {count} rows: {reason}")
    evaluation = models.train_and_evaluate(result.data, seed=args.seed)
    print(f"Split: {evaluation.split_method} "
          f"(train {evaluation.n_train}, test {evaluation.n_test})")
    if evaluation.split_warning:
        print("Warning:", evaluation.split_warning)
    print(evaluation.metrics.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    synthetic = "synthetic" in Path(args.data).name.lower()
    models.save_model(models.model_bundle(evaluation.primary, models.PRIMARY_MODEL,
                                          Path(args.data).name, synthetic), out)
    print(f"Saved {models.PRIMARY_MODEL} to {out}")


def cmd_predict(args):
    bundle = models.load_model(args.model)
    result = preprocessing.load_flows(args.data, missing=args.missing)
    scored = detection.score_flows(bundle["model"], result.data)
    summary = detection.summarize_windows(scored)
    print(f"Model: {bundle['name']} trained on {bundle['data_source']}")
    columns = ["window", "flows", "legit_pct", "attack", "victim_ip"]
    print(summary[columns].to_string(index=False, float_format=lambda v: f"{v:.0f}"))
    if args.out:
        scored.to_csv(args.out, index=False)
        print(f"Predictions written to {args.out}")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m ddos", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("sample", help="write the synthetic sample CSV files")
    p.add_argument("--out", default="data")
    p.add_argument("--seed", type=int, default=0)
    p.set_defaults(run=cmd_sample)

    p = sub.add_parser("train", help="train and evaluate all models, save the Random Forest")
    p.add_argument("--data", required=True)
    p.add_argument("--out", default="models/random_forest.joblib")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--missing", choices=["drop", "keep"], default="drop")
    p.set_defaults(run=cmd_train)

    p = sub.add_parser("predict", help="detect attacks in a CSV with a saved model")
    p.add_argument("--model", required=True)
    p.add_argument("--data", required=True)
    p.add_argument("--out")
    p.add_argument("--missing", choices=["drop", "keep"], default="keep")
    p.set_defaults(run=cmd_predict)

    args = parser.parse_args(argv)
    try:
        args.run(args)
    except (preprocessing.DatasetError, models.ModelError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
