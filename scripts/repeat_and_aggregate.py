import os
import sys
import time
import shutil
import subprocess
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_DIR = os.path.join(REPO_ROOT, "data")
RUNS_DIR = os.path.join(DATA_DIR, "runs")
os.makedirs(RUNS_DIR, exist_ok=True)

LAT_SRC = os.path.join(DATA_DIR, "latency_baselines.csv")
LOAD_SRC = os.path.join(DATA_DIR, "load_benchmark.csv")

LAT_SCRIPT = os.path.join(REPO_ROOT, "scripts", "latency_baselines.py")
LOAD_SCRIPT = os.path.join(REPO_ROOT, "scripts", "load_benchmark.py")
SYSINFO_SCRIPT = os.path.join(REPO_ROOT, "scripts", "system_info.py")


def run_py(script_path: str) -> None:
    subprocess.run([sys.executable, script_path], check=True)


def bootstrap_ci(values: np.ndarray, iters: int = 2000, alpha: float = 0.05) -> Tuple[float, float]:
    """
    Nonparametric bootstrap CI over run-level summary values.
    With small run counts, this is more robust than pretending we have large-N independence.
    """
    values = values[~np.isnan(values)]
    n = len(values)
    if n < 2:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(12345)
    means = []
    for _ in range(iters):
        sample = rng.choice(values, size=n, replace=True)
        means.append(np.mean(sample))
    means = np.array(means)
    lo = np.percentile(means, 100 * (alpha / 2))
    hi = np.percentile(means, 100 * (1 - alpha / 2))
    return float(lo), float(hi)


def summarize_latency(df: pd.DataFrame) -> pd.DataFrame:
    ok = df[df["status_code"] == 200].copy()

    def p95(x): return float(np.percentile(x.to_numpy(), 95)) if len(x) else np.nan
    def p99(x): return float(np.percentile(x.to_numpy(), 99)) if len(x) else np.nan

    g = ok.groupby(["mode", "baseline"])["latency_ms"].agg(["mean", p95, p99]).reset_index()
    g = g.rename(columns={"mean": "mean_ms", "p95": "p95_ms", "p99": "p99_ms"})
    return g


def summarize_load(df: pd.DataFrame) -> pd.DataFrame:
    # Already aggregated per baseline/concurrency in your script; keep it as-is
    return df.copy()


def main():
    K = int(os.environ.get("RUNS", "5"))
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    batch_dir = os.path.join(RUNS_DIR, f"batch_{stamp}")
    os.makedirs(batch_dir, exist_ok=True)

    # Capture system info once per batch
    run_py(SYSINFO_SCRIPT)
    shutil.copy2(os.path.join(DATA_DIR, "system_info.json"), os.path.join(batch_dir, "system_info.json"))
    shutil.copy2(os.path.join(DATA_DIR, "system_info.md"), os.path.join(batch_dir, "system_info.md"))

    lat_runs = []
    load_runs = []

    manifest_rows = []

    for i in range(K):
        run_id = f"run_{i+1:02d}"
        run_dir = os.path.join(batch_dir, run_id)
        os.makedirs(run_dir, exist_ok=True)

        t0 = time.time()
        print(f"\n=== Running benchmark {i+1}/{K} ===")

        run_py(LAT_SCRIPT)
        if os.path.exists(LAT_SRC):
            shutil.copy2(LAT_SRC, os.path.join(run_dir, "latency_baselines.csv"))
            lat_df = pd.read_csv(os.path.join(run_dir, "latency_baselines.csv"))
            lat_runs.append(summarize_latency(lat_df).assign(run=run_id))

        run_py(LOAD_SCRIPT)
        if os.path.exists(LOAD_SRC):
            shutil.copy2(LOAD_SRC, os.path.join(run_dir, "load_benchmark.csv"))
            load_df = pd.read_csv(os.path.join(run_dir, "load_benchmark.csv"))
            load_runs.append(summarize_load(load_df).assign(run=run_id))

        t1 = time.time()
        manifest_rows.append({
            "run": run_id,
            "utc_start": datetime.utcfromtimestamp(t0).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "utc_end": datetime.utcfromtimestamp(t1).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "seconds": round(t1 - t0, 2),
        })

    pd.DataFrame(manifest_rows).to_csv(os.path.join(batch_dir, "manifest.csv"), index=False)
    print(f"\n✅ Saved run manifest: {os.path.join(batch_dir, 'manifest.csv')}")

    # --- Aggregate latency (CI across runs) ---
    if lat_runs:
        all_lat = pd.concat(lat_runs, ignore_index=True)
        out_rows = []
        for (mode, baseline), grp in all_lat.groupby(["mode", "baseline"]):
            for metric in ["mean_ms", "p95_ms", "p99_ms"]:
                vals = grp[metric].to_numpy(dtype=float)
                lo, hi = bootstrap_ci(vals)
                out_rows.append({
                    "mode": mode,
                    "baseline": baseline,
                    "metric": metric,
                    "runs": len(vals),
                    "value_mean": float(np.mean(vals)),
                    "value_std": float(np.std(vals, ddof=1)) if len(vals) > 1 else 0.0,
                    "ci95_low": lo,
                    "ci95_high": hi,
                })
        out_lat = pd.DataFrame(out_rows)
        out_lat_path = os.path.join(DATA_DIR, "aggregate_latency_baselines_ci.csv")
        out_lat.to_csv(out_lat_path, index=False)
        print(f"✅ Saved: {out_lat_path}")

    # --- Aggregate load (CI across runs) ---
    if load_runs:
        all_load = pd.concat(load_runs, ignore_index=True)
        out_rows = []
        for (baseline, concurrency), grp in all_load.groupby(["baseline", "concurrency"]):
            for metric in ["throughput_rps", "lat_mean_ms", "lat_p95_ms", "lat_p99_ms"]:
                vals = grp[metric].to_numpy(dtype=float)
                lo, hi = bootstrap_ci(vals)
                out_rows.append({
                    "baseline": baseline,
                    "concurrency": int(concurrency),
                    "metric": metric,
                    "runs": len(vals),
                    "value_mean": float(np.mean(vals)),
                    "value_std": float(np.std(vals, ddof=1)) if len(vals) > 1 else 0.0,
                    "ci95_low": lo,
                    "ci95_high": hi,
                })
        out_load = pd.DataFrame(out_rows)
        out_load_path = os.path.join(DATA_DIR, "aggregate_load_benchmark_ci.csv")
        out_load.to_csv(out_load_path, index=False)
        print(f"✅ Saved: {out_load_path}")

    print(f"\n✅ Batch archived at: {batch_dir}")
    print("Tip: set RUNS=7 for tighter CIs.")


if __name__ == "__main__":
    main()
