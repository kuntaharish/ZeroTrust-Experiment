# scripts/generate_revision2_figures.py
#
# Revision-2 figure generator (robust across schema changes)
#
# Produces:
#   fig1_policy_matrix.png
#   fig2_infection_curves.png
#   fig2b_final_infection_rate.png
#   fig3_latency_decomposition.png
#   fig4_throughput_vs_concurrency.png
#   fig4b_p99_vs_concurrency.png
#
# Robustness features:
# - Chooses the newest of CSV vs CSV.GZ (avoids stale files being loaded).
# - latency_baselines supports BOTH schemas:
#     New:  mode, phase, ok, latency_ms, ...
#     Old:  mode, baseline, status_code, latency_ms, ...
#   It will normalize to: mode, phase(COLD/WARM), ok(bool), latency_ms(float)
# - load_benchmark supports BOTH schemas:
#     Newer: baseline, concurrency, throughput_rps, lat_p99_ms, ...
#     Older: mode, concurrency, rps, p99_ms, ...
#
# Python 3.9+

from pathlib import Path
from typing import Optional, List

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DATA_DIR = REPO_ROOT / "data"
FIG_DIR = DATA_DIR / "figures_v2"
FIG_DIR.mkdir(parents=True, exist_ok=True)


def newest_of(paths: List[Path]) -> Optional[Path]:
    existing = [p for p in paths if p.exists()]
    if not existing:
        return None
    return max(existing, key=lambda p: p.stat().st_mtime)


def read_csv_prefer_newest(stem_path: Path) -> pd.DataFrame:
    """
    Tries to read the newest among:
      <stem>.csv
      <stem>.csv.gz
    """
    csv_path = stem_path.with_suffix(".csv")
    gz_path = stem_path.with_suffix(".csv.gz")

    chosen = newest_of([csv_path, gz_path])
    if chosen is None:
        raise FileNotFoundError(f"Could not find {csv_path} or {gz_path}")

    if chosen.suffix == ".gz":
        return pd.read_csv(chosen, compression="gzip")
    return pd.read_csv(chosen)


def pick_col(df: pd.DataFrame, candidates: List[str]) -> Optional[str]:
    for c in candidates:
        if c in df.columns:
            return c
    return None


def save_fig(path: Path) -> None:
    plt.tight_layout()
    plt.savefig(path, dpi=300)
    print(f"✅ Saved: {path}")


def fig_policy_matrix() -> None:
    pm_path = DATA_DIR / "policy_matrix.csv"
    if not pm_path.exists():
        print("⚠️  policy_matrix.csv not found; skipping fig1_policy_matrix.png")
        return

    df = pd.read_csv(pm_path)
    if "caller_identity" in df.columns:
        df = df.set_index("caller_identity")

    def cell_to_score(v: str) -> int:
        v = str(v)
        if v.startswith("ALLOW"):
            return 1
        if v.startswith("DENY"):
            return 0
        if v.startswith("DOWN"):
            return -1
        return 0

    score = df.apply(lambda col: col.map(cell_to_score)).astype(int)

    plt.figure(figsize=(14, 7))
    ax = plt.gca()
    im = ax.imshow(score.values, aspect="auto")

    ax.set_xticks(np.arange(score.shape[1]))
    ax.set_yticks(np.arange(score.shape[0]))
    ax.set_xticklabels(score.columns.tolist(), rotation=0)
    ax.set_yticklabels(score.index.tolist())

    ax.set_title("Policy Matrix (mTLS + Micro-Segmentation Allowlist)")
    ax.set_xlabel("Target Service")
    ax.set_ylabel("Caller Identity (from mTLS certificate CN)")

    for i in range(df.shape[0]):
        for j in range(df.shape[1]):
            txt = str(df.iloc[i, j])
            ax.text(j, i, txt, ha="center", va="center", fontsize=6)

    cbar = plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_ticks([-1, 0, 1])
    cbar.set_ticklabels(["DOWN", "DENY", "ALLOW"])

    save_fig(FIG_DIR / "fig1_policy_matrix.png")
    plt.close()


def fig_infection_curves() -> None:
    curves_path = DATA_DIR / "worm_infection_curves.csv"
    if not curves_path.exists():
        print("⚠️  worm_infection_curves.csv not found; skipping fig2_infection_curves.png")
        return

    df = pd.read_csv(curves_path)

    step_col = pick_col(df, ["step", "round", "hop", "t", "time"])
    pct_col = pick_col(df, ["infected_pct", "infected_percent", "infected_percentage"])
    arch_col = pick_col(df, ["arch", "architecture"])
    strat_col = pick_col(df, ["strategy"])

    missing = [("step", step_col), ("pct", pct_col), ("arch", arch_col), ("strategy", strat_col)]
    missing = [name for name, col in missing if col is None]
    if missing:
        raise KeyError(f"worm_infection_curves.csv missing required columns: {missing}. "
                       f"Found columns: {list(df.columns)}")

    agg = df.groupby([arch_col, strat_col, step_col])[pct_col].mean().reset_index()

    plt.figure(figsize=(11, 6))
    ax = plt.gca()

    combos = agg[[arch_col, strat_col]].drop_duplicates().values.tolist()
    combos = sorted(combos, key=lambda x: (str(x[0]), str(x[1])))

    for arch, strat in combos:
        sub = agg[(agg[arch_col] == arch) & (agg[strat_col] == strat)].sort_values(step_col)
        label = f"{str(arch).upper()} • {strat}"
        ax.plot(sub[step_col].values, sub[pct_col].values, linewidth=2, label=label)

    ax.set_title("Worm Propagation Over Time: Legacy vs Zero-Trust")
    ax.set_xlabel("Propagation Step")
    ax.set_ylabel("Infected Services (%)")
    ax.set_ylim(0, 105)
    ax.grid(True, alpha=0.3)
    ax.legend(loc="lower right", fontsize=8)

    save_fig(FIG_DIR / "fig2_infection_curves.png")
    plt.close()


def fig_final_infection_rate() -> None:
    summary_path = DATA_DIR / "worm_trials_summary.csv"
    if not summary_path.exists():
        print("⚠️  worm_trials_summary.csv not found; skipping fig2b_final_infection_rate.png")
        return

    df = pd.read_csv(summary_path)

    arch_col = pick_col(df, ["arch", "architecture"])
    strat_col = pick_col(df, ["strategy"])
    if arch_col is None or strat_col is None:
        raise KeyError(f"worm_trials_summary.csv must have arch/strategy. Found: {list(df.columns)}")

    per_trial = pick_col(df, ["final_infected_pct", "final_infection_pct"])
    mean_col = pick_col(df, ["mean_final_infection_pct", "mean_final_infected_pct"])
    min_col = pick_col(df, ["min_final_infection_pct", "min_final_infected_pct"])
    max_col = pick_col(df, ["max_final_infection_pct", "max_final_infected_pct"])

    plt.figure(figsize=(11, 6))
    ax = plt.gca()

    if per_trial is not None:
        df["group"] = df[arch_col].astype(str) + " • " + df[strat_col].astype(str)
        groups = sorted(df["group"].unique().tolist())
        data = [df[df["group"] == g][per_trial].values for g in groups]
        ax.boxplot(data, labels=groups, showmeans=True)
        ax.set_title("Final Infection Rate Distribution (per-trial)")
        ax.set_ylabel("Final Infected Services (%)")
        ax.set_ylim(0, 105)
        ax.grid(True, axis="y", alpha=0.3)

    elif mean_col is not None and min_col is not None and max_col is not None:
        df = df.copy()
        df["group"] = df[arch_col].astype(str) + " • " + df[strat_col].astype(str)
        if set(["arch", "strategy"]).issubset(df.columns):
            df = df.sort_values(["arch", "strategy"])
        else:
            df = df.sort_values("group")

        x = np.arange(len(df))
        means = df[mean_col].astype(float).values
        mins = df[min_col].astype(float).values
        maxs = df[max_col].astype(float).values
        yerr = np.vstack([means - mins, maxs - means])

        ax.bar(x, means, yerr=yerr, capsize=6)
        ax.set_xticks(x)
        ax.set_xticklabels(df["group"].tolist(), rotation=20, ha="right")
        ax.set_title("Final Infection Rate (mean with min/max across trials)")
        ax.set_ylabel("Final Infected Services (%)")
        ax.set_ylim(0, 105)
        ax.grid(True, axis="y", alpha=0.3)

        for i, m in enumerate(means):
            ax.text(i, m + 2, f"{m:.1f}%", ha="center", va="bottom", fontsize=9)

    else:
        raise KeyError(
            "worm_trials_summary.csv schema not recognized. "
            "Expected final_infected_pct OR mean/min/max_final_infection_pct columns. "
            f"Found: {list(df.columns)}"
        )

    save_fig(FIG_DIR / "fig2b_final_infection_rate.png")
    plt.close()


def _normalize_latency_baselines(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize latency_baselines to required columns:
      - mode
      - phase (COLD/WARM)
      - ok (bool)
      - latency_ms
    Accepts older schemas too.
    """
    df = df.copy()

    # mode
    if "mode" not in df.columns:
        alt = pick_col(df, ["name", "gateway", "baseline_name"])
        if alt is None:
            raise KeyError(f"latency_baselines missing 'mode'. Found: {list(df.columns)}")
        df["mode"] = df[alt].astype(str)

    # latency_ms
    if "latency_ms" not in df.columns:
        alt = pick_col(df, ["Latency_ms", "latency", "ms"])
        if alt is None:
            raise KeyError(f"latency_baselines missing 'latency_ms'. Found: {list(df.columns)}")
        df["latency_ms"] = pd.to_numeric(df[alt], errors="coerce")

    # phase
    if "phase" not in df.columns:
        if "baseline" in df.columns:
            df["phase"] = df["baseline"].astype(str)
        else:
            df["phase"] = "WARM"

    def norm_phase(v: str) -> str:
        u = str(v).upper()
        if "WARM" in u:
            return "WARM"
        if "COLD" in u:
            return "COLD"
        return str(v)

    df["phase"] = df["phase"].map(norm_phase)

    # ok
    if "ok" not in df.columns:
        if "status_code" in df.columns:
            df["ok"] = (pd.to_numeric(df["status_code"], errors="coerce") == 200)
        else:
            df["ok"] = True
    else:
        df["ok"] = df["ok"].astype(bool)

    return df


def fig_latency_decomposition() -> None:
    try:
        raw = read_csv_prefer_newest(DATA_DIR / "latency_baselines")
    except FileNotFoundError:
        print("⚠️  latency_baselines.csv(.gz) not found; skipping fig3_latency_decomposition.png")
        return

    df = _normalize_latency_baselines(raw)

    warm = df[(df["phase"] == "WARM") & (df["ok"] == True)].copy()
    modes = ["http_proxy", "tls_only", "mtls_allowed"]
    warm = warm[warm["mode"].isin(modes)]

    if warm.empty:
        raise RuntimeError(
            "No warm success rows found in latency_baselines after normalization. "
            "Check your gateways are up and returning 200s."
        )

    stats = warm.groupby("mode")["latency_ms"].agg(["mean"]).reset_index()
    p99 = warm.groupby("mode")["latency_ms"].quantile(0.99).reset_index(name="p99")
    stats = stats.merge(p99, on="mode")

    order = {m: i for i, m in enumerate(modes)}
    stats["order"] = stats["mode"].map(order)
    stats = stats.sort_values("order")

    plt.figure(figsize=(9, 6))
    ax = plt.gca()

    x = np.arange(len(stats))
    ax.bar(x, stats["mean"].values)
    ax.set_xticks(x)
    ax.set_xticklabels(stats["mode"].tolist())

    ax.set_title("Latency Decomposition (Warm, Success Only)")
    ax.set_ylabel("Mean Latency (ms)")
    ax.grid(True, axis="y", alpha=0.3)

    for _, row in stats.iterrows():
        i = order[row["mode"]]
        ax.text(
            i,
            row["mean"] + 0.05,
            f"mean={row['mean']:.3f}\np99={row['p99']:.3f}",
            ha="center",
            va="bottom",
            fontsize=9
        )

    save_fig(FIG_DIR / "fig3_latency_decomposition.png")
    plt.close()


def _normalize_load_benchmark(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize load_benchmark to:
      - mode
      - concurrency
      - rps
      - p99_ms
      - (optional) p95_ms
    Works with both schemas:
      Newer: baseline, concurrency, throughput_rps, lat_p95_ms, lat_p99_ms
      Older: mode, concurrency, rps, p99_ms
    """
    df = df.copy()

    # mode
    if "mode" not in df.columns:
        if "baseline" in df.columns:
            df["mode"] = df["baseline"].astype(str)
        else:
            alt = pick_col(df, ["name", "gateway"])
            if alt is None:
                raise KeyError(f"load_benchmark missing mode/baseline. Found: {list(df.columns)}")
            df["mode"] = df[alt].astype(str)

    # concurrency
    if "concurrency" not in df.columns:
        alt = pick_col(df, ["c"])
        if alt is None:
            raise KeyError(f"load_benchmark missing concurrency. Found: {list(df.columns)}")
        df["concurrency"] = pd.to_numeric(df[alt], errors="coerce")

    # rps
    if "rps" not in df.columns:
        if "throughput_rps" in df.columns:
            df["rps"] = pd.to_numeric(df["throughput_rps"], errors="coerce")
        else:
            alt = pick_col(df, ["requests_per_second"])
            if alt is None:
                raise KeyError(f"load_benchmark missing rps/throughput_rps. Found: {list(df.columns)}")
            df["rps"] = pd.to_numeric(df[alt], errors="coerce")

    # p99
    if "p99_ms" not in df.columns:
        if "lat_p99_ms" in df.columns:
            df["p99_ms"] = pd.to_numeric(df["lat_p99_ms"], errors="coerce")
        else:
            alt = pick_col(df, ["p99", "p99_latency_ms"])
            if alt is None:
                raise KeyError(f"load_benchmark missing p99_ms/lat_p99_ms. Found: {list(df.columns)}")
            df["p99_ms"] = pd.to_numeric(df[alt], errors="coerce")

    # p95 optional
    if "p95_ms" not in df.columns:
        if "lat_p95_ms" in df.columns:
            df["p95_ms"] = pd.to_numeric(df["lat_p95_ms"], errors="coerce")

    df["concurrency"] = df["concurrency"].astype(int)
    return df


def fig_throughput_and_p99() -> None:
    lb_path = DATA_DIR / "load_benchmark.csv"
    if not lb_path.exists():
        print("⚠️  load_benchmark.csv not found; skipping fig4/fig4b")
        return

    raw = pd.read_csv(lb_path)
    df = _normalize_load_benchmark(raw)

    plt.figure(figsize=(10, 6))
    ax = plt.gca()
    for mode in sorted(df["mode"].unique().tolist()):
        sub = df[df["mode"] == mode].sort_values("concurrency")
        ax.plot(sub["concurrency"], sub["rps"], marker="o", linewidth=2, label=mode)
    ax.set_title("Throughput vs Concurrency (RPS)")
    ax.set_xlabel("Concurrency")
    ax.set_ylabel("Requests / Second (RPS)")
    ax.grid(True, alpha=0.3)
    ax.legend()
    save_fig(FIG_DIR / "fig4_throughput_vs_concurrency.png")
    plt.close()

    plt.figure(figsize=(10, 6))
    ax = plt.gca()
    for mode in sorted(df["mode"].unique().tolist()):
        sub = df[df["mode"] == mode].sort_values("concurrency")
        ax.plot(sub["concurrency"], sub["p99_ms"], marker="o", linewidth=2, label=mode)
    ax.set_title("Tail Latency vs Concurrency (p99)")
    ax.set_xlabel("Concurrency")
    ax.set_ylabel("p99 Latency (ms)")
    ax.grid(True, alpha=0.3)
    ax.legend()
    save_fig(FIG_DIR / "fig4b_p99_vs_concurrency.png")
    plt.close()


def main() -> None:
    print("📊 Generating Revision-2 figures...")

    fig_policy_matrix()
    fig_infection_curves()
    fig_final_infection_rate()
    fig_latency_decomposition()
    fig_throughput_and_p99()

    print(f"\n✅ All figures saved in: {FIG_DIR}")


if __name__ == "__main__":
    main()
