import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_DIR = os.path.join(REPO_ROOT, "data")
FIG_DIR = os.path.join(DATA_DIR, "figures_v2")
os.makedirs(FIG_DIR, exist_ok=True)

POLICY_CSV = os.path.join(DATA_DIR, "policy_matrix.csv")
CURVES_CSV = os.path.join(DATA_DIR, "worm_infection_curves.csv")
WORM_SUMMARY_CSV = os.path.join(DATA_DIR, "worm_trials_summary.csv")
LAT_BASELINES_CSV = os.path.join(DATA_DIR, "latency_baselines.csv")
LOAD_CSV = os.path.join(DATA_DIR, "load_benchmark.csv")


def require(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing required file: {path}")


def save(fig, name: str):
    out = os.path.join(FIG_DIR, name)
    fig.tight_layout()
    fig.savefig(out, dpi=300)
    print(f"✅ Saved: {out}")


# -----------------------------
# Figure 1: Policy matrix
# -----------------------------
def fig_policy_matrix():
    require(POLICY_CSV)
    df = pd.read_csv(POLICY_CSV)

    # columns are: caller_identity, a,b,c,d
    callers = df["caller_identity"].tolist()
    targets = [c for c in df.columns if c != "caller_identity"]

    # Convert text -> numeric: ALLOW=1, DENY=0
    mat = []
    for _, row in df.iterrows():
        r = []
        for t in targets:
            v = str(row[t])
            r.append(1 if "ALLOW" in v else 0)
        mat.append(r)
    mat = np.array(mat)

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.imshow(mat, aspect="auto")

    ax.set_xticks(np.arange(len(targets)))
    ax.set_xticklabels(targets)
    ax.set_yticks(np.arange(len(callers)))
    ax.set_yticklabels(callers)

    # annotate cells
    for i in range(mat.shape[0]):
        for j in range(mat.shape[1]):
            ax.text(j, i, "ALLOW" if mat[i, j] == 1 else "DENY",
                    ha="center", va="center")

    ax.set_title("Policy Matrix (mTLS + Authorization): Valid Identity Still Restricted by Segment")
    ax.set_xlabel("Target Service")
    ax.set_ylabel("Caller Identity")

    save(fig, "fig1_policy_matrix.png")


# -----------------------------
# Figure 2: Infection curves
# -----------------------------
def fig_infection_curves():
    require(CURVES_CSV)
    require(WORM_SUMMARY_CSV)

    curves = pd.read_csv(CURVES_CSV)
    summary = pd.read_csv(WORM_SUMMARY_CSV)

    # We'll plot mean infected_pct over time for each (arch,strategy)
    fig, axes = plt.subplots(1, 2, figsize=(14, 4), sharey=True)

    strategies = ["hitlist", "pseudorandom_random"]
    for idx, strat in enumerate(strategies):
        ax = axes[idx]
        sub = curves[curves["strategy"] == strat]

        for arch in ["legacy", "zt"]:
            ss = sub[sub["arch"] == arch]
            # mean over trials at each t
            g = ss.groupby("t")["infected_pct"].mean().reset_index()
            ax.plot(g["t"], g["infected_pct"], label=arch)

        ax.set_title(f"Infection Curve ({strat})")
        ax.set_xlabel("Propagation round (t)")
        ax.grid(True, linestyle="--", linewidth=0.5)
        if idx == 0:
            ax.set_ylabel("Infected Nodes (%)")
        ax.set_ylim(0, 110)
        ax.legend(frameon=True)

    fig.suptitle("Worm Propagation: Legacy Reaches 100%; Zero Trust Policy Bounds Spread", y=1.05)
    save(fig, "fig2_infection_curves.png")

    # Bonus: bar chart of final infection %
    fig2, ax2 = plt.subplots(figsize=(8, 4))
    bar_rows = summary.groupby(["arch", "strategy"])["final_infected_pct"].mean().reset_index()
    x = np.arange(len(bar_rows))
    ax2.bar(x, bar_rows["final_infected_pct"].to_numpy())
    ax2.set_xticks(x)
    ax2.set_xticklabels([f"{r.arch}-{r.strategy}" for r in bar_rows.itertuples()], rotation=20, ha="right")
    ax2.set_ylabel("Final Infection (%)")
    ax2.set_title("Final Infection Rate (Mean across trials)")
    ax2.set_ylim(0, 110)
    ax2.grid(True, axis="y", linestyle="--", linewidth=0.5)

    save(fig2, "fig2b_final_infection_rate.png")


# -----------------------------
# Figure 3: Latency decomposition
# -----------------------------
def fig_latency_decomposition():
    require(LAT_BASELINES_CSV)
    df = pd.read_csv(LAT_BASELINES_CSV)

    # summarize mean & p99 by mode/baseline for status_code==200
    ok = df[df["status_code"] == 200].copy()

    def p99(x):
        return float(np.percentile(x.to_numpy(), 99)) if len(x) else np.nan

    agg = ok.groupby(["mode", "baseline"])["latency_ms"].agg(["mean", p99]).reset_index()
    agg = agg.rename(columns={"mean": "mean_ms", "p99": "p99_ms"})

    modes = ["cold", "warm"]
    baselines = ["http_proxy", "tls_only", "mtls_allowed"]

    fig, axes = plt.subplots(1, 2, figsize=(14, 4), sharey=True)
    for i, mode in enumerate(modes):
        ax = axes[i]
        sub = agg[agg["mode"] == mode]
        sub = sub.set_index("baseline").reindex(baselines).reset_index()

        x = np.arange(len(baselines))
        ax.bar(x, sub["mean_ms"].to_numpy())
        ax.scatter(x, sub["p99_ms"].to_numpy(), marker="o", label="p99")

        ax.set_xticks(x)
        ax.set_xticklabels(baselines, rotation=15, ha="right")
        ax.set_title(f"{mode.upper()} (mean bars, p99 dots)")
        ax.set_ylabel("Latency (ms)" if i == 0 else "")
        ax.grid(True, axis="y", linestyle="--", linewidth=0.5)

        for xi, v in enumerate(sub["mean_ms"].to_numpy()):
            ax.text(xi, v, f"{v:.2f}", ha="center", va="bottom")

        ax.legend(frameon=True)

    fig.suptitle("Latency Decomposition: Proxy vs TLS vs mTLS (Cold vs Warm)", y=1.05)
    save(fig, "fig3_latency_decomposition.png")


# -----------------------------
# Figure 4: Load benchmark
# -----------------------------
def fig_load_benchmark():
    require(LOAD_CSV)
    df = pd.read_csv(LOAD_CSV)

    # Throughput vs concurrency
    fig, ax = plt.subplots(figsize=(9, 4))
    for baseline in df["baseline"].unique():
        sub = df[df["baseline"] == baseline].sort_values("concurrency")
        ax.plot(sub["concurrency"], sub["throughput_rps"], marker="o", label=baseline)

    ax.set_title("Throughput vs Concurrency (OK 200 only)")
    ax.set_xlabel("Concurrency")
    ax.set_ylabel("Throughput (req/s)")
    ax.grid(True, linestyle="--", linewidth=0.5)
    ax.legend(frameon=True)
    save(fig, "fig4_throughput_vs_concurrency.png")

    # p99 latency vs concurrency
    fig2, ax2 = plt.subplots(figsize=(9, 4))
    for baseline in df["baseline"].unique():
        sub = df[df["baseline"] == baseline].sort_values("concurrency")
        ax2.plot(sub["concurrency"], sub["lat_p99_ms"], marker="o", label=baseline)

    ax2.set_title("Tail Latency (p99) vs Concurrency")
    ax2.set_xlabel("Concurrency")
    ax2.set_ylabel("p99 latency (ms)")
    ax2.grid(True, linestyle="--", linewidth=0.5)
    ax2.legend(frameon=True)
    save(fig2, "fig4b_p99_vs_concurrency.png")


def main():
    print("📊 Generating Revision-2 figures...")
    fig_policy_matrix()
    fig_infection_curves()
    fig_latency_decomposition()
    fig_load_benchmark()
    print(f"\n✅ All figures saved in: {FIG_DIR}")


if __name__ == "__main__":
    main()
