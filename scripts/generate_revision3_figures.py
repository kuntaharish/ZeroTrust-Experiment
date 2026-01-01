import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_DIR = os.path.join(REPO_ROOT, "data")
FIG_DIR = os.path.join(DATA_DIR, "figures_v3_ci")
os.makedirs(FIG_DIR, exist_ok=True)

POLICY_CSV = os.path.join(DATA_DIR, "policy_matrix.csv")
CURVES_CSV = os.path.join(DATA_DIR, "worm_infection_curves.csv")
LAT_CI = os.path.join(DATA_DIR, "aggregate_latency_baselines_ci.csv")
LOAD_CI = os.path.join(DATA_DIR, "aggregate_load_benchmark_ci.csv")


def require(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing required file: {path}")


def save(fig, name: str):
    out = os.path.join(FIG_DIR, name)
    fig.tight_layout()
    fig.savefig(out, dpi=300)
    print(f"✅ Saved: {out}")


def fig_policy_matrix():
    require(POLICY_CSV)
    df = pd.read_csv(POLICY_CSV)
    callers = df["caller_identity"].tolist()
    targets = [c for c in df.columns if c != "caller_identity"]

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

    for i in range(mat.shape[0]):
        for j in range(mat.shape[1]):
            ax.text(j, i, "ALLOW" if mat[i, j] == 1 else "DENY", ha="center", va="center")

    ax.set_title("Authorization Policy Matrix (Valid Identities Restricted by Segment)")
    ax.set_xlabel("Target Service")
    ax.set_ylabel("Caller Identity")
    save(fig, "fig1_policy_matrix.png")


def fig_infection_curves():
    require(CURVES_CSV)
    curves = pd.read_csv(CURVES_CSV)

    fig, axes = plt.subplots(1, 2, figsize=(14, 4), sharey=True)
    strategies = ["hitlist", "pseudorandom_random"]

    for idx, strat in enumerate(strategies):
        ax = axes[idx]
        sub = curves[curves["strategy"] == strat]
        for arch in ["legacy", "zt"]:
            ss = sub[sub["arch"] == arch]
            g = ss.groupby("t")["infected_pct"].mean().reset_index()
            ax.plot(g["t"], g["infected_pct"], label=arch)

        ax.set_title(f"Infection Curve ({strat})")
        ax.set_xlabel("Propagation round (t)")
        ax.grid(True, linestyle="--", linewidth=0.5)
        if idx == 0:
            ax.set_ylabel("Infected Nodes (%)")
        ax.set_ylim(0, 110)
        ax.legend(frameon=True)

    fig.suptitle("Propagation Results: Legacy Reaches 100%; ZT Authorization Bounds Spread", y=1.05)
    save(fig, "fig2_infection_curves.png")


def fig_latency_ci():
    require(LAT_CI)
    df = pd.read_csv(LAT_CI)

    # Plot warm mean with CI for the three baselines
    baselines = ["http_proxy", "tls_only", "mtls_allowed"]
    mode = "warm"
    metric = "mean_ms"

    sub = df[(df["mode"] == mode) & (df["metric"] == metric)].set_index("baseline").reindex(baselines).reset_index()

    means = sub["value_mean"].to_numpy()
    yerr = np.vstack([means - sub["ci95_low"].to_numpy(), sub["ci95_high"].to_numpy() - means])

    fig, ax = plt.subplots(figsize=(9, 4))
    x = np.arange(len(baselines))
    ax.bar(x, means, yerr=yerr, capsize=5)
    ax.set_xticks(x)
    ax.set_xticklabels(baselines, rotation=15, ha="right")
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Warm Steady-State Latency (Mean ± 95% CI across runs)")
    ax.grid(True, axis="y", linestyle="--", linewidth=0.5)

    save(fig, "fig3_warm_latency_ci.png")


def fig_load_ci():
    require(LOAD_CI)
    df = pd.read_csv(LOAD_CI)

    # Throughput vs concurrency with CI
    fig, ax = plt.subplots(figsize=(9, 4))
    for baseline in sorted(df["baseline"].unique()):
        sub = df[(df["baseline"] == baseline) & (df["metric"] == "throughput_rps")].sort_values("concurrency")
        x = sub["concurrency"].to_numpy()
        y = sub["value_mean"].to_numpy()
        yerr = np.vstack([y - sub["ci95_low"].to_numpy(), sub["ci95_high"].to_numpy() - y])
        ax.errorbar(x, y, yerr=yerr, marker="o", capsize=4, label=baseline)

    ax.set_title("Throughput vs Concurrency (Mean ± 95% CI across runs)")
    ax.set_xlabel("Concurrency")
    ax.set_ylabel("Throughput (req/s)")
    ax.grid(True, linestyle="--", linewidth=0.5)
    ax.legend(frameon=True)
    save(fig, "fig4_throughput_ci.png")

    # p99 vs concurrency with CI
    fig2, ax2 = plt.subplots(figsize=(9, 4))
    for baseline in sorted(df["baseline"].unique()):
        sub = df[(df["baseline"] == baseline) & (df["metric"] == "lat_p99_ms")].sort_values("concurrency")
        x = sub["concurrency"].to_numpy()
        y = sub["value_mean"].to_numpy()
        yerr = np.vstack([y - sub["ci95_low"].to_numpy(), sub["ci95_high"].to_numpy() - y])
        ax2.errorbar(x, y, yerr=yerr, marker="o", capsize=4, label=baseline)

    ax2.set_title("Tail Latency (p99) vs Concurrency (Mean ± 95% CI across runs)")
    ax2.set_xlabel("Concurrency")
    ax2.set_ylabel("p99 latency (ms)")
    ax2.grid(True, linestyle="--", linewidth=0.5)
    ax2.legend(frameon=True)
    save(fig2, "fig4b_p99_ci.png")


def main():
    print("📊 Generating CI-aware Revision-3 figures...")
    fig_policy_matrix()
    fig_infection_curves()
    fig_latency_ci()
    fig_load_ci()
    print(f"\n✅ Figures saved in: {FIG_DIR}")


if __name__ == "__main__":
    main()
