import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# -----------------------------
# Paths (repo-safe)
# -----------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_DIR = os.path.join(REPO_ROOT, "data")
FIG_DIR = os.path.join(DATA_DIR, "figures")
os.makedirs(FIG_DIR, exist_ok=True)

ADVERSARY_CSV = os.path.join(DATA_DIR, "advanced_adversary_results_real_mtls.csv")
KEEPALIVE_CSV = os.path.join(DATA_DIR, "zt_keepalive_benchmark.csv")

# -----------------------------
# Helpers
# -----------------------------
def _require_file(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing required input file: {path}")

def _save(fig, filename: str):
    out = os.path.join(FIG_DIR, filename)
    fig.tight_layout()
    fig.savefig(out, dpi=300)
    print(f"✅ Saved: {out}")

def _percent(x: float) -> float:
    return float(np.round(100.0 * x, 1))

def stats(series: pd.Series) -> dict:
    arr = series.dropna().to_numpy()
    if len(arr) == 0:
        return {"n": 0, "mean": np.nan, "p95": np.nan, "p99": np.nan}
    return {
        "n": int(len(arr)),
        "mean": float(np.mean(arr)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
    }

# -----------------------------
# Figure 1: Outcome correctness (block vs success rates)
# -----------------------------
def fig_outcomes_stacked(df: pd.DataFrame):
    """
    Reviewer question: "Does ZT actually block unauthorized propagation while allowing authorized?"
    Output: stacked bar per (Mode, Attack_Type) showing result percentages.
    """
    # Ensure consistent order
    result_order = ["SUCCESS", "BLOCKED_TLS", "BLOCKED_APP", "ERROR"]
    mode_order = ["COLD_CONNECTIONS", "WARM_CONNECTIONS"]
    attack_order = ["LEGACY_CLEAR", "ZT_GOOD_MTLS", "ZT_NO_CERT", "ZT_ROGUE_CERT"]

    # Build percentage table
    counts = df.groupby(["Mode", "Attack_Type", "Result"]).size().reset_index(name="Count")
    totals = df.groupby(["Mode", "Attack_Type"]).size().reset_index(name="Total")
    merged = counts.merge(totals, on=["Mode", "Attack_Type"], how="left")
    merged["Pct"] = merged["Count"] / merged["Total"] * 100.0

    # Create a complete grid so missing categories show as 0
    rows = []
    for m in mode_order:
        for a in attack_order:
            for r in result_order:
                sub = merged[(merged["Mode"] == m) & (merged["Attack_Type"] == a) & (merged["Result"] == r)]
                pct = float(sub["Pct"].iloc[0]) if not sub.empty else 0.0
                rows.append({"Mode": m, "Attack_Type": a, "Result": r, "Pct": pct})
    plot_df = pd.DataFrame(rows)

    # Plot: two panels (cold vs warm) for readability
    fig, axes = plt.subplots(1, 2, figsize=(14, 5), sharey=True)
    for idx, mode in enumerate(mode_order):
        ax = axes[idx]
        sub = plot_df[plot_df["Mode"] == mode]

        x = np.arange(len(attack_order))
        bottom = np.zeros(len(attack_order))

        for r in result_order:
            y = np.array([sub[(sub["Attack_Type"] == a) & (sub["Result"] == r)]["Pct"].iloc[0] for a in attack_order])
            ax.bar(x, y, bottom=bottom, label=r)
            bottom += y

        ax.set_title(mode.replace("_", " ").title())
        ax.set_xticks(x)
        ax.set_xticklabels(attack_order, rotation=20, ha="right")
        ax.set_ylim(0, 100)
        ax.set_ylabel("Outcome Rate (%)" if idx == 0 else "")
        ax.grid(True, axis="y", linestyle="--", linewidth=0.5)

    axes[1].legend(loc="upper right", frameon=True)
    fig.suptitle("Outcome Correctness: Legacy Allows; Zero Trust Blocks Unauthorized at TLS Layer", y=1.05)
    _save(fig, "fig1_outcome_correctness.png")

# -----------------------------
# Figure 2: Security tax summary (means + p99)
# -----------------------------
def fig_security_tax_bar(df: pd.DataFrame):
    """
    Reviewer question: "What is the performance cost, and do you report tail latency?"
    Output: mean + p99 bars for Legacy vs ZT Good, cold vs warm (SUCCESS only).
    """
    rows = []
    for mode in ["COLD_CONNECTIONS", "WARM_CONNECTIONS"]:
        # Legacy success
        legacy = df[(df["Mode"] == mode) & (df["Attack_Type"] == "LEGACY_CLEAR") & (df["Result"] == "SUCCESS")]["Latency_ms"]
        zt_good = df[(df["Mode"] == mode) & (df["Attack_Type"] == "ZT_GOOD_MTLS") & (df["Result"] == "SUCCESS")]["Latency_ms"]
        rows.append({"Mode": mode, "Path": "Legacy", **stats(legacy)})
        rows.append({"Mode": mode, "Path": "ZeroTrust_mTLS", **stats(zt_good)})

    s = pd.DataFrame(rows)

    # Plot 2x2 grouped bars: mean and p99
    fig, ax = plt.subplots(figsize=(10, 5))
    xlabels = ["Cold", "Warm"]
    x = np.arange(len(xlabels))
    width = 0.32

    # Mean bars
    legacy_mean = [s[(s["Mode"] == "COLD_CONNECTIONS") & (s["Path"] == "Legacy")]["mean"].iloc[0],
                   s[(s["Mode"] == "WARM_CONNECTIONS") & (s["Path"] == "Legacy")]["mean"].iloc[0]]
    zt_mean = [s[(s["Mode"] == "COLD_CONNECTIONS") & (s["Path"] == "ZeroTrust_mTLS")]["mean"].iloc[0],
               s[(s["Mode"] == "WARM_CONNECTIONS") & (s["Path"] == "ZeroTrust_mTLS")]["mean"].iloc[0]]

    legacy_p99 = [s[(s["Mode"] == "COLD_CONNECTIONS") & (s["Path"] == "Legacy")]["p99"].iloc[0],
                  s[(s["Mode"] == "WARM_CONNECTIONS") & (s["Path"] == "Legacy")]["p99"].iloc[0]]
    zt_p99 = [s[(s["Mode"] == "COLD_CONNECTIONS") & (s["Path"] == "ZeroTrust_mTLS")]["p99"].iloc[0],
              s[(s["Mode"] == "WARM_CONNECTIONS") & (s["Path"] == "ZeroTrust_mTLS")]["p99"].iloc[0]]

    ax.bar(x - width/2, legacy_mean, width, label="Legacy mean")
    ax.bar(x + width/2, zt_mean, width, label="mTLS mean")

    # Overlay p99 markers (dots)
    ax.scatter(x - width/2, legacy_p99, marker="o", label="Legacy p99")
    ax.scatter(x + width/2, zt_p99, marker="o", label="mTLS p99")

    ax.set_xticks(x)
    ax.set_xticklabels(xlabels)
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Security Tax Summary (SUCCESS only): Mean + p99 Tail Latency")
    ax.grid(True, axis="y", linestyle="--", linewidth=0.5)
    ax.legend(frameon=True)

    _save(fig, "fig2_security_tax_mean_p99.png")

# -----------------------------
# Figure 3: Latency distributions (boxplot) for SUCCESS only
# -----------------------------
def fig_latency_boxplot(df: pd.DataFrame):
    """
    Reviewer question: "Do distributions look sane? Any weird bimodality?"
    Output: boxplots of SUCCESS latencies for Legacy vs ZT Good in cold/warm.
    """
    plot_rows = []
    for mode in ["COLD_CONNECTIONS", "WARM_CONNECTIONS"]:
        for path, attack in [("Legacy", "LEGACY_CLEAR"), ("ZeroTrust_mTLS", "ZT_GOOD_MTLS")]:
            s = df[(df["Mode"] == mode) & (df["Attack_Type"] == attack) & (df["Result"] == "SUCCESS")]["Latency_ms"].dropna()
            for v in s.to_list():
                plot_rows.append({"Mode": mode, "Path": path, "Latency_ms": v})

    p = pd.DataFrame(plot_rows)
    if p.empty:
        print("⚠️ No SUCCESS latencies found for boxplot.")
        return

    # Build lists in fixed order for consistent plots
    labels = []
    data = []
    for mode in ["COLD_CONNECTIONS", "WARM_CONNECTIONS"]:
        for path in ["Legacy", "ZeroTrust_mTLS"]:
            labels.append(f"{mode.split('_')[0].title()}-{path}")
            data.append(p[(p["Mode"] == mode) & (p["Path"] == path)]["Latency_ms"].to_numpy())

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.boxplot(data, labels=labels, showfliers=False)
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Latency Distributions (SUCCESS only) — Boxplot (no outliers shown)")
    ax.grid(True, axis="y", linestyle="--", linewidth=0.5)

    _save(fig, "fig3_latency_distribution_boxplot.png")

# -----------------------------
# Figure 4: Keep-alive handshake amortization (line + bar)
# -----------------------------
def fig_keepalive_amortization():
    """
    Reviewer question: "Is your warm-mode claim real? Do you prove keep-alive reuse?"
    Output:
      - line plot of first ~60 requests latencies
      - bar showing first-3 mean vs steady-state mean/p99
    """
    _require_file(KEEPALIVE_CSV)
    df = pd.read_csv(KEEPALIVE_CSV)
    lat = df["latency_ms"].to_numpy()

    if len(lat) < 10:
        print("⚠️ Not enough samples in keepalive benchmark.")
        return

    first3 = lat[:3]
    rest = lat[3:]

    # 4A: line plot (first 60)
    n_line = min(60, len(lat))
    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot(np.arange(n_line), lat[:n_line])
    ax.set_title("mTLS Keep-Alive: Handshake Cost Amortizes After First Requests")
    ax.set_xlabel("Request index")
    ax.set_ylabel("Latency (ms)")
    ax.grid(True, linestyle="--", linewidth=0.5)
    _save(fig, "fig4a_keepalive_latency_trace.png")

    # 4B: bar chart comparing first-3 vs steady-state
    first_mean = float(np.mean(first3))
    rest_mean = float(np.mean(rest))
    rest_p99 = float(np.percentile(rest, 99))

    fig2, ax2 = plt.subplots(figsize=(8, 4))
    ax2.bar(["Handshake-heavy (first 3)", "Steady-state (after 3)"], [first_mean, rest_mean])
    ax2.scatter([1], [rest_p99], marker="o", label="Steady-state p99")
    ax2.set_ylabel("Latency (ms)")
    ax2.set_title("Cold vs Warm Overhead (Keep-Alive)")
    ax2.grid(True, axis="y", linestyle="--", linewidth=0.5)
    ax2.legend(frameon=True)

    _save(fig2, "fig4b_keepalive_cold_vs_warm.png")

# -----------------------------
# Export a reviewer-friendly summary table
# -----------------------------
def export_reviewer_tables(df: pd.DataFrame):
    """
    Produces a small CSV with the exact headline metrics reviewers care about:
    - block rates for no-cert and rogue-cert
    - success rate for good mTLS
    - security tax mean and p99 for cold and warm (SUCCESS only)
    """
    rows = []

    for mode in ["COLD_CONNECTIONS", "WARM_CONNECTIONS"]:
        # Rates
        def rate(attack, result):
            sub = df[(df["Mode"] == mode) & (df["Attack_Type"] == attack)]
            if sub.empty:
                return np.nan
            return _percent((sub["Result"] == result).mean())

        rows.append({
            "Mode": mode,
            "Legacy_SUCCESS_%": rate("LEGACY_CLEAR", "SUCCESS"),
            "ZT_Good_mTLS_SUCCESS_%": rate("ZT_GOOD_MTLS", "SUCCESS"),
            "ZT_NoCert_BLOCKED_TLS_%": rate("ZT_NO_CERT", "BLOCKED_TLS"),
            "ZT_RogueCert_BLOCKED_TLS_%": rate("ZT_ROGUE_CERT", "BLOCKED_TLS"),
        })

        # Latency stats (SUCCESS only)
        legacy_ok = df[(df["Mode"] == mode) & (df["Attack_Type"] == "LEGACY_CLEAR") & (df["Result"] == "SUCCESS")]["Latency_ms"]
        zt_ok = df[(df["Mode"] == mode) & (df["Attack_Type"] == "ZT_GOOD_MTLS") & (df["Result"] == "SUCCESS")]["Latency_ms"]

        if not legacy_ok.empty and not zt_ok.empty:
            rows[-1].update({
                "Legacy_mean_ms": float(legacy_ok.mean()),
                "Legacy_p99_ms": float(np.percentile(legacy_ok.to_numpy(), 99)),
                "mTLS_mean_ms": float(zt_ok.mean()),
                "mTLS_p99_ms": float(np.percentile(zt_ok.to_numpy(), 99)),
                "SecurityTax_mean_ms": float(zt_ok.mean() - legacy_ok.mean()),
                "SecurityTax_p99_delta_ms": float(np.percentile(zt_ok.to_numpy(), 99) - np.percentile(legacy_ok.to_numpy(), 99)),
            })

    out = os.path.join(FIG_DIR, "reviewer_headline_metrics.csv")
    pd.DataFrame(rows).to_csv(out, index=False)
    print(f"✅ Saved: {out}")

# -----------------------------
# Main
# -----------------------------
def main():
    _require_file(ADVERSARY_CSV)
    df = pd.read_csv(ADVERSARY_CSV)

    # Basic sanity: ensure required columns exist
    required_cols = {"Mode", "Attack_Type", "Result", "Latency_ms"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"CSV is missing required columns: {missing}")

    print("📊 Generating reviewer-ready figures...")
    fig_outcomes_stacked(df)
    fig_security_tax_bar(df)
    fig_latency_boxplot(df)

    # Keepalive plots if file exists
    if os.path.exists(KEEPALIVE_CSV):
        fig_keepalive_amortization()
    else:
        print(f"ℹ️ Keep-alive CSV not found (skipping keep-alive figures): {KEEPALIVE_CSV}")

    export_reviewer_tables(df)

    print("\n✅ Done. Figures are in:")
    print(f"   {FIG_DIR}")

if __name__ == "__main__":
    main()
