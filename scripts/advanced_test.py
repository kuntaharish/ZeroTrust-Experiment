import os
import time
import numpy as np
import pandas as pd
import requests
from typing import Optional, Tuple

# -----------------------------
# Path-safe repo root + certs
# -----------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_DIR = os.path.join(REPO_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)

CA_CERT = os.path.join(REPO_ROOT, "certs", "ca.crt")
GOOD_CERT = (
    os.path.join(REPO_ROOT, "certs", "client_good.crt"),
    os.path.join(REPO_ROOT, "certs", "client_good.key"),
)
BAD_CERT = (
    os.path.join(REPO_ROOT, "certs", "client_bad.crt"),
    os.path.join(REPO_ROOT, "certs", "client_bad.key"),
)

# -----------------------------
# Targets
# -----------------------------
LEGACY_URLS = [
    "http://localhost:5001/hop",
    "http://localhost:5002/hop",
]
ZT_URLS = [
    "https://localhost:6001/hop",
    "https://localhost:6002/hop",
]

# Sticky targets for warm reuse
LEGACY_STICKY = "http://localhost:5001/hop"
ZT_STICKY = "https://localhost:6001/hop"

# -----------------------------
# Experiment Settings
# -----------------------------
TRIALS = 1200
WARMUP = 30
TIMEOUT_S = 3

ATTACK_TYPES = ["LEGACY_CLEAR", "ZT_GOOD_MTLS", "ZT_NO_CERT", "ZT_ROGUE_CERT"]


def _check_files_exist():
    for p in [CA_CERT, GOOD_CERT[0], GOOD_CERT[1], BAD_CERT[0], BAD_CERT[1]]:
        if not os.path.exists(p):
            raise FileNotFoundError(f"Missing required cert file: {p}")


def pick_url(urls) -> str:
    return str(np.random.choice(urls))


def classify(event: str, status_code: Optional[int]) -> str:
    """
    Paper-friendly labels:
    - TLS handshake rejection (no cert / rogue cert) => BLOCKED_TLS
    - HTTP 200 => SUCCESS (authorized)
    - HTTP 403 => BLOCKED_APP (L7 policy)
    - Other => ERROR
    """
    if event == "TLS_FAIL":
        return "BLOCKED_TLS"
    if event == "CONN_FAIL":
        return "ERROR"
    if status_code == 200:
        return "SUCCESS"
    if status_code == 403:
        return "BLOCKED_APP"
    return "ERROR"


def timed_post(session: Optional[requests.Session], url: str, **kwargs) -> Tuple[str, Optional[int], float]:
    """
    Returns: (event, status_code, latency_ms)
    event: "HTTP", "TLS_FAIL", or "CONN_FAIL"
    """
    start = time.perf_counter()
    try:
        if session is None:
            resp = requests.post(url, timeout=TIMEOUT_S, **kwargs)
        else:
            resp = session.post(url, timeout=TIMEOUT_S, **kwargs)
        end = time.perf_counter()
        return "HTTP", resp.status_code, (end - start) * 1000

    except requests.exceptions.SSLError:
        end = time.perf_counter()
        return "TLS_FAIL", None, (end - start) * 1000

    except requests.exceptions.ConnectionError:
        end = time.perf_counter()
        # HTTPS connection errors in this test are typically TLS-level blocks (no/rogue cert)
        if url.startswith("https://"):
            return "TLS_FAIL", None, (end - start) * 1000
        return "CONN_FAIL", None, (end - start) * 1000

    except requests.exceptions.Timeout:
        end = time.perf_counter()
        return "CONN_FAIL", None, (end - start) * 1000


def latency_stats(series: pd.Series) -> dict:
    if series.empty:
        return {"n": 0, "mean": np.nan, "std": np.nan, "p95": np.nan, "p99": np.nan}
    arr = series.to_numpy()
    return {
        "n": int(len(arr)),
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0,
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
    }


def print_box(title: str):
    line = "=" * len(title)
    print(f"\n{title}\n{line}")


def print_table(df: pd.DataFrame, title: str):
    print(f"\n{title}")
    print("-" * len(title))
    if df.empty:
        print("(no rows)")
        return
    print(df.to_string(index=False))


def run_mode(mode_name: str, cold_connections: bool) -> pd.DataFrame:
    rows = []

    legacy_sess = None if cold_connections else requests.Session()
    zt_good_sess = None if cold_connections else requests.Session()
    zt_nocert_sess = None if cold_connections else requests.Session()
    zt_rogue_sess = None if cold_connections else requests.Session()

    # Warm-up: warm only good path on sticky targets (so warm mode is meaningful)
    for _ in range(WARMUP):
        try:
            requests.post(LEGACY_STICKY, timeout=TIMEOUT_S)
        except Exception:
            pass
        try:
            requests.post(ZT_STICKY, cert=GOOD_CERT, verify=CA_CERT, timeout=TIMEOUT_S)
        except Exception:
            pass

    for i in range(TRIALS):
        attack = str(np.random.choice(ATTACK_TYPES))

        if attack == "LEGACY_CLEAR":
            url = LEGACY_STICKY if not cold_connections else pick_url(LEGACY_URLS)
            event, code, lat = timed_post(legacy_sess if not cold_connections else None, url)
            arch = "Legacy"

        elif attack == "ZT_GOOD_MTLS":
            url = ZT_STICKY if not cold_connections else pick_url(ZT_URLS)
            event, code, lat = timed_post(
                zt_good_sess if not cold_connections else None,
                url,
                cert=GOOD_CERT,
                verify=CA_CERT
            )
            arch = "Zero-Trust"

        elif attack == "ZT_NO_CERT":
            url = pick_url(ZT_URLS)
            event, code, lat = timed_post(
                zt_nocert_sess if not cold_connections else None,
                url,
                verify=CA_CERT
            )
            arch = "Zero-Trust"

        else:  # ZT_ROGUE_CERT
            url = pick_url(ZT_URLS)
            event, code, lat = timed_post(
                zt_rogue_sess if not cold_connections else None,
                url,
                cert=BAD_CERT,
                verify=CA_CERT
            )
            arch = "Zero-Trust"

        rows.append({
            "Mode": mode_name,
            "Trial": i,
            "Architecture": arch,
            "NodeURL": url,
            "Attack_Type": attack,
            "Event": event,
            "Status_Code": int(code) if code is not None else 0,
            "Result": classify(event, code),
            "Latency_ms": round(lat, 3),
        })

    for s in [legacy_sess, zt_good_sess, zt_nocert_sess, zt_rogue_sess]:
        if s:
            s.close()

    return pd.DataFrame(rows)


def make_readable_report(df: pd.DataFrame):
    print_box("EB-1A Zero Trust Experiment Report (Real mTLS)")

    # 1) Outcomes as rates
    counts = df.groupby(["Mode", "Attack_Type", "Result"]).size().reset_index(name="Count")
    totals = df.groupby(["Mode", "Attack_Type"]).size().reset_index(name="Total")
    merged = counts.merge(totals, on=["Mode", "Attack_Type"], how="left")
    merged["Rate_%"] = (merged["Count"] / merged["Total"] * 100).round(1)

    # Pivot into a compact table with % (Count/Total)
    def fmt_row(row):
        return f"{int(row['Count'])}/{int(row['Total'])} ({row['Rate_%']}%)"

    merged["Display"] = merged.apply(fmt_row, axis=1)

    pivot = merged.pivot_table(
        index=["Mode", "Attack_Type"],
        columns="Result",
        values="Display",
        aggfunc="first",
        fill_value="0/0 (0.0%)"
    ).reset_index()

    # Ensure consistent column order
    ordered_cols = ["Mode", "Attack_Type"]
    for col in ["SUCCESS", "BLOCKED_TLS", "BLOCKED_APP", "ERROR"]:
        if col in pivot.columns:
            ordered_cols.append(col)
    pivot = pivot[ordered_cols]

    print_table(pivot, "1) Outcomes (Count/Total and %)")

    # 2) Latency summaries (SUCCESS only)
    print_table(pd.DataFrame([
        {"Mode": "COLD_CONNECTIONS", "Path": "Legacy (HTTP 200)", **latency_stats(df[(df["Mode"]=="COLD_CONNECTIONS") & (df["Attack_Type"]=="LEGACY_CLEAR") & (df["Result"]=="SUCCESS")]["Latency_ms"])},
        {"Mode": "COLD_CONNECTIONS", "Path": "ZT Good mTLS (200)", **latency_stats(df[(df["Mode"]=="COLD_CONNECTIONS") & (df["Attack_Type"]=="ZT_GOOD_MTLS") & (df["Result"]=="SUCCESS")]["Latency_ms"])},
        {"Mode": "WARM_CONNECTIONS", "Path": "Legacy (HTTP 200)", **latency_stats(df[(df["Mode"]=="WARM_CONNECTIONS") & (df["Attack_Type"]=="LEGACY_CLEAR") & (df["Result"]=="SUCCESS")]["Latency_ms"])},
        {"Mode": "WARM_CONNECTIONS", "Path": "ZT Good mTLS (200)", **latency_stats(df[(df["Mode"]=="WARM_CONNECTIONS") & (df["Attack_Type"]=="ZT_GOOD_MTLS") & (df["Result"]=="SUCCESS")]["Latency_ms"])},
    ]).rename(columns={
        "n": "n",
        "mean": "mean_ms",
        "std": "std_ms",
        "p95": "p95_ms",
        "p99": "p99_ms"
    }), "2) Latency Summary (SUCCESS only)")

    # 3) Security tax (mean difference, SUCCESS only)
    def mean_latency(mode, attack):
        s = df[(df["Mode"] == mode) & (df["Attack_Type"] == attack) & (df["Result"] == "SUCCESS")]["Latency_ms"]
        return float(s.mean()) if not s.empty else np.nan

    cold_tax = mean_latency("COLD_CONNECTIONS", "ZT_GOOD_MTLS") - mean_latency("COLD_CONNECTIONS", "LEGACY_CLEAR")
    warm_tax = mean_latency("WARM_CONNECTIONS", "ZT_GOOD_MTLS") - mean_latency("WARM_CONNECTIONS", "LEGACY_CLEAR")

    print_box("3) Security Tax (mTLS SUCCESS vs Legacy SUCCESS)")
    print(f"Cold-path tax (handshake-heavy): {cold_tax:.3f} ms")
    print(f"Warm-path tax (steady-state):    {warm_tax:.3f} ms")

    # 4) Warm handshake vs steady-state on ZT Good mTLS
    warm_zt = df[(df["Mode"] == "WARM_CONNECTIONS") & (df["Attack_Type"] == "ZT_GOOD_MTLS") & (df["Result"] == "SUCCESS")]["Latency_ms"].reset_index(drop=True)
    if len(warm_zt) >= 10:
        first = warm_zt.iloc[:3]
        rest = warm_zt.iloc[3:]
        first_s = latency_stats(first)
        rest_s = latency_stats(rest)

        print_box("4) Warm ZT Good mTLS: Handshake vs Steady-State")
        print(f"First 3 requests (handshake-heavy): mean={first_s['mean']:.3f} ms | p99={first_s['p99']:.3f} ms")
        print(f"After first 3 (steady-state):       mean={rest_s['mean']:.3f} ms | p99={rest_s['p99']:.3f} ms")

    print("\n✅ CSV saved for charts/evidence:")
    print(f"   {os.path.join(DATA_DIR, 'advanced_adversary_results_real_mtls.csv')}")


def main():
    _check_files_exist()

    df_cold = run_mode("COLD_CONNECTIONS", cold_connections=True)
    df_warm = run_mode("WARM_CONNECTIONS", cold_connections=False)
    df = pd.concat([df_cold, df_warm], ignore_index=True)

    out_csv = os.path.join(DATA_DIR, "advanced_adversary_results_real_mtls.csv")
    df.to_csv(out_csv, index=False)

    make_readable_report(df)


if __name__ == "__main__":
    main()
