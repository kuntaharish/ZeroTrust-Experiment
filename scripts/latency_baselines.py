# scripts/latency_baselines.py
#
# Latency baselines with PAIRED deltas (reviewer-friendly)
# Measures:
#   - http_proxy   (plain HTTP through gateway)
#   - tls_only     (server TLS only)
#   - mtls_allowed (mutual TLS)
#
# Produces:
#   data/latency_baselines.csv.gz        (per-request rows; compatible with figure generator)
#   data/latency_pairs.csv.gz            (per-pair rows; deltas per pair)
#   data/latency_baselines_summary.csv   (small summary + paired delta stats)
#
# Key improvement:
#   - Paired measurement: for each "pair i", measure http/tls/mtls in randomized order,
#     then compute deltas:
#        tls - http
#        mtls - tls
#        mtls - http
#   - Prints CI for mean deltas (normal approx; n is large by default).
#
# Python 3.9+

import argparse
import os
import ssl
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import requests


# ----------------------------
# Repo paths
# ----------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DATA_DIR = REPO_ROOT / "data"


# ----------------------------
# Defaults (can override via env or CLI)
# ----------------------------
DEFAULT_HTTP_PROXY_URL = os.getenv("HTTP_PROXY_URL", "http://localhost:6200/a/hop")
DEFAULT_TLS_ONLY_URL = os.getenv("TLS_ONLY_URL", "https://localhost:6100/a/hop")
DEFAULT_MTLS_URL = os.getenv("MTLS_URL", "https://localhost:6000/a/hop")

DEFAULT_CA_CERT = os.getenv("CA_CERT", str(REPO_ROOT / "certs" / "ca.crt"))

# Client cert/key for mTLS
DEFAULT_CLIENT_CERT = os.getenv("CLIENT_CERT", str(REPO_ROOT / "certs" / "service-a.crt"))
DEFAULT_CLIENT_KEY = os.getenv("CLIENT_KEY", str(REPO_ROOT / "certs" / "service-a.key"))

DEFAULT_WORKLOAD_ID = os.getenv("WORKLOAD_ID", "service-a")


# ----------------------------
# Helpers
# ----------------------------
def ms_since(start: float, end: float) -> float:
    return (end - start) * 1000.0


def percentile(arr: np.ndarray, p: float) -> float:
    if arr.size == 0:
        return float("nan")
    return float(np.percentile(arr, p))


def summarize_latencies(values_ms: List[float]) -> Dict[str, float]:
    arr = np.array(values_ms, dtype=float)
    if arr.size == 0:
        return {
            "n": 0,
            "mean_ms": float("nan"),
            "std_ms": float("nan"),
            "p50_ms": float("nan"),
            "p95_ms": float("nan"),
            "p99_ms": float("nan"),
        }
    return {
        "n": int(arr.size),
        "mean_ms": float(np.mean(arr)),
        "std_ms": float(np.std(arr, ddof=0)),
        "p50_ms": float(np.median(arr)),
        "p95_ms": percentile(arr, 95),
        "p99_ms": percentile(arr, 99),
    }


def summarize_deltas(deltas_ms: List[float]) -> Dict[str, float]:
    """
    Returns delta summary + 95% CI for mean using normal approx (n large).
    """
    arr = np.array(deltas_ms, dtype=float)
    if arr.size == 0:
        return {
            "n": 0,
            "mean_ms": float("nan"),
            "std_ms": float("nan"),
            "p50_ms": float("nan"),
            "p95_ms": float("nan"),
            "p99_ms": float("nan"),
            "ci95_low_ms": float("nan"),
            "ci95_high_ms": float("nan"),
        }

    mean = float(np.mean(arr))
    std = float(np.std(arr, ddof=0))
    n = int(arr.size)
    se = std / (n ** 0.5) if n > 0 else float("nan")
    z = 1.96  # 95% CI (normal approx)
    ci_low = mean - z * se
    ci_high = mean + z * se

    return {
        "n": n,
        "mean_ms": mean,
        "std_ms": std,
        "p50_ms": float(np.median(arr)),
        "p95_ms": percentile(arr, 95),
        "p99_ms": percentile(arr, 99),
        "ci95_low_ms": float(ci_low),
        "ci95_high_ms": float(ci_high),
    }


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def request_once(
    session: requests.Session,
    url: str,
    timeout_s: float,
    verify: Optional[str] = None,
    cert: Optional[Tuple[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[bool, Optional[float], Optional[int], Optional[str], Dict[str, str]]:
    """
    Returns:
      ok, latency_ms, status_code, error_str, response_headers_subset
    """
    start = time.perf_counter()
    try:
        resp = session.post(
            url,
            timeout=timeout_s,
            verify=(verify if verify else True),
            cert=cert,
            headers=headers or {},
        )
        end = time.perf_counter()
        latency = ms_since(start, end)

        ok = (resp.status_code == 200)

        rh = {}
        for k in ["Server", "Connection", "Keep-Alive"]:
            if k in resp.headers:
                rh[k] = resp.headers.get(k, "")
        return ok, latency, int(resp.status_code), None, rh

    except Exception as e:
        end = time.perf_counter()
        latency = ms_since(start, end)
        return False, latency, None, f"{type(e).__name__}: {e}", {}


def preflight(
    name: str,
    url: str,
    timeout_s: float,
    verify: Optional[str],
    cert: Optional[Tuple[str, str]],
    headers: Dict[str, str],
) -> None:
    s = requests.Session()
    ok, _, code, err, rh = request_once(s, url, timeout_s, verify=verify, cert=cert, headers=headers)

    if code is None and err:
        raise RuntimeError(f"Preflight failed for {name}: {err}")

    if code is None:
        raise RuntimeError(f"Preflight failed for {name}: no status code returned")

    server = rh.get("Server", "")
    conn = rh.get("Connection", "")
    print(f"✅ {name} preflight status={code} | Server={server or '?'} | Connection={conn or '?'}")


def make_headers(workload_id: str, force_close: bool) -> Dict[str, str]:
    h = {"X-Workload-Id": workload_id}
    if force_close:
        h["Connection"] = "close"
    return h


def run_paired_phase(
    phase: str,
    pair_n: int,
    warm_discard: int,
    timeout_s: float,
    seed: int,
    force_close: bool,
    urls: Dict[str, str],
    ca_cert: str,
    mtls_cert: Tuple[str, str],
    workload_id: str,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Returns:
      per_request_df, per_pair_df
    """
    rng = np.random.default_rng(seed=seed)

    modes = ["http_proxy", "tls_only", "mtls_allowed"]
    warm_sessions: Dict[str, requests.Session] = {m: requests.Session() for m in modes}
    headers = make_headers(workload_id, force_close=force_close)

    # warm-up discard
    if phase == "WARM" and warm_discard > 0:
        for m in modes:
            for _ in range(warm_discard):
                s = warm_sessions[m]
                verify = ca_cert if m in ("tls_only", "mtls_allowed") else None
                cert = mtls_cert if m == "mtls_allowed" else None
                request_once(s, urls[m], timeout_s, verify=verify, cert=cert, headers=headers)

    per_req_rows = []
    per_pair_rows = []

    def call_mode(mode: str):
        s = requests.Session() if phase == "COLD" else warm_sessions[mode]
        verify = ca_cert if mode in ("tls_only", "mtls_allowed") else None
        cert = mtls_cert if mode == "mtls_allowed" else None
        return request_once(s, urls[mode], timeout_s, verify=verify, cert=cert, headers=headers)

    for i in range(pair_n):
        order = modes[:]
        rng.shuffle(order)

        lat_by_mode: Dict[str, Optional[float]] = {m: None for m in modes}
        ok_by_mode: Dict[str, bool] = {m: False for m in modes}
        hdr_sample = {}

        for order_idx, mode in enumerate(order):
            ok, lat_ms, code, err, rh = call_mode(mode)

            per_req_rows.append({
                "phase": phase,
                "pair_id": i,
                "order_idx": order_idx,
                "mode": mode,
                "ok": bool(ok),
                "status_code": int(code) if code is not None else -1,
                "latency_ms": float(lat_ms) if lat_ms is not None else float("nan"),
                "error": err if err else "",
            })

            ok_by_mode[mode] = bool(ok)
            lat_by_mode[mode] = float(lat_ms) if lat_ms is not None else None

            if i < 5 and rh:
                hdr_sample[mode] = rh

        all_ok = all(ok_by_mode[m] for m in modes)

        if all_ok:
            d_tls_http = float(lat_by_mode["tls_only"] - lat_by_mode["http_proxy"])  # type: ignore
            d_mtls_tls = float(lat_by_mode["mtls_allowed"] - lat_by_mode["tls_only"])  # type: ignore
            d_mtls_http = float(lat_by_mode["mtls_allowed"] - lat_by_mode["http_proxy"])  # type: ignore
        else:
            d_tls_http = float("nan")
            d_mtls_tls = float("nan")
            d_mtls_http = float("nan")

        per_pair_rows.append({
            "phase": phase,
            "pair_id": i,
            "http_proxy_ms": lat_by_mode["http_proxy"] if lat_by_mode["http_proxy"] is not None else float("nan"),
            "tls_only_ms": lat_by_mode["tls_only"] if lat_by_mode["tls_only"] is not None else float("nan"),
            "mtls_allowed_ms": lat_by_mode["mtls_allowed"] if lat_by_mode["mtls_allowed"] is not None else float("nan"),
            "ok_all_3": bool(all_ok),
            "delta_tls_minus_http_ms": d_tls_http,
            "delta_mtls_minus_tls_ms": d_mtls_tls,
            "delta_mtls_minus_http_ms": d_mtls_http,
            "hdr_sample": str(hdr_sample) if hdr_sample else "",
        })

    return pd.DataFrame(per_req_rows), pd.DataFrame(per_pair_rows)


def print_phase_summaries(phase: str, per_req: pd.DataFrame, per_pairs: pd.DataFrame) -> None:
    print(f"\n=== {phase} SUMMARY (success-only per mode) ===")
    for mode in ["http_proxy", "tls_only", "mtls_allowed"]:
        lat = per_req[(per_req["phase"] == phase) & (per_req["mode"] == mode) & (per_req["ok"] == True)]["latency_ms"].to_list()
        s = summarize_latencies(lat)
        print(
            f"{phase}:{mode:>12}  n={s['n']:4d}  mean={s['mean_ms']:.3f} ms  "
            f"p95={s['p95_ms']:.3f}  p99={s['p99_ms']:.3f}  std={s['std_ms']:.3f}"
        )

    ok_pairs = per_pairs[(per_pairs["phase"] == phase) & (per_pairs["ok_all_3"] == True)].copy()
    d1 = ok_pairs["delta_tls_minus_http_ms"].dropna().astype(float).to_list()
    d2 = ok_pairs["delta_mtls_minus_tls_ms"].dropna().astype(float).to_list()
    d3 = ok_pairs["delta_mtls_minus_http_ms"].dropna().astype(float).to_list()

    print(f"\n=== {phase} PAIRED DELTAS (only pairs where all 3 succeeded) ===")

    def fmt(name: str, s: Dict[str, float]) -> None:
        print(
            f"{name:>22}  n={int(s['n']):4d}  mean={s['mean_ms']:.3f} ms  "
            f"CI95=[{s['ci95_low_ms']:.3f}, {s['ci95_high_ms']:.3f}]  "
            f"p95={s['p95_ms']:.3f}  p99={s['p99_ms']:.3f}  std={s['std_ms']:.3f}"
        )

    fmt("TLS - HTTP", summarize_deltas(d1))
    fmt("mTLS - TLS", summarize_deltas(d2))
    fmt("mTLS - HTTP", summarize_deltas(d3))


def safe_to_csv(df: pd.DataFrame, path: Path, gzip: bool = False) -> bool:
    try:
        if gzip:
            df.to_csv(path, index=False, compression="gzip")
        else:
            df.to_csv(path, index=False)
        return True
    except OSError as e:
        print(f"⚠️  Could not write {path}: {e}")
        return False


def run() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pair-n", type=int, default=int(os.getenv("PAIR_N", "2000")),
                    help="Number of paired trials per phase (each trial measures 3 modes)")
    ap.add_argument("--warm-discard", type=int, default=int(os.getenv("WARM_DISCARD", "3")),
                    help="Discard first k requests per mode in warm phase")
    ap.add_argument("--timeout", type=float, default=float(os.getenv("TIMEOUT_S", "3.0")),
                    help="Per-request timeout seconds")
    ap.add_argument("--seed", type=int, default=int(os.getenv("SEED", "20250101")),
                    help="RNG seed (order randomization)")
    ap.add_argument("--force-close", action="store_true",
                    help="Send Connection: close header (makes behavior explicit)")
    ap.add_argument("--out-dir", type=str, default=str(DATA_DIR),
                    help="Output directory (default: ./data)")
    ap.add_argument("--write-csv", action="store_true",
                    help="Also write uncompressed .csv (in addition to .csv.gz)")
    args = ap.parse_args()

    out_dir = Path(args.out_dir).resolve()
    ensure_dir(out_dir)

    urls = {
        "http_proxy": DEFAULT_HTTP_PROXY_URL,
        "tls_only": DEFAULT_TLS_ONLY_URL,
        "mtls_allowed": DEFAULT_MTLS_URL,
    }

    ca_cert = str(Path(DEFAULT_CA_CERT).resolve())
    client_cert = str(Path(DEFAULT_CLIENT_CERT).resolve())
    client_key = str(Path(DEFAULT_CLIENT_KEY).resolve())
    mtls_cert = (client_cert, client_key)

    print("\n=== LATENCY BASELINES (PAIRED DELTAS) ===")
    print(f"Python SSL backend: {ssl.OPENSSL_VERSION}")
    print(f"PAIR_N={args.pair_n} | warm_discard={args.warm_discard} | timeout={args.timeout}s | seed={args.seed}")
    print(f"HTTP_PROXY_URL: {urls['http_proxy']}")
    print(f"TLS_ONLY_URL:   {urls['tls_only']}")
    print(f"MTLS_URL:       {urls['mtls_allowed']}")
    print(f"CA_CERT:        {ca_cert}")
    print(f"CLIENT_CERT:    {client_cert}")
    print(f"CLIENT_KEY:     {client_key}")
    print(f"X-Workload-Id:   {DEFAULT_WORKLOAD_ID}")
    print(f"force_close:    {bool(args.force_close)}")

    # Preflight (fail fast)
    headers = make_headers(DEFAULT_WORKLOAD_ID, force_close=args.force_close)
    preflight("http_proxy", urls["http_proxy"], args.timeout, verify=None, cert=None, headers=headers)
    preflight("tls_only", urls["tls_only"], args.timeout, verify=ca_cert, cert=None, headers=headers)
    preflight("mtls_allowed", urls["mtls_allowed"], args.timeout, verify=ca_cert, cert=mtls_cert, headers=headers)

    print("\n--- PAIRED COLD (handshake-heavy) ---")
    cold_req, cold_pairs = run_paired_phase(
        phase="COLD",
        pair_n=args.pair_n,
        warm_discard=args.warm_discard,
        timeout_s=args.timeout,
        seed=args.seed,
        force_close=args.force_close,
        urls=urls,
        ca_cert=ca_cert,
        mtls_cert=mtls_cert,
        workload_id=DEFAULT_WORKLOAD_ID,
    )

    print("\n--- PAIRED WARM (steady-state) ---")
    warm_req, warm_pairs = run_paired_phase(
        phase="WARM",
        pair_n=args.pair_n,
        warm_discard=args.warm_discard,
        timeout_s=args.timeout,
        seed=args.seed + 1,
        force_close=args.force_close,
        urls=urls,
        ca_cert=ca_cert,
        mtls_cert=mtls_cert,
        workload_id=DEFAULT_WORKLOAD_ID,
    )

    per_req = pd.concat([cold_req, warm_req], ignore_index=True)
    per_pairs = pd.concat([cold_pairs, warm_pairs], ignore_index=True)

    print_phase_summaries("COLD", per_req, per_pairs)
    print_phase_summaries("WARM", per_req, per_pairs)

    # Write outputs (gzip by default to save disk)
    out_baselines_gz = out_dir / "latency_baselines.csv.gz"
    out_pairs_gz = out_dir / "latency_pairs.csv.gz"
    out_summary = out_dir / "latency_baselines_summary.csv"

    wrote1 = safe_to_csv(per_req, out_baselines_gz, gzip=True)
    wrote2 = safe_to_csv(per_pairs, out_pairs_gz, gzip=True)

    summary_rows = []
    for phase in ["COLD", "WARM"]:
        for mode in ["http_proxy", "tls_only", "mtls_allowed"]:
            lat = per_req[(per_req["phase"] == phase) & (per_req["mode"] == mode) & (per_req["ok"] == True)]["latency_ms"].to_list()
            s = summarize_latencies(lat)
            summary_rows.append({"kind": "mode_latency", "phase": phase, "name": mode, **s})

        ok_pairs = per_pairs[(per_pairs["phase"] == phase) & (per_pairs["ok_all_3"] == True)].copy()
        d_tls_http = ok_pairs["delta_tls_minus_http_ms"].dropna().astype(float).to_list()
        d_mtls_tls = ok_pairs["delta_mtls_minus_tls_ms"].dropna().astype(float).to_list()
        d_mtls_http = ok_pairs["delta_mtls_minus_http_ms"].dropna().astype(float).to_list()

        summary_rows.append({"kind": "paired_delta", "phase": phase, "name": "TLS-HTTP", **summarize_deltas(d_tls_http)})
        summary_rows.append({"kind": "paired_delta", "phase": phase, "name": "mTLS-TLS", **summarize_deltas(d_mtls_tls)})
        summary_rows.append({"kind": "paired_delta", "phase": phase, "name": "mTLS-HTTP", **summarize_deltas(d_mtls_http)})

    summary_df = pd.DataFrame(summary_rows)
    wrote3 = safe_to_csv(summary_df, out_summary, gzip=False)

    if args.write_csv:
        safe_to_csv(per_req, out_dir / "latency_baselines.csv", gzip=False)
        safe_to_csv(per_pairs, out_dir / "latency_pairs.csv", gzip=False)

    print("\n✅ Outputs:")
    if wrote1:
        print(f"  - {out_baselines_gz}")
    if wrote2:
        print(f"  - {out_pairs_gz}")
    if wrote3:
        print(f"  - {out_summary}")

    if not (wrote1 and wrote2 and wrote3):
        print("\n⚠️  One or more outputs could not be written (disk space?).")
        print("   Fix: delete large old CSVs in ./data or free disk, then rerun.")


if __name__ == "__main__":
    run()
