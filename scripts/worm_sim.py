import requests
import pandas as pd
import time
import os
import random
import string
import numpy as np

LEGACY_NODES = ["http://localhost:5001/hop", "http://localhost:5002/hop"]
ZT_NODES = ["http://localhost:6001/hop", "http://localhost:6002/hop"]

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

VALID_CERT = "EB1A-RESEARCH-SIG-2025"

TRIALS = 500          # bump to 2000+ for “paper-grade”
WARMUP = 30           # throw away warm-up measurements

RESET_URLS = ["http://localhost:6001/reset", "http://localhost:6002/reset"]  # only if you implemented /reset


def maybe_reset_zt_state():
    # Safe to call even if /reset doesn't exist (it'll just fail quietly)
    with requests.Session() as s:
        for url in RESET_URLS:
            try:
                s.post(url, timeout=1)
            except Exception:
                pass


def classify(status_code: int) -> str:
    if status_code == 200:
        return "BREACHED"
    if status_code == 403:
        return "BLOCKED"
    return "SERVER_ERROR"


def timed_post(session: requests.Session, url: str, headers: dict) -> tuple[int, float]:
    start = time.perf_counter()
    resp = session.post(url, headers=headers, timeout=5)
    end = time.perf_counter()
    return resp.status_code, (end - start) * 1000


def run_trials(target_urls, arch_name, workload_id, cert_signature=None, invalid_mode=False):
    rows = []
    with requests.Session() as session:
        # Warm-up
        for _ in range(WARMUP):
            for url in target_urls:
                headers = {"X-Workload-Id": workload_id}
                if cert_signature:
                    headers["X-Client-Cert-Signature"] = cert_signature
                session.post(url, headers=headers, timeout=5)

        # Measured trials
        for t in range(TRIALS):
            for i, url in enumerate(target_urls, start=1):
                headers = {"X-Workload-Id": workload_id}

                if cert_signature:
                    headers["X-Client-Cert-Signature"] = cert_signature
                elif invalid_mode:
                    # Exercise revocation: same workload id + repeated invalid creds
                    headers["X-Client-Cert-Signature"] = ''.join(
                        random.choices(string.ascii_letters + string.digits, k=16)
                    )

                try:
                    code, latency = timed_post(session, url, headers)
                    rows.append({
                        "Trial": t,
                        "Architecture": arch_name,
                        "Node": i,
                        "Workload_Id": workload_id,
                        "Status_Code": code,
                        "Result": classify(code),
                        "Latency_ms": round(latency, 3),
                    })
                except Exception:
                    rows.append({
                        "Trial": t,
                        "Architecture": arch_name,
                        "Node": i,
                        "Workload_Id": workload_id,
                        "Status_Code": 0,
                        "Result": "CLIENT_ERROR",
                        "Latency_ms": 0.0,
                    })
    return rows


def print_latency_stats(df, label):
    lat = df["Latency_ms"].to_numpy()
    if len(lat) == 0:
        print(f"{label}: no latency samples")
        return
    print(f"\n--- {label} LATENCY STATS (ms) ---")
    print(f"n={len(lat)}")
    print(f"mean={np.mean(lat):.4f}  std={np.std(lat, ddof=1):.4f}")
    print(f"p95={np.percentile(lat, 95):.4f}  p99={np.percentile(lat, 99):.4f}")


if __name__ == "__main__":
    print("Starting EB-1A Experimental Data Collection...\n")

    # Reset ZT revocation state between runs (optional but recommended)
    maybe_reset_zt_state()

    legacy_rows = run_trials(
        LEGACY_NODES,
        arch_name="Legacy-Perimeter",
        workload_id="legacy-runner",
        cert_signature=None,
        invalid_mode=False
    )

    # Unauthorized attacker: repeated invalid attempts with SAME workload id → triggers revocation
    zt_unauth_rows = run_trials(
        ZT_NODES,
        arch_name="Zero-Trust-Unauthorized",
        workload_id="attacker-x",
        cert_signature=None,
        invalid_mode=True
    )

    # Authorized workload: valid cert → should stay allowed
    zt_auth_rows = run_trials(
        ZT_NODES,
        arch_name="Zero-Trust-Authorized",
        workload_id="service-a",
        cert_signature=VALID_CERT,
        invalid_mode=False
    )

    df = pd.DataFrame(legacy_rows + zt_unauth_rows + zt_auth_rows)
    out_csv = os.path.join(DATA_DIR, "experiment_results.csv")
    df.to_csv(out_csv, index=False)

    print("\n--- OUTCOME COUNTS ---")
    print(df.groupby(["Architecture", "Result"]).size().reset_index(name="Count"))

    # Security tax: compare legacy mean vs authorized ZT mean (only successful 200s if you want stricter)
    legacy_lat = df[(df["Architecture"] == "Legacy-Perimeter") & (df["Result"] == "BREACHED")]["Latency_ms"]
    zt_lat = df[(df["Architecture"] == "Zero-Trust-Authorized") & (df["Result"] == "BREACHED")]["Latency_ms"]
    if len(legacy_lat) and len(zt_lat):
        print_latency_stats(legacy_lat.to_frame(), "LEGACY (200s)")
        print_latency_stats(zt_lat.to_frame(), "ZT AUTH (200s)")
        print(f"\nCalculated Latency Overhead (mean): {(zt_lat.mean() - legacy_lat.mean()):.4f} ms")
    else:
        print("\nCould not compute security tax: missing 200 samples.")

    print(f"\nResults saved to {out_csv}")
