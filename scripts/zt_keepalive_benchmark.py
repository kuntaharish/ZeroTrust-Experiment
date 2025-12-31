import time
import os
import numpy as np
import pandas as pd
import requests

# Always resolve paths relative to repo root, regardless of where script is run from
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

ZT_URL = "https://localhost:6001/hop"

CA_CERT = os.path.join(REPO_ROOT, "certs", "ca.crt")
CLIENT_CERT = os.path.join(REPO_ROOT, "certs", "client_good.crt")
CLIENT_KEY = os.path.join(REPO_ROOT, "certs", "client_good.key")
GOOD_CERT = (CLIENT_CERT, CLIENT_KEY)

N = 2000
TIMEOUT_S = 5

DATA_DIR = os.path.join(REPO_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)


def main():
    # Sanity check paths early
    for p in [CA_CERT, CLIENT_CERT, CLIENT_KEY]:
        if not os.path.exists(p):
            raise FileNotFoundError(f"Missing required cert file: {p}")

    latencies = []
    conn_headers = []

    with requests.Session() as s:
        s.headers.update({"Connection": "keep-alive"})

        for i in range(N):
            start = time.perf_counter()
            resp = s.post(ZT_URL, cert=GOOD_CERT, verify=CA_CERT, timeout=TIMEOUT_S)
            end = time.perf_counter()

            if resp.status_code != 200:
                raise RuntimeError(f"Expected 200, got {resp.status_code}: {resp.text}")

            lat_ms = (end - start) * 1000.0
            latencies.append(lat_ms)

            # Sample response headers occasionally
            if i < 5 or i in (9, 99, 999):
                conn_headers.append({
                    "i": i,
                    "Connection": resp.headers.get("Connection", ""),
                    "Keep-Alive": resp.headers.get("Keep-Alive", ""),
                    "Server": resp.headers.get("Server", "")
                })

    arr = np.array(latencies)
    first = arr[:3]
    rest = arr[3:]

    print("\n--- ZT Keep-Alive Benchmark (GOOD mTLS only) ---")
    print(f"N={N}")
    print(f"First 3 mean: {first.mean():.4f} ms | p99: {np.percentile(first, 99):.4f}")
    print(f"After 3 mean: {rest.mean():.4f} ms | p95: {np.percentile(rest, 95):.4f} | p99: {np.percentile(rest, 99):.4f}")
    print(f"Overall mean: {arr.mean():.4f} ms | std: {arr.std(ddof=1):.4f} ms")

    out_csv = os.path.join(DATA_DIR, "zt_keepalive_benchmark.csv")
    pd.DataFrame({"latency_ms": arr}).to_csv(out_csv, index=False)
    print(f"\n✅ Saved: {out_csv}")

    print("\n--- Sampled response headers (to detect Connection: close) ---")
    for row in conn_headers:
        print(row)


if __name__ == "__main__":
    main()
