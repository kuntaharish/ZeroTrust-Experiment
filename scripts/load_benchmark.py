import os
import time
import numpy as np
import pandas as pd
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
CERTS = os.path.join(REPO_ROOT, "certs")
DATA_DIR = os.path.join(REPO_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)

CA = os.path.join(CERTS, "ca.crt")
CLIENT = (os.path.join(CERTS, "service-a.crt"), os.path.join(CERTS, "service-a.key"))

TARGETS = [
    ("http_proxy", "http://localhost:6200/a/hop", None, None),
    ("tls_only", "https://localhost:6100/a/hop", None, CA),
    ("mtls_allowed", "https://localhost:6000/a/hop", CLIENT, CA),
]

CONCURRENCY_LEVELS = [1, 10, 50, 100]
TOTAL_REQUESTS = 2000
TIMEOUT_S = 3

def worker(url, cert, verify, n):
    lat = []
    ok = 0
    with requests.Session() as s:
        for _ in range(n):
            start = time.perf_counter()
            try:
                r = s.post(url, cert=cert, verify=verify, timeout=TIMEOUT_S)
                end = time.perf_counter()
                ms = (end - start) * 1000.0
                if r.status_code == 200:
                    ok += 1
                    lat.append(ms)
            except Exception:
                pass
    return ok, lat

def summarize(arr):
    arr = np.array(arr)
    if len(arr) == 0:
        return {"n": 0, "mean": np.nan, "p95": np.nan, "p99": np.nan}
    return {
        "n": int(len(arr)),
        "mean": float(np.mean(arr)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
    }

def main():
    rows = []

    for name, url, cert, verify in TARGETS:
        for c in CONCURRENCY_LEVELS:
            per_worker = TOTAL_REQUESTS // c
            extras = TOTAL_REQUESTS % c

            start_wall = time.perf_counter()
            all_lat = []
            all_ok = 0

            with ThreadPoolExecutor(max_workers=c) as ex:
                futures = []
                for i in range(c):
                    n = per_worker + (1 if i < extras else 0)
                    futures.append(ex.submit(worker, url, cert, verify, n))

                for f in as_completed(futures):
                    ok, lat = f.result()
                    all_ok += ok
                    all_lat.extend(lat)

            end_wall = time.perf_counter()
            wall_s = end_wall - start_wall
            rps = all_ok / wall_s if wall_s > 0 else 0

            s = summarize(all_lat)
            rows.append({
                "baseline": name,
                "concurrency": c,
                "ok_200": all_ok,
                "wall_seconds": round(wall_s, 3),
                "throughput_rps": round(rps, 2),
                "lat_n": s["n"],
                "lat_mean_ms": round(s["mean"], 3) if not np.isnan(s["mean"]) else None,
                "lat_p95_ms": round(s["p95"], 3) if not np.isnan(s["p95"]) else None,
                "lat_p99_ms": round(s["p99"], 3) if not np.isnan(s["p99"]) else None,
            })

            print(f"\n{name} @ concurrency={c}: ok={all_ok}, rps={rps:.2f}, mean={s['mean']:.3f}ms, p99={s['p99']:.3f}ms")

    df = pd.DataFrame(rows)
    out = os.path.join(DATA_DIR, "load_benchmark.csv")
    df.to_csv(out, index=False)
    print(f"\n✅ Saved: {out}")

if __name__ == "__main__":
    main()
