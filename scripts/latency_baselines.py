import os
import time
import numpy as np
import pandas as pd
import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
CERTS = os.path.join(REPO_ROOT, "certs")
DATA_DIR = os.path.join(REPO_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)

CA = os.path.join(CERTS, "ca.crt")
CLIENT = (os.path.join(CERTS, "service-a.crt"), os.path.join(CERTS, "service-a.key"))

# Same target service path across baselines
HTTP_PROXY = "http://localhost:6200/a/hop"
TLS_ONLY = "https://localhost:6100/a/hop"
MTLS_ALLOWED = "https://localhost:6000/a/hop"  # service-a -> /a is allowed by policy

N = 2000
WARM_DISCARD = 3

def one_request(url, session=None, cert=None, verify=None, force_close=False):
    headers = {}
    if force_close:
        headers["Connection"] = "close"

    start = time.perf_counter()
    try:
        if session:
            r = session.post(url, headers=headers, cert=cert, verify=verify, timeout=3)
        else:
            r = requests.post(url, headers=headers, cert=cert, verify=verify, timeout=3)
        end = time.perf_counter()
        return r.status_code, (end - start) * 1000.0
    except requests.exceptions.SSLError:
        end = time.perf_counter()
        return 0, (end - start) * 1000.0
    except requests.exceptions.ConnectionError:
        end = time.perf_counter()
        return 0, (end - start) * 1000.0

def summarize(name, arr):
    arr = np.array(arr)
    return {
        "name": name,
        "n": int(len(arr)),
        "mean_ms": float(np.mean(arr)),
        "p95_ms": float(np.percentile(arr, 95)),
        "p99_ms": float(np.percentile(arr, 99)),
        "std_ms": float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0,
    }

def run():
    rows = []

    targets = [
        ("http_proxy", HTTP_PROXY, None, None),
        ("tls_only", TLS_ONLY, None, CA),
        ("mtls_allowed", MTLS_ALLOWED, CLIENT, CA),
    ]

    # COLD: new connection each request (force close + no session reuse)
    for name, url, cert, verify in targets:
        lat = []
        for i in range(N):
            code, ms = one_request(url, session=None, cert=cert, verify=verify, force_close=True)
            rows.append({"mode": "cold", "baseline": name, "i": i, "status_code": code, "latency_ms": round(ms, 3)})
            if code == 200:
                lat.append(ms)
        print("\nCOLD:", summarize(name, lat))

    # WARM: single session keep-alive, discard first few
    for name, url, cert, verify in targets:
        with requests.Session() as s:
            lat = []
            for i in range(N):
                code, ms = one_request(url, session=s, cert=cert, verify=verify, force_close=False)
                rows.append({"mode": "warm", "baseline": name, "i": i, "status_code": code, "latency_ms": round(ms, 3)})
                if code == 200 and i >= WARM_DISCARD:
                    lat.append(ms)
        print("\nWARM (after discard):", summarize(name, lat))

    df = pd.DataFrame(rows)
    out = os.path.join(DATA_DIR, "latency_baselines.csv")
    df.to_csv(out, index=False)
    print(f"\n✅ Saved: {out}")

    print("\n=== Decomposed overhead (warm, success only) ===")
    warm_ok = df[(df["mode"] == "warm") & (df["status_code"] == 200) & (df["i"] >= WARM_DISCARD)]
    mean_http = warm_ok[warm_ok["baseline"] == "http_proxy"]["latency_ms"].mean()
    mean_tls = warm_ok[warm_ok["baseline"] == "tls_only"]["latency_ms"].mean()
    mean_mtls = warm_ok[warm_ok["baseline"] == "mtls_allowed"]["latency_ms"].mean()

    print(f"HTTP proxy mean: {mean_http:.3f} ms")
    print(f"TLS-only mean:   {mean_tls:.3f} ms (TLS tax ≈ {mean_tls-mean_http:.3f} ms)")
    print(f"mTLS mean:       {mean_mtls:.3f} ms (mTLS increment over TLS ≈ {mean_mtls-mean_tls:.3f} ms)")

if __name__ == "__main__":
    run()
