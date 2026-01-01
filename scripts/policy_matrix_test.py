import os
import requests
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
CERTS = os.path.join(REPO_ROOT, "certs")
DATA_DIR = os.path.join(REPO_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)

MTLS_BASE = "https://localhost:6000"
CA = os.path.join(CERTS, "ca.crt")

IDENTITIES = ["service-a", "service-b", "service-c", "service-d"]
TARGETS = ["a", "b", "c", "d"]

def cert(identity: str):
    return (os.path.join(CERTS, f"{identity}.crt"), os.path.join(CERTS, f"{identity}.key"))

def call(identity: str, target: str):
    url = f"{MTLS_BASE}/{target}/hop"
    try:
        r = requests.post(url, cert=cert(identity), verify=CA, timeout=3)
        if r.status_code == 200:
            return "ALLOW(200)"
        if r.status_code == 403:
            return "DENY(403)"
        return f"HTTP({r.status_code})"
    except requests.exceptions.SSLError:
        return "BLOCKED_TLS(SSL)"
    except requests.exceptions.ConnectionError:
        return "BLOCKED_TLS(CONN)"
    except Exception:
        return "ERROR"

def main():
    rows = []
    for ident in IDENTITIES:
        row = {"caller_identity": ident}
        for t in TARGETS:
            row[t] = call(ident, t)
        rows.append(row)

    df = pd.DataFrame(rows)
    out = os.path.join(DATA_DIR, "policy_matrix.csv")
    df.to_csv(out, index=False)

    print("\n=== POLICY MATRIX (mTLS + allowlist) ===")
    print(df.to_string(index=False))
    print(f"\n✅ Saved: {out}")

if __name__ == "__main__":
    main()
