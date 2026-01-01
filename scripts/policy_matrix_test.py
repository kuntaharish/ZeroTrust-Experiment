import os
import ssl
import string
from pathlib import Path
from typing import Dict, Tuple

import pandas as pd
import requests
from requests.exceptions import SSLError, ConnectionError, Timeout

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
CERT_DIR = REPO_ROOT / "certs"
DATA_DIR = REPO_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

BASE_URL = os.environ.get("ZT_GATEWAY_URL", "https://localhost:6000")
CA_CERT = CERT_DIR / "ca.crt"

LETTERS = list(string.ascii_lowercase[:12])  # a..l
TARGETS = LETTERS
CALLERS = [f"service-{c}" for c in LETTERS]


def cert_pair(identity: str) -> Tuple[str, str]:
    return str(CERT_DIR / f"{identity}.crt"), str(CERT_DIR / f"{identity}.key")


def classify(resp_status: int = None, exc: Exception = None) -> str:
    if exc is not None:
        if isinstance(exc, SSLError):
            return "BLOCKED_TLS(SSL)"
        if isinstance(exc, ConnectionError):
            return "DOWN(CONN)"
        if isinstance(exc, Timeout):
            return "TIMEOUT"
        return "ERROR"
    if resp_status == 200:
        return "ALLOW(200)"
    if resp_status == 403:
        return "DENY(403)"
    return f"ERR({resp_status})"


def main() -> None:
    print("\n=== POLICY MATRIX (mTLS + allowlist) ===")
    print(f"Python SSL backend: {ssl.OPENSSL_VERSION}")

    if not CA_CERT.exists():
        raise FileNotFoundError(f"Missing CA cert: {CA_CERT}")

    # Ensure all client certs exist
    missing = []
    for caller in CALLERS:
        crt, key = cert_pair(caller)
        if not Path(crt).exists():
            missing.append(crt)
        if not Path(key).exists():
            missing.append(key)
    if missing:
        raise FileNotFoundError("Missing cert files:\n" + "\n".join(missing))

    timeout_s = 4

    table: Dict[str, Dict[str, str]] = {}
    debug_rows = []

    for caller in CALLERS:
        table[caller] = {}
        crt, key = cert_pair(caller)

        # IMPORTANT: isolate TLS per caller (avoid keepalive mixing identities)
        with requests.Session() as s:
            s.trust_env = False
            for tgt in TARGETS:
                url = f"{BASE_URL}/{tgt}/hop"
                try:
                    r = s.post(
                        url,
                        cert=(crt, key),
                        verify=str(CA_CERT),
                        timeout=timeout_s,
                        headers={"Connection": "close", "User-Agent": "policy-matrix-test/12svc"},
                    )
                    table[caller][tgt] = classify(resp_status=r.status_code)
                    debug_rows.append({
                        "caller_requested": caller,
                        "target": tgt,
                        "status": r.status_code,
                        "x_debug_client_cn": r.headers.get("X-Debug-Client-CN", ""),
                        "x_debug_segment": r.headers.get("X-Debug-Segment", ""),
                        "x_debug_allowed": r.headers.get("X-Debug-Allowed", ""),
                    })
                    r.close()
                except Exception as e:
                    table[caller][tgt] = classify(exc=e)

    df = pd.DataFrame.from_dict(table, orient="index")
    df.index.name = "caller_identity"
    print(df.to_string())

    out_csv = DATA_DIR / "policy_matrix.csv"
    df.reset_index().to_csv(out_csv, index=False)
    print(f"\n✅ Saved: {out_csv}")

    dbg = pd.DataFrame(debug_rows)
    dbg_out = DATA_DIR / "policy_matrix_debug_headers.csv"
    dbg.to_csv(dbg_out, index=False)
    print(f"✅ Saved: {dbg_out}")


if __name__ == "__main__":
    main()
