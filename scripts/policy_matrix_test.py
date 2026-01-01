import os
import ssl
from pathlib import Path
from typing import Dict, Tuple

import pandas as pd
import requests
from requests.exceptions import SSLError, ConnectionError, Timeout

# ---- Paths (robust even when run from anywhere) ----
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
CERT_DIR = REPO_ROOT / "certs"
DATA_DIR = REPO_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

# ---- Gateway ----
BASE_URL = os.environ.get("ZT_GATEWAY_URL", "https://localhost:6000")

# ---- Service routing keys used by nginx (/a/, /b/, /c/, /d/) ----
TARGETS = ["a", "b", "c", "d"]

# ---- Client identities ----
CALLERS = ["service-a", "service-b", "service-c", "service-d"]

CA_CERT = CERT_DIR / "ca.crt"


def cert_pair(identity: str) -> Tuple[str, str]:
    crt = CERT_DIR / f"{identity}.crt"
    key = CERT_DIR / f"{identity}.key"
    return str(crt), str(key)


def classify_cell(resp_status: int = None, exc: Exception = None) -> str:
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


def short_reason(e: Exception) -> str:
    msg = str(e).replace("\n", " ").strip()
    return msg if len(msg) <= 100 else msg[:97] + "..."


def main() -> None:
    print("\n=== POLICY MATRIX (mTLS + allowlist) ===")
    try:
        print(f"Python SSL backend: {ssl.OPENSSL_VERSION}")
    except Exception:
        pass

    # Sanity checks
    if not CA_CERT.exists():
        raise FileNotFoundError(f"Missing CA cert: {CA_CERT}")

    missing = []
    for c in CALLERS:
        crt, key = cert_pair(c)
        if not Path(crt).exists():
            missing.append(crt)
        if not Path(key).exists():
            missing.append(key)
    if missing:
        raise FileNotFoundError("Missing client cert/key files:\n" + "\n".join(missing))

    timeout_s = 4

    # Policy table and debug evidence
    table: Dict[str, Dict[str, str]] = {}
    debug_rows = []
    err_rows = []

    for caller in CALLERS:
        # IMPORTANT: new Session per caller to avoid TLS connection reuse with wrong client cert
        with requests.Session() as s:
            s.trust_env = False  # ignore proxy env vars
            table[caller] = {}
            crt, key = cert_pair(caller)

            for tgt in TARGETS:
                url = f"{BASE_URL}/{tgt}/hop"
                try:
                    r = s.post(
                        url,
                        cert=(crt, key),
                        verify=str(CA_CERT),
                        timeout=timeout_s,
                        headers={
                            "Connection": "close",   # force no keep-alive reuse across identities
                            "User-Agent": "policy-matrix-test/1.1",
                        },
                    )
                    cell = classify_cell(resp_status=r.status_code)
                    table[caller][tgt] = cell

                    # Capture debug headers if nginx adds them (helpful evidence)
                    dbg_cn = r.headers.get("X-Debug-Client-CN", "")
                    dbg_seg = r.headers.get("X-Debug-Segment", "")
                    debug_rows.append({
                        "caller_requested": caller,
                        "target": tgt,
                        "status": r.status_code,
                        "x_debug_client_cn": dbg_cn,
                        "x_debug_segment": dbg_seg,
                    })
                    r.close()

                except Exception as e:
                    table[caller][tgt] = classify_cell(exc=e)
                    err_rows.append({
                        "caller": caller,
                        "target": tgt,
                        "url": url,
                        "exception_type": type(e).__name__,
                        "exception": short_reason(e),
                    })

    # Print matrix
    df = pd.DataFrame.from_dict(table, orient="index")
    df.index.name = "caller_identity"
    print(df.to_string())

    out_csv = DATA_DIR / "policy_matrix.csv"
    df.reset_index().to_csv(out_csv, index=False)
    print(f"\n✅ Saved: {out_csv}")

    # Save debug headers (optional evidence)
    dbg_df = pd.DataFrame(debug_rows)
    dbg_path = DATA_DIR / "policy_matrix_debug_headers.csv"
    dbg_df.to_csv(dbg_path, index=False)
    print(f"✅ Saved: {dbg_path}")

    # Save errors if any
    if err_rows:
        err_df = pd.DataFrame(err_rows)
        err_path = DATA_DIR / "policy_matrix_errors.csv"
        err_df.to_csv(err_path, index=False)
        print(f"✅ Saved: {err_path}")
        print("\nNote: If you see SSLError everywhere, verify nginx is up and cert paths are correct.\n")


if __name__ == "__main__":
    main()
