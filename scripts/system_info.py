import json
import os
import platform
import subprocess
import sys
import ssl
from datetime import datetime
from typing import Optional, Dict, Any

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_DIR = os.path.join(REPO_ROOT, "data")
CERT_DIR = os.path.join(REPO_ROOT, "certs")
os.makedirs(DATA_DIR, exist_ok=True)


def sh(cmd: str) -> Optional[str]:
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True).strip()
        return out
    except Exception:
        return None


def read_cert_pubkey_alg(cert_path: str) -> Optional[str]:
    if not os.path.exists(cert_path):
        return None
    # Parse via openssl text output
    out = sh(f'openssl x509 -in "{cert_path}" -noout -text')
    if not out:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.lower().startswith("public key algorithm:"):
            return line.split(":", 1)[1].strip()
    return None


def sysctl_mem_bytes() -> Optional[int]:
    if platform.system() != "Darwin":
        return None
    out = sh("sysctl -n hw.memsize")
    if out and out.isdigit():
        return int(out)
    return None


def main() -> None:
    info: Dict[str, Any] = {}
    info["generated_utc"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    info["python_executable"] = sys.executable
    info["python_version"] = sys.version.replace("\n", " ")
    info["platform"] = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    }
    info["cpu_count"] = os.cpu_count()
    info["memory_bytes"] = sysctl_mem_bytes()
    info["python_ssl"] = {
        "OPENSSL_VERSION": getattr(ssl, "OPENSSL_VERSION", None),
        "OPENSSL_VERSION_INFO": getattr(ssl, "OPENSSL_VERSION_INFO", None),
    }

    info["tools"] = {
        "docker": sh("docker --version"),
        "docker_compose": sh("docker compose version"),
        "openssl": sh("openssl version"),
        "nginx_image": sh("docker run --rm nginx:1.27-alpine nginx -v 2>&1"),
    }

    # Cert metadata
    meta_path = os.path.join(CERT_DIR, "cert_metadata.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r") as f:
                info["cert_metadata"] = json.load(f)
        except Exception:
            info["cert_metadata"] = "present_but_unreadable"
    else:
        info["cert_metadata"] = None

    info["certs"] = {
        "server_public_key_algorithm": read_cert_pubkey_alg(os.path.join(CERT_DIR, "server.crt")),
        "client_a_public_key_algorithm": read_cert_pubkey_alg(os.path.join(CERT_DIR, "service-a.crt")),
        "ca_public_key_algorithm": read_cert_pubkey_alg(os.path.join(CERT_DIR, "ca.crt")),
    }

    # Save JSON
    out_json = os.path.join(DATA_DIR, "system_info.json")
    with open(out_json, "w") as f:
        json.dump(info, f, indent=2)

    # Save a paper-friendly markdown summary
    out_md = os.path.join(DATA_DIR, "system_info.md")
    with open(out_md, "w") as f:
        f.write("# Experimental Setup (Auto-generated)\n\n")
        f.write(f"- Generated (UTC): {info['generated_utc']}\n")
        f.write(f"- OS: {info['platform']['system']} {info['platform']['release']} ({info['platform']['machine']})\n")
        f.write(f"- CPU cores: {info['cpu_count']}\n")
        if info["memory_bytes"]:
            f.write(f"- RAM: {round(info['memory_bytes'] / (1024**3), 2)} GB\n")
        f.write(f"- Python: {info['python_version']}\n")
        f.write(f"- Python SSL: {info['python_ssl'].get('OPENSSL_VERSION')}\n\n")
        f.write("## Toolchain\n")
        for k, v in info["tools"].items():
            f.write(f"- {k}: {v}\n")
        f.write("\n## Certificates\n")
        f.write(f"- cert_metadata.json: {info.get('cert_metadata') is not None}\n")
        f.write(f"- Server public key algorithm: {info['certs'].get('server_public_key_algorithm')}\n")
        f.write(f"- Client-A public key algorithm: {info['certs'].get('client_a_public_key_algorithm')}\n")
        f.write(f"- CA public key algorithm: {info['certs'].get('ca_public_key_algorithm')}\n")

    print(f"✅ Saved: {out_json}")
    print(f"✅ Saved: {out_md}")


if __name__ == "__main__":
    main()
