# ZeroTrust-Experiment (mTLS + Micro-Segmentation + Worm Propagation Testbed)

A beginner-friendly, reproducible security testbed that demonstrates:

1) Legacy (Flat Trust) propagation: worm-like infection can spread across all reachable services.  
2) Zero Trust (mTLS + Authorization / Micro-segmentation): even valid identities are restricted by policy, bounding lateral movement.  
3) Performance trade-offs: separates cold (handshake-heavy) vs warm (keep-alive) behavior and measures p95/p99 + concurrency.

This repo produces CSV artifacts + figures suitable for inclusion in a technical report/paper.

---

## Table of Contents

- What this repo contains  
- Architecture and ports  
- Prerequisites  
- Quick Start (recommended)  
- Step-by-step (new users)  
- Run the experiments  
- Generate figures  
- Multi-run confidence intervals (optional but recommended)  
- Reproducibility artifacts  
- Expected outputs  
- Troubleshooting  
- Security note (do NOT commit keys)  

---

## What this repo contains

Folders
- app/ – Flask microservice (endpoints: /hop, /infect, /metrics, /reset, /health)
- nginx/ – NGINX gateways (Legacy HTTP / HTTP proxy / TLS-only / mTLS+policy)
- scripts/ – experiment scripts that generate CSVs and figures
- certs/ – generated certificates (CA/server/client + rogue client)
- data/ – output CSV/PNG artifacts (often gitignored)

Key concepts
- Identity: provided by a client certificate (mTLS).
- Authorization / micro-segmentation: allow/deny policy matrix restricting which valid identities may call which services.
- Worm propagation: infection spreads across services using scanning strategies (hitlist + pseudorandom-random).
- Cold vs warm:
  - Cold = new connections (handshake-heavy)
  - Warm = keep-alive session reuse (steady-state)

---

## Architecture and ports

Services (4 microservices)
- service-a management: http://localhost:7001
- service-b management: http://localhost:7002
- service-c management: http://localhost:7003
- service-d management: http://localhost:7004

Management ports are used only to reset state and read metrics.

Gateways
- Legacy (flat trust): http://localhost:5000
- HTTP proxy baseline: http://localhost:6200
- TLS-only (server TLS only): https://localhost:6100
- mTLS + authorization (micro-segmentation): https://localhost:6000

Default segmentation policy
Two segments:
- Segment 1: {a, b} can talk to {a, b}
- Segment 2: {c, d} can talk to {c, d}
Cross-segment calls are denied (403), even with valid certificates.

---

## Prerequisites

Required software
- Docker Desktop (Mac/Windows) OR Docker Engine (Linux)
- Python 3.9+
- OpenSSL

Verify installs
Run:

```
docker --version  
docker compose version  
python --version  
openssl version
``` 

If docker compose doesn’t work, install Docker Desktop or update Docker Engine.  
If Python is older than 3.9, install Python 3.11+.

---

## Quick Start (recommended)

1) Clone + enter repo:

```
git clone git@github.com:kuntaharish/ZeroTrust-Experiment.git  
cd ZeroTrust-Experiment
```  

2) Create and activate Python venv:

```
python -m venv venv  
source venv/bin/activate  
pip install -U pip  
pip install requests pandas numpy matplotlib 
``` 

Windows PowerShell:

```
python -m venv venv  
.\venv\Scripts\Activate.ps1  
pip install -U pip  
pip install requests pandas numpy matplotlib  
```

3) Generate certs:

```
bash scripts/gen_certs.sh  
```

4) Start the lab:

```
docker compose up --build  
```

5) In a new terminal, activate venv and run experiments:

```
source venv/bin/activate  

python scripts/policy_matrix_test.py  
python scripts/worm_propagation.py  
python scripts/latency_baselines.py  
python scripts/load_benchmark.py  
```

6) Generate figures:

```
python scripts/generate_revision2_figures.py  
```

All CSVs and figures are written under data/.

---

## Step-by-step (new users)

Step 1 — Clone the repo

```
git clone git@github.com:kuntaharish/ZeroTrust-Experiment.git  
cd ZeroTrust-Experiment  
```

Step 2 — Create a Python virtual environment

Mac/Linux:

```
python -m venv venv  
source venv/bin/activate  
pip install -U pip  
pip install requests pandas numpy matplotlib  
```

Windows (PowerShell):

```
python -m venv venv  
.\venv\Scripts\Activate.ps1  
pip install -U pip  
pip install requests pandas numpy matplotlib  
```

Step 3 — Generate certificates (trusted + rogue)

This creates:
- Trusted CA + server cert
- Client certs for service-a..service-d
- Rogue CA + rogue client cert (attacker)

```
bash scripts/gen_certs.sh  
```

Optional (advanced): generate ECDSA certs instead of RSA:

```
KEY_TYPE=ecdsa bash scripts/gen_certs.sh  
```

Confirm certs exist:

ls certs/  

You should see:
- ca.crt, ca.key
- server.crt, server.key
- service-a.crt/.key ... service-d.crt/.key
- rogue_client.crt/.key, rogue_ca.crt/.key
- cert_metadata.json

Step 4 — Start Docker services

```
docker compose up --build  
```

Leave this terminal running.

Step 5 — Quick health checks (optional)

```
curl -s http://localhost:5000/a/health  
curl -sk https://localhost:6100/a/health  
```

If you see JSON responses, the lab is healthy.

---

## Run the experiments

Always run scripts from the repo root with the venv activated.

```
source venv/bin/activate  
```

A) Verify micro-segmentation policy (mTLS + authorization)

```
python scripts/policy_matrix_test.py  
```

Output:
- data/policy_matrix.csv

Expected:
- service-a and service-b → ALLOW to a,b, DENY to c,d
- service-c and service-d → ALLOW to c,d, DENY to a,b

This proves: valid identities are restricted (authorization), not just authenticated.

B) Worm propagation simulation (legacy vs zero trust)

```
python scripts/worm_propagation.py  
```

Outputs:
- data/worm_trials_summary.csv
- data/worm_infection_curves.csv

Expected (with 4 nodes / 2 segments):
- Legacy → 100% infection
- Zero Trust (mTLS+policy) → 50% infection (bounded to patient-zero segment)

C) Latency baselines (proxy vs TLS-only vs mTLS)

```
python scripts/latency_baselines.py  
```

Output:
- data/latency_baselines.csv

What it measures:
- HTTP proxy baseline (NGINX proxy cost)
- TLS-only (encryption cost)
- mTLS (client-auth + policy cost)
- split into cold vs warm

Expected:
- Cold: higher latency due to handshake
- Warm: low steady-state overhead due to keep-alive reuse

D) Concurrency/load benchmark (throughput + p99 tails)

```
python scripts/load_benchmark.py  
```

Output:
- data/load_benchmark.csv

Measures at concurrency levels (1, 10, 50, 100):
- throughput (req/s)
- mean latency
- p95 latency
- p99 latency

---

## Generate figures

If your repo contains scripts/generate_revision2_figures.py:

```
python scripts/generate_revision2_figures.py
```  

Outputs in:
- data/figures_v2/

Typical figures:
- Policy matrix visualization
- Infection curves (legacy vs ZT)
- Latency decomposition (cold vs warm)
- Throughput and p99 vs concurrency

---

## Multi-run confidence intervals (optional but recommended)

If your repo contains scripts/repeat_and_aggregate.py + CI figure script:

1) Run multiple benchmark repetitions:

```
RUNS=5 python scripts/repeat_and_aggregate.py  
```

2) Generate CI-aware plots:

```
python scripts/generate_revision3_figures.py 
``` 

Outputs:
- data/aggregate_latency_baselines_ci.csv
- data/aggregate_load_benchmark_ci.csv
- data/figures_v3_ci/

This is recommended for publication-quality reporting (mean ± 95% CI).

---

## Reproducibility artifacts

Generate a system and toolchain report:

```
python scripts/system_info.py  
```

Outputs:
- data/system_info.json
- data/system_info.md

These files capture:
- OS / CPU / RAM
- Docker version
- OpenSSL version
- certificate key type metadata

---

## Expected outputs

After running the core experiments, you should see:
- data/policy_matrix.csv
- data/worm_trials_summary.csv
- data/worm_infection_curves.csv
- data/latency_baselines.csv
- data/load_benchmark.csv
- figures under data/figures_v2/ (or data/figures_v3_ci/)

---

## Troubleshooting

Ports already in use
If Docker fails to start due to ports, stop the conflicting process or change ports in docker-compose.yml:
- 5000, 6000, 6100, 6200, 7001–7004

TLS errors / CA file missing
Make sure certs exist:

```
ls certs/  
```

If not, regenerate:

```
bash scripts/gen_certs.sh  
```

LibreSSL warning from urllib3
You may see:
```
urllib3 v2 only supports OpenSSL 1.1.1+ … LibreSSL …
```

This warning is common on some macOS Python builds and usually does not block experiments.  
If it breaks HTTPS requests, install Python 3.11 via Homebrew (macOS) or run in Linux.

Seeing 403 responses
403 is expected when policy blocks cross-segment access. Confirm policy matrix:

```
python scripts/policy_matrix_test.py  
```

Docker build issues
Try:

```
docker compose down  
docker compose build --no-cache  
docker compose up  
```

---

## Security note (do NOT commit keys)

This repo generates private keys under certs/.  
Do NOT commit or push private keys to GitHub.

Recommended .gitignore entries:
- certs/*.key
- data/

If you accidentally committed keys, remove them immediately and rotate/regenerate.

---

## License


---

## Support / Issues
If something fails, open a GitHub issue with:
- OS + Python version
- docker compose version
- the command you ran
- the full error output
