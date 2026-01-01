import os
import random
import string
import time
from pathlib import Path
from typing import Dict, List, Set, Tuple

import pandas as pd
import requests

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
CERT_DIR = REPO_ROOT / "certs"
DATA_DIR = REPO_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

LETTERS = list(string.ascii_lowercase[:12])  # a..l
SERVICES = [f"service-{c}" for c in LETTERS]

# Management ports: 7001..7012
MGMT_PORT_BASE = 7001
MGMT_URLS = {c: f"http://localhost:{MGMT_PORT_BASE + i}" for i, c in enumerate(LETTERS)}

# Gateways
LEGACY_GATEWAY = os.environ.get("LEGACY_GATEWAY", "http://localhost:5000")
ZT_GATEWAY = os.environ.get("ZT_GATEWAY", "https://localhost:6000")
CA_CERT = str(CERT_DIR / "ca.crt")

# Segment policy must match nginx/mtls_allowed_gateway.conf
SEGMENTS = {
    "seg1": set(["a", "b"]),                  # size 2
    "seg2": set(["c", "d", "e", "f"]),         # size 4
    "seg3": set(["g", "h", "i", "j", "k", "l"]) # size 6
}

# Experiment knobs
TRIALS = int(os.environ.get("TRIALS", "30"))
ROUNDS = int(os.environ.get("ROUNDS", "8"))          # enough to saturate within segment
FANOUT = int(os.environ.get("FANOUT", "4"))          # attempts per infected node per round
SLEEP_S = float(os.environ.get("SLEEP_S", "0.0"))    # set to small (0.01) if you want less burst

STRATEGIES = ["hitlist", "pseudorandom_random"]
ARCHS = ["legacy", "zt"]


def caller_cert(letter: str) -> Tuple[str, str]:
    identity = f"service-{letter}"
    return str(CERT_DIR / f"{identity}.crt"), str(CERT_DIR / f"{identity}.key")


def reset_all() -> None:
    for c in LETTERS:
        try:
            requests.post(f"{MGMT_URLS[c]}/reset", timeout=2)
        except Exception:
            pass


def mark_infected(letter: str) -> None:
    try:
        requests.post(f"{MGMT_URLS[letter]}/infect", timeout=2)
    except Exception:
        pass


def is_infected(letter: str) -> bool:
    try:
        r = requests.get(f"{MGMT_URLS[letter]}/metrics", timeout=2)
        j = r.json()
        return bool(j.get("infected", False))
    except Exception:
        return False


def segment_of(letter: str) -> str:
    for seg, members in SEGMENTS.items():
        if letter in members:
            return seg
    return "unknown"


def choose_targets(strategy: str, rng: random.Random, all_letters: List[str], exclude: Set[str], k: int) -> List[str]:
    candidates = [x for x in all_letters if x not in exclude]
    if not candidates:
        return []

    if strategy == "hitlist":
        rng.shuffle(candidates)
        return candidates[:k]

    # pseudorandom_random: deterministic per trial seed, but still "random-looking"
    return [rng.choice(candidates) for _ in range(k)]


def attempt_hop(arch: str, caller: str, target: str, timeout_s: float = 2.5) -> bool:
    """
    Returns True if hop allowed (200), False otherwise.
    """
    if arch == "legacy":
        url = f"{LEGACY_GATEWAY}/{target}/hop"
        try:
            r = requests.post(url, timeout=timeout_s, headers={"X-Workload-Id": f"service-{caller}"})
            return r.status_code == 200
        except Exception:
            return False

    # Zero Trust: real mTLS + policy via nginx
    url = f"{ZT_GATEWAY}/{target}/hop"
    crt, key = caller_cert(caller)
    try:
        r = requests.post(
            url,
            cert=(crt, key),
            verify=CA_CERT,
            timeout=timeout_s,
            headers={"Connection": "close", "User-Agent": "worm-prop/12svc"},
        )
        return r.status_code == 200
    except Exception:
        return False


def run_one_trial(trial_id: int, arch: str, strategy: str) -> Tuple[float, List[Dict]]:
    rng = random.Random(1000 + trial_id * 13 + (0 if arch == "legacy" else 7) + (0 if strategy == "hitlist" else 3))

    reset_all()

    patient_zero = rng.choice(LETTERS)
    mark_infected(patient_zero)

    infected: Set[str] = set([patient_zero])

    curve_rows: List[Dict] = []
    curve_rows.append({
        "trial": trial_id,
        "arch": arch,
        "strategy": strategy,
        "t": 0,
        "infected_count": len(infected),
        "infected_pct": 100.0 * len(infected) / len(LETTERS),
        "patient_zero": patient_zero,
        "patient_zero_segment": segment_of(patient_zero),
        "segment_size": len(SEGMENTS.get(segment_of(patient_zero), [])),
    })

    for t in range(1, ROUNDS + 1):
        newly_infected: Set[str] = set()

        for caller in list(infected):
            targets = choose_targets(strategy, rng, LETTERS, infected.union(newly_infected), FANOUT)
            for target in targets:
                allowed = attempt_hop(arch, caller, target)
                if allowed:
                    newly_infected.add(target)
                    mark_infected(target)

                if SLEEP_S > 0:
                    time.sleep(SLEEP_S)

        infected |= newly_infected

        curve_rows.append({
            "trial": trial_id,
            "arch": arch,
            "strategy": strategy,
            "t": t,
            "infected_count": len(infected),
            "infected_pct": 100.0 * len(infected) / len(LETTERS),
            "patient_zero": patient_zero,
            "patient_zero_segment": segment_of(patient_zero),
            "segment_size": len(SEGMENTS.get(segment_of(patient_zero), [])),
        })

        if len(infected) == len(LETTERS):
            break

    final_pct = 100.0 * len(infected) / len(LETTERS)
    return final_pct, curve_rows


def main() -> None:
    all_curve_rows: List[Dict] = []
    summary_rows: List[Dict] = []

    for arch in ARCHS:
        for strategy in STRATEGIES:
            finals: List[float] = []
            for trial in range(TRIALS):
                final_pct, curve_rows = run_one_trial(trial, arch, strategy)
                finals.append(final_pct)
                all_curve_rows.extend(curve_rows)

            summary_rows.append({
                "arch": arch,
                "strategy": strategy,
                "trials": TRIALS,
                "mean_final_infection_pct": sum(finals) / len(finals),
                "min_final_infection_pct": min(finals),
                "max_final_infection_pct": max(finals),
            })

    curves_df = pd.DataFrame(all_curve_rows)
    curves_path = DATA_DIR / "worm_infection_curves.csv"
    curves_df.to_csv(curves_path, index=False)

    summary_df = pd.DataFrame(summary_rows)
    summary_path = DATA_DIR / "worm_trials_summary.csv"
    summary_df.to_csv(summary_path, index=False)

    print("\n=== WORM PROPAGATION SUMMARY (12 services) ===")
    print(summary_df.to_string(index=False))

    # Optional: show patient-zero → segment size → final infection clusters
    print("\n✅ Saved:", str(summary_path))
    print("✅ Saved:", str(curves_path))

    # Post-run snapshot (management)
    rows = []
    for c in LETTERS:
        try:
            r = requests.get(f"{MGMT_URLS[c]}/metrics", timeout=2)
            j = r.json()
            rows.append({
                "service": f"service-{c}",
                "infected": j.get("infected"),
                "infect_count": j.get("infect_count"),
                "hop_count": j.get("hop_count"),
            })
        except Exception:
            pass

    if rows:
        print("\n=== POST-RUN METRICS SNAPSHOT (management ports) ===")
        print(pd.DataFrame(rows).to_string(index=False))


if __name__ == "__main__":
    main()
