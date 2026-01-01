import os
import time
import random
import requests
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
CERTS = os.path.join(REPO_ROOT, "certs")
DATA_DIR = os.path.join(REPO_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)

LEGACY_BASE = "http://localhost:5000"
ZT_BASE = "https://localhost:6000"
CA = os.path.join(CERTS, "ca.crt")

MGMT_PORTS = {
    "a": "http://localhost:7001",
    "b": "http://localhost:7002",
    "c": "http://localhost:7003",
    "d": "http://localhost:7004",
}

NODES = ["a", "b", "c", "d"]

# Map node -> identity cert name (same idea as real workloads)
IDENTITY_FOR_NODE = {
    "a": "service-a",
    "b": "service-b",
    "c": "service-c",
    "d": "service-d",
}

def cert(identity: str):
    return (os.path.join(CERTS, f"{identity}.crt"), os.path.join(CERTS, f"{identity}.key"))

def reset_all():
    for n, base in MGMT_PORTS.items():
        requests.post(f"{base}/reset", timeout=2)

def metrics(node: str):
    base = MGMT_PORTS[node]
    return requests.get(f"{base}/metrics", timeout=2).json()

def infect_request(arch: str, caller_node: str, target_node: str):
    """
    Returns (success_bool, status_label)
    """
    if arch == "legacy":
        url = f"{LEGACY_BASE}/{target_node}/infect"
        try:
            r = requests.post(url, timeout=2)
            return (r.status_code == 200), f"HTTP({r.status_code})"
        except Exception:
            return False, "ERROR"
    else:
        # ZT: caller uses its own workload identity
        caller_ident = IDENTITY_FOR_NODE[caller_node]
        url = f"{ZT_BASE}/{target_node}/infect"
        try:
            r = requests.post(url, cert=cert(caller_ident), verify=CA, timeout=2)
            if r.status_code == 200:
                return True, "ALLOW(200)"
            if r.status_code == 403:
                return False, "BLOCKED_POLICY(403)"
            return False, f"HTTP({r.status_code})"
        except requests.exceptions.SSLError:
            return False, "BLOCKED_TLS(SSL)"
        except requests.exceptions.ConnectionError:
            return False, "BLOCKED_TLS(CONN)"
        except Exception:
            return False, "ERROR"

def scan_order(strategy: str, rng: random.Random):
    """
    hitlist: fixed order
    pseudorandom_random: random permutation (mirrors poster language)
    """
    if strategy == "hitlist":
        return list(NODES)
    if strategy == "pseudorandom_random":
        order = list(NODES)
        rng.shuffle(order)
        return order
    raise ValueError("Unknown strategy")

def run_trial(arch: str, strategy: str, seed: int, patient_zero: str = "a", max_rounds: int = 25):
    rng = random.Random(seed)

    reset_all()

    # Infect patient zero directly (as initial compromise)
    # For legacy, just call /infect; for ZT, use patient_zero identity to infect itself (allowed)
    ok, _ = infect_request(arch, patient_zero, patient_zero)
    if not ok:
        # If this fails, the trial is broken.
        raise RuntimeError("Failed to infect patient zero")

    infected = {patient_zero}
    infection_order = {patient_zero: 1}
    parent_of = {patient_zero: None}

    timeline = []
    timeline.append({"t": 0, "infected_count": 1})

    # Multi-source propagation: each round, every infected node tries targets in scan order
    t = 0
    for _round in range(max_rounds):
        changed = False
        t += 1

        for parent in list(infected):
            order = scan_order(strategy, rng)
            for target in order:
                if target in infected:
                    continue
                ok, label = infect_request(arch, parent, target)
                if ok:
                    infected.add(target)
                    infection_order[target] = len(infected)
                    parent_of[target] = parent
                    changed = True
                # emulate “miss delay” concept from poster: if blocked or error, small processing delay
                if label.startswith("BLOCKED") or label.startswith("ERROR"):
                    time.sleep(0.001)

        timeline.append({"t": t, "infected_count": len(infected)})

        if not changed:
            break

    return infected, infection_order, parent_of, timeline

def main():
    TRIALS = 30
    STRATEGIES = ["hitlist", "pseudorandom_random"]
    rows = []
    curve_rows = []

    for arch in ["legacy", "zt"]:
        for strat in STRATEGIES:
            for trial in range(TRIALS):
                seed = 1000 + trial
                infected, order, parent, timeline = run_trial(arch, strat, seed)

                rows.append({
                    "arch": arch,
                    "strategy": strat,
                    "trial": trial,
                    "final_infected": len(infected),
                    "final_infected_pct": round(100.0 * len(infected) / len(NODES), 1),
                })

                for point in timeline:
                    curve_rows.append({
                        "arch": arch,
                        "strategy": strat,
                        "trial": trial,
                        "t": point["t"],
                        "infected_count": point["infected_count"],
                        "infected_pct": round(100.0 * point["infected_count"] / len(NODES), 1),
                    })

    df = pd.DataFrame(rows)
    curves = pd.DataFrame(curve_rows)

    out1 = os.path.join(DATA_DIR, "worm_trials_summary.csv")
    out2 = os.path.join(DATA_DIR, "worm_infection_curves.csv")
    df.to_csv(out1, index=False)
    curves.to_csv(out2, index=False)

    print("\n=== WORM PROPAGATION SUMMARY ===")
    print(df.groupby(["arch", "strategy"])["final_infected_pct"].describe().round(2))
    print(f"\n✅ Saved: {out1}")
    print(f"✅ Saved: {out2}")

    # Quick sanity: verify ZT blocked attempts do not reach app by checking hop_count/infect_count
    print("\n=== POST-RUN METRICS SNAPSHOT (management ports) ===")
    snap = []
    for n in NODES:
        m = metrics(n)
        snap.append(m)
    print(pd.DataFrame(snap).to_string(index=False))

if __name__ == "__main__":
    main()
