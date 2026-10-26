"""Mesure la latence de l'API pendant un scan (ENF-02 : p95 < 500 ms).

Usage : python tests/perf/measure_latency.py --user admin --launch deep --target 172.30.0.0/24
Le mot de passe est demandé (ou variable d'environnement NETSENTRY_PASSWORD). Bibliothèque standard uniquement.
"""

import argparse
import getpass
import json
import os
import statistics
import sys
import time
import urllib.request

ENDPOINTS = ["/scans", "/hosts", "/findings?limit=100", "/findings/summary", "/scopes"]


def call(base, path, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, headers=headers, method="POST" if body is not None else "GET")
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=30) as response:  # noqa: S310 - URL fournie par l'utilisateur
        payload = json.loads(response.read())
    return (time.perf_counter() - start) * 1000, payload


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--user", required=True)
    ap.add_argument("--launch", choices=["discovery", "standard", "deep"], help="lance un scan avant de mesurer")
    ap.add_argument("--target", default="172.30.0.0/24")
    ap.add_argument("--rounds", type=int, default=60, help="requêtes par route")
    args = ap.parse_args()

    password = os.environ.get("NETSENTRY_PASSWORD") or getpass.getpass("Mot de passe : ")
    _, tokens = call(args.base, "/auth/login", body={"username": args.user, "password": password})
    token = tokens["access_token"]

    scan_id = None
    if args.launch:
        _, scan = call(args.base, "/scans", token, {"target": args.target, "profile": args.launch})
        scan_id = scan["id"]
        print(f"Scan #{scan_id} ({args.launch}) lancé ; attente du démarrage...")
        time.sleep(3)

    def scan_status():
        return call(args.base, f"/scans/{scan_id}", token)[1]["status"] if scan_id else "(aucun scan lancé)"

    before = scan_status()
    timings = {path: [call(args.base, path, token)[0] for _ in range(args.rounds)] for path in ENDPOINTS}
    after = scan_status()

    everything = [t for series in timings.values() for t in series]
    p95 = statistics.quantiles(everything, n=20)[18]
    print(f"\nStatut du scan avant / après la mesure : {before} / {after}")
    print(f"{'Route':<24}{'médiane':>10}{'p95':>10}{'max':>10}   (ms)")
    for path, series in timings.items():
        print(
            f"{path:<24}{statistics.median(series):>10.1f}{statistics.quantiles(series, n=20)[18]:>10.1f}{max(series):>10.1f}"
        )
    print(f"\nGlobal : {len(everything)} requêtes, p95 = {p95:.1f} ms")
    if scan_id and (before != "running" or after != "running"):
        print(
            "ATTENTION : le scan n'était pas en cours pendant toute la mesure (résultat non probant). "
            "Vérifiez que le worker tourne (docker compose logs worker) et utilisez le profil 'deep'."
        )
    ok = p95 < 500
    print("ENF-02 :", "OK (p95 < 500 ms)" if ok else "ÉCHEC (p95 >= 500 ms)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
