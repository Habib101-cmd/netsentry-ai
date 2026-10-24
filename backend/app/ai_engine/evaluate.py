"""Évaluation du module d'anomalies : python -m app.ai_engine.evaluate [--report FICHIER] [--export DOSSIER]"""
import argparse
import csv
from pathlib import Path

import numpy as np

from app.ai_engine.features import FEATURES, extract_features
from app.ai_engine.model import SEED, TARGET_FPR, feature_matrix, fit
from app.ai_engine.synthetic import ANOMALY_TYPES, Simulation, simulate

EVAL_SEED = 7
ROBUST_SEEDS = list(range(100, 110))
WARMUP = 21


def observations(sim: Simulation, start: int = WARMUP) -> list[dict]:
    rows = []
    for t in range(start, len(sim.snapshots)):
        hist, cur = sim.snapshots[:t], sim.snapshots[t]
        prev = hist[-1]
        for ip, f in extract_features(hist, cur).items():
            # Règle de référence = comparaison de scans : nouvel hôte ou nouveau port ouvert vs scan précédent
            rule = ip not in prev or any(k not in prev[ip] for k in cur[ip])
            rows.append({"t": t, "ip": ip, "features": f, "label": sim.labels[t].get(ip), "rule": rule})
    return rows


def metrics(truth: np.ndarray, pred: np.ndarray) -> dict:
    tp = int((truth & pred).sum())
    fp = int((~truth & pred).sum())
    fn = int((truth & ~pred).sum())
    tn = int((~truth & ~pred).sum())
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else 0.0,
            "recall": tp / (tp + fn) if tp + fn else 0.0,
            "fpr": fp / (fp + tn) if fp + tn else 0.0}


def evaluate(eval_seed: int = EVAL_SEED, model=None) -> dict:
    if model is None:
        X, _ = feature_matrix(simulate(SEED, inject=False))
        model = fit(X)
    rows = observations(simulate(eval_seed, inject=True))
    X = np.array([[r["features"][k] for k in FEATURES] for r in rows])
    ml = model.raw_scores(X) > model.threshold
    rule = np.array([r["rule"] for r in rows])
    truth = np.array([r["label"] is not None for r in rows])
    for r, flag, raw in zip(rows, ml, model.raw_scores(X)):
        r["ml"], r["ml_score"] = bool(flag), float(raw)
    per_type = {}
    for kind in ANOMALY_TYPES:
        sel = np.array([r["label"] == kind for r in rows])
        per_type[kind] = {"n": int(sel.sum()), "rules": int((sel & rule).sum()), "ml": int((sel & ml).sum()),
                          "rules_and_ml": int((sel & rule & ml).sum())}
    return {"n_obs": len(rows), "n_anomalies": int(truth.sum()), "rows": rows, "per_type": per_type,
            "systems": {"Règles seules (comparaison de scans)": metrics(truth, rule),
                        "ML seul (Isolation Forest)": metrics(truth, ml),
                        "Règles ET ML (changement confirmé comme atypique)": metrics(truth, rule & ml),
                        "Règles OU ML (union)": metrics(truth, rule | ml)}}


def robustness(model) -> dict:
    acc: dict[str, list] = {}
    for seed in ROBUST_SEEDS:
        for name, m in evaluate(seed, model)["systems"].items():
            acc.setdefault(name, []).append(m)
    return {name: {k: float(np.mean([m[k] for m in ms])) for k in ("precision", "recall", "fpr", "fp", "fn")}
            for name, ms in acc.items()}


def render_report(res: dict, robust: dict, version: str) -> str:
    def pct(x):
        return f"{x * 100:.1f} %"
    L = ["# Évaluation du module d'anomalies (Machine Learning)", "",
         "Document généré par `python -m app.ai_engine.evaluate` : les chiffres ci-dessous sont reproductibles.", "",
         "## Principe", "",
         "- Modèle : Isolation Forest (scikit-learn), 200 arbres, graine fixe. "
         f"Version : `{version}`.",
         "- Données **synthétiques** (un laboratoire réel de 10 à 20 machines ne fournit pas assez d'historique) : "
         "15 hôtes, 8 semaines à raison d'un scan par jour (56 scans), avec variations bénignes "
         "(hôte injoignable 2 % du temps, port non vu 1 % du temps, service ajouté ou retiré durablement dans "
         "2 % des couples hôte/scan : sans ces évolutions bénignes, les caractéristiques « nouveaux services » et "
         "« services inhabituels » seraient constantes à 0 et l'Isolation Forest ne pourrait pas s'en servir).",
         f"- **Entraînement** : simulation graine {SEED}, sans aucune anomalie. "
         f"**Évaluation** : simulation distincte (graine {EVAL_SEED}), 21 scans d'historique puis injection "
         "d'anomalies étiquetées. Aucune observation n'est partagée entre les deux jeux.",
         f"- Seuil : score au-delà du quantile {100 - TARGET_FPR * 100:.0f} % des scores d'entraînement "
         f"(taux de faux positifs visé : {TARGET_FPR * 100:.0f} %).",
         "- Anomalies injectées (persistantes, étiquetées à leur première observation) : nouvel hôte, "
         "nouveau port, service inhabituel, hausse brutale du nombre de ports.", "",
         "## Caractéristiques (par hôte et par scan)", "",
         "| Caractéristique | Définition |", "|---|---|",
         "| open_ports | nombre de ports ouverts |",
         "| identified_services | nombre de services ouverts dont le nom est identifié |",
         "| new_services | ports ouverts absents du profil de référence (union des 3 scans précédents) |",
         "| hosts_delta | variation relative du nombre d'hôtes actifs par rapport au scan précédent |",
         "| change_freq | part des 5 dernières transitions où l'ensemble des ports de l'hôte a changé |",
         "| unusual_ratio | part des services ouverts dont le nom n'a jamais été vu sur cet hôte (référence) |", "",
         f"## Résultats sur le jeu d'évaluation ({res['n_obs']} observations, {res['n_anomalies']} anomalies)", "",
         "| Système | Précision | Rappel | Taux de faux positifs | Faux positifs | Faux négatifs |",
         "|---|---|---|---|---|---|"]
    for name, m in res["systems"].items():
        L.append(f"| {name} | {pct(m['precision'])} | {pct(m['recall'])} | {pct(m['fpr'])} | {m['fp']} | {m['fn']} |")
    L += ["", "### Détection par type d'anomalie (anomalies détectées / injectées)", "",
          "| Type | Injectées | Règles | ML | Règles ET ML |", "|---|---|---|---|---|"]
    for kind, d in res["per_type"].items():
        L.append(f"| {kind} | {d['n']} | {d['rules']} | {d['ml']} | {d['rules_and_ml']} |")
    L += ["", f"### Robustesse : moyenne sur {len(ROBUST_SEEDS)} simulations d'évaluation indépendantes", "",
          "| Système | Précision | Rappel | Taux de faux positifs | Faux positifs (moy.) | Faux négatifs (moy.) |",
          "|---|---|---|---|---|---|"]
    for name, m in robust.items():
        L.append(f"| {name} | {pct(m['precision'])} | {pct(m['recall'])} | {pct(m['fpr'])} | "
                 f"{m['fp']:.1f} | {m['fn']:.1f} |")
    L += ["", "## Lecture honnête des résultats", "",
          "- Les anomalies sont injectées par nous : les règles de comparaison les voient par construction "
          "(un nouvel hôte ou un nouveau port est toujours un changement). Un rappel élevé des règles n'est donc "
          "pas une surprise.",
          "- L'apport mesurable du ML est de **filtrer** les changements anodins (port qui réapparaît après une "
          "indisponibilité, hôte de retour) : voir la ligne « Règles ET ML » et la baisse des faux positifs.",
          "- Les anomalies sont rares (de l'ordre de 3 % des observations) : la précision est mécaniquement "
          "faible pour tous les systèmes, et un seul jeu d'évaluation en contient peu (quelques dizaines). La "
          "moyenne sur plusieurs simulations est plus fiable.",
          "- Contrepartie : le ML peut manquer les anomalies discrètes (ex. un seul nouveau port d'un service déjà "
          "connu sur l'hôte), car un tel changement ressemble à une évolution bénigne. C'est visible dans le tableau "
          "par type.",
          "- Le ML ne sait pas qu'un service précis (telnet, RDP...) est risqué : il ne voit que sa nouveauté. "
          "Les règles de risque (étape 7) restent indispensables.",
          "", "## Limites", "",
          "- Données synthétiques : un vrai réseau a d'autres régularités. Le modèle est adapté à un laboratoire "
          "et doit être réentraîné sur un historique réel avant tout usage opérationnel.",
          "- Le modèle ne voit que des comptages de ports et de services, pas le contenu du trafic.",
          "- Une anomalie est un **comportement atypique à vérifier** : ce n'est ni une vulnérabilité, ni une "
          "attaque confirmée.",
          "- Au moins 2 scans précédents (même cible, même profil, hors découverte rapide) sont nécessaires.", ""]
    return "\n".join(L)


def export_csv(res: dict, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    X, keys = feature_matrix(simulate(SEED, inject=False))
    with open(directory / "train_normal.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["scan_index", "ip", *FEATURES])
        for (t, ip), row in zip(keys, X):
            w.writerow([t, ip, *row])
    with open(directory / "eval_labeled.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["scan_index", "ip", *FEATURES, "label", "rule_flag", "ml_flag", "ml_score"])
        for r in res["rows"]:
            w.writerow([r["t"], r["ip"], *[r["features"][k] for k in FEATURES], r["label"] or "",
                        int(r["rule"]), int(r["ml"]), round(r["ml_score"], 4)])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", help="écrit le rapport Markdown dans ce fichier")
    ap.add_argument("--export", help="écrit les jeux de données CSV dans ce dossier")
    args = ap.parse_args()
    X, _ = feature_matrix(simulate(SEED, inject=False))
    model = fit(X)
    res = evaluate(EVAL_SEED, model)
    text = render_report(res, robustness(model), model.version)
    if args.report:
        Path(args.report).write_text(text, encoding="utf-8")
        print(f"Rapport écrit : {args.report}")
    else:
        print(text)
    if args.export:
        export_csv(res, Path(args.export))
        print(f"CSV écrits dans : {args.export}")


if __name__ == "__main__":
    main()
