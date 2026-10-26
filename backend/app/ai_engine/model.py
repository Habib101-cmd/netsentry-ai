"""Isolation Forest entraîné sur des données synthétiques (aucun fichier pickle : réentraînement déterministe)."""

from dataclasses import dataclass
from functools import lru_cache

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from app.ai_engine.features import FEATURES, REF_WINDOW, extract_features
from app.ai_engine.synthetic import Simulation, simulate

SEED = 42
N_ESTIMATORS = 200
TARGET_FPR = 0.02  # taux de faux positifs visé sur les données normales d'entraînement
STD_FLOOR = 0.1
LABELS = {
    "open_ports": "Nombre de ports ouverts",
    "identified_services": "Nombre de services identifiés",
    "new_services": "Nouveaux services par rapport au profil de référence",
    "hosts_delta": "Variation du nombre d'hôtes actifs",
    "change_freq": "Fréquence des changements récents",
    "unusual_ratio": "Proportion de services inhabituels pour cet équipement",
}
RATIO_FEATURES = {"hosts_delta", "change_freq", "unusual_ratio"}


def feature_matrix(sim: Simulation, start: int = REF_WINDOW):
    rows, keys = [], []
    for t in range(start, len(sim.snapshots)):
        feats = extract_features(sim.snapshots[:t], sim.snapshots[t])
        for ip, f in feats.items():
            rows.append([f[k] for k in FEATURES])
            keys.append((t, ip))
    return np.array(rows, dtype=float), keys


def _fmt(feature: str, value: float) -> str:
    return f"{value * 100:.0f} %" if feature in RATIO_FEATURES else f"{round(value, 1):g}"


@dataclass
class TrainedModel:
    forest: IsolationForest
    threshold: float
    mean: np.ndarray
    std: np.ndarray
    version: str

    def raw_scores(self, X: np.ndarray) -> np.ndarray:
        return -self.forest.score_samples(X)  # entre 0 et 1 : plus c'est haut, plus c'est atypique

    def score(self, feats: dict[str, dict[str, float]]) -> dict[str, dict]:
        ips = list(feats)
        X = np.array([[feats[ip][k] for k in FEATURES] for ip in ips], dtype=float)
        raw = self.raw_scores(X)
        results = {}
        for i, ip in enumerate(ips):
            z = (X[i] - self.mean) / self.std
            pos = np.clip(z, 0, None)
            share = pos / pos.sum() if pos.sum() > 0 else pos
            details = sorted(
                (
                    {
                        "feature": f,
                        "label": LABELS[f],
                        "value": float(X[i][j]),
                        "baseline_mean": round(float(self.mean[j]), 3),
                        "z": round(float(z[j]), 2),
                        "contribution": round(float(share[j]), 3),
                    }
                    for j, f in enumerate(FEATURES)
                ),
                key=lambda d: -d["contribution"],
            )
            flagged = bool(raw[i] > self.threshold)
            if flagged:
                parts = [
                    f"{d['label']} : {_fmt(d['feature'], d['value'])} "
                    f"(habituellement ≈ {_fmt(d['feature'], d['baseline_mean'])})"
                    for d in details
                    if d["contribution"] >= 0.2
                ][:3]
                summary = "Comportement atypique à vérifier. " + " ; ".join(parts) + "."
            else:
                summary = "Dans la plage de comportement observée lors de l'apprentissage."
            results[ip] = {
                "score": round(float(raw[i]) * 100, 1),
                "is_anomaly": flagged,
                "features": feats[ip],
                "explanation": {"summary": summary, "details": details, "threshold": round(self.threshold * 100, 1)},
            }
        return results


def fit(
    X: np.ndarray, seed: int = SEED, n_estimators: int = N_ESTIMATORS, target_fpr: float = TARGET_FPR
) -> TrainedModel:
    forest = IsolationForest(n_estimators=n_estimators, random_state=seed).fit(X)
    threshold = float(np.quantile(-forest.score_samples(X), 1 - target_fpr))
    return TrainedModel(
        forest,
        threshold,
        X.mean(axis=0),
        np.maximum(X.std(axis=0), STD_FLOOR),
        f"iforest-1-skl{sklearn.__version__}-seed{seed}",
    )


@lru_cache(maxsize=1)
def get_model() -> TrainedModel:
    X, _ = feature_matrix(simulate(SEED, inject=False))
    return fit(X)
