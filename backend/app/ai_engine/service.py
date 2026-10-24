"""Pont entre la base de données et le module d'anomalies."""
from sqlalchemy import delete, select
from sqlalchemy.orm import selectinload

from app.ai_engine.features import FREQ_WINDOW, MIN_HISTORY, REF_WINDOW, Snapshot, extract_features
from app.models.anomaly import AnomalyResult
from app.models.scan import Host, Scan

HISTORY_LIMIT = REF_WINDOW + FREQ_WINDOW


def snapshot(db, scan_id: int) -> Snapshot:
    hosts = db.scalars(select(Host).where(Host.scan_id == scan_id, Host.state == "up")
                       .options(selectinload(Host.services))).all()
    return {h.ip: {(s.port, s.protocol): (s.name or "") for s in h.services if s.state == "open"}
            for h in hosts}


def history_scans(db, scan: Scan) -> list[Scan]:
    """Scans terminés précédents, comparables : même cible et même profil."""
    rows = db.scalars(select(Scan).where(Scan.status == "done", Scan.id < scan.id,
                                         Scan.target == scan.target, Scan.profile == scan.profile)
                      .order_by(Scan.id.desc()).limit(HISTORY_LIMIT)).all()
    return list(reversed(rows))


def missing_reason(db, scan: Scan) -> str:
    if scan.status != "done":
        return "Le scan n'est pas terminé."
    if scan.profile == "discovery":
        return "Le profil Découverte rapide ne collecte pas les ports : pas d'analyse d'anomalies."
    n = len(history_scans(db, scan))
    if n < MIN_HISTORY:
        return (f"Historique insuffisant : {n} scan(s) précédent(s) comparable(s) (même cible, même profil), "
                f"{MIN_HISTORY} au minimum requis (3 ou plus recommandés).")
    return ("Aucun résultat enregistré pour ce scan (analyse non exécutée ou en erreur : "
            "consultez les journaux du worker).")


def analyze_anomalies(db, scan: Scan) -> int:
    """Calcule et enregistre les résultats d'anomalies. Retourne le nombre d'hôtes analysés."""
    if scan.profile == "discovery":
        return 0
    past = history_scans(db, scan)
    if len(past) < MIN_HISTORY:
        return 0
    from app.ai_engine.model import get_model  # import tardif : scikit-learn n'est chargé que par le worker

    feats = extract_features([snapshot(db, s.id) for s in past], snapshot(db, scan.id))
    if not feats:
        return 0
    ids = {h.ip: h.id for h in db.scalars(select(Host).where(Host.scan_id == scan.id))}
    model = get_model()
    db.execute(delete(AnomalyResult).where(AnomalyResult.scan_id == scan.id))
    for ip, r in model.score(feats).items():
        db.add(AnomalyResult(scan_id=scan.id, host_id=ids[ip], score=r["score"],
                             is_anomaly=r["is_anomaly"], features=r["features"],
                             explanation=r["explanation"], model_version=model.version))
    return len(feats)
