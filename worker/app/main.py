import logging
import subprocess
import tempfile
import time

from sqlalchemy import select, update

from app.database import SessionLocal
from app.models.scan import Host, Scan, Scope, Service, Vulnerability
from app.services.audit import audit
from app.services.nmap_cmd import build_cmd
from app.services.nmap_parser import MAX_XML_BYTES, parse_nmap_xml
from app.services.target_validation import validate_target
from app.timeutils import utcnow

log = logging.getLogger("worker")
POLL_SECONDS = 3
SCAN_TIMEOUT = 1800  # durée max d'un scan (SEC-09) ; 1 scan à la fois par worker


def claim_job(db):
    scan = db.scalar(select(Scan).where(Scan.status == "pending").order_by(Scan.id)
                     .limit(1).with_for_update(skip_locked=True))
    if scan:
        scan.status = "running"
        scan.started_at = utcnow()
        db.commit()
    return scan


def run_nmap(db, scan, cmd):
    """Exécute Nmap SANS shell (liste d'arguments). Retourne ('ok', xml) ou ('cancelled', None)."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(cmd, stdout=out, stderr=err, shell=False)
        deadline = time.monotonic() + SCAN_TIMEOUT
        while proc.poll() is None:
            time.sleep(1)
            db.refresh(scan)
            db.commit()
            if scan.cancel_requested:
                proc.kill()
                proc.wait()
                return "cancelled", None
            if time.monotonic() > deadline:
                proc.kill()
                proc.wait()
                raise TimeoutError("Délai d'expiration du scan dépassé")
        if proc.returncode != 0:
            err.seek(0)
            raise RuntimeError("Nmap a échoué : " + err.read(1000).decode(errors="replace"))
        if out.seek(0, 2) > MAX_XML_BYTES:
            raise ValueError("Sortie Nmap trop volumineuse")
        out.seek(0)
        return "ok", out.read().decode("utf-8", errors="replace")


def save_results(db, scan, data):
    scan.nmap_version = data.get("nmap_version")
    hosts = []
    for h in data["hosts"]:
        prev = db.scalar(select(Host).where(Host.ip == h["ip"]).order_by(Host.id.desc()).limit(1))
        host = Host(scan_id=scan.id, ip=h["ip"], mac=h["mac"], hostname=h["hostname"],
                    os_guess=h["os_guess"], state=h["state"],
                    criticality=prev.criticality if prev else "normal")
        for s in h["services"]:
            svc = Service(port=s["port"], protocol=s["protocol"], state=s["state"], name=s["name"],
                          product=s["product"], version=s["version"], confidence=s["confidence"])
            svc.vulnerabilities = [Vulnerability(cve=v["cve"], cvss=v["cvss"], source="nse:vulners")
                                   for v in s["vulnerabilities"]]
            host.services.append(svc)
        db.add(host)
        hosts.append(host)
    db.flush()
    return hosts


def finish(db, scan, status, error=None):
    scan.status = status
    scan.error = error
    scan.finished_at = utcnow()
    db.commit()
    audit(db, "scan_finished", status, target=str(scan.id))


def process(db, scan):
    try:
        # Revalidation côté worker (défense en profondeur)
        scopes = [(s.id, s.cidr, s.allow_public)
                  for s in db.scalars(select(Scope).where(Scope.is_active))]
        net, _ = validate_target(scan.target, scopes)
        status, xml = run_nmap(db, scan, build_cmd(scan.profile, str(net)))
        if status == "cancelled":
            finish(db, scan, "cancelled")
            return
        data = parse_nmap_xml(xml)
        hosts = save_results(db, scan, data)  # noqa: F841 (utilisé à l'étape 7)
        scan.status = "done"
        scan.finished_at = utcnow()
        db.commit()  # UNE transaction : tout ou rien (ENF-03)
        audit(db, "scan_finished", "done", target=str(scan.id))
    except Exception as exc:
        db.rollback()
        log.exception("Scan %s en échec", scan.id)
        finish(db, scan, "failed", str(exc)[:500])


def recover_interrupted():
    with SessionLocal() as db:
        db.execute(update(Scan).where(Scan.status == "running")
                   .values(status="failed", error="Interrompu (redémarrage du worker)",
                           finished_at=utcnow()))
        db.commit()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    log.info("Worker démarré")
    while True:
        try:
            recover_interrupted()
            break
        except Exception:
            log.warning("Base pas prête, nouvel essai...")
            time.sleep(5)
    while True:
        try:
            with SessionLocal() as db:
                scan = claim_job(db)
                if scan:
                    process(db, scan)
                    continue
        except Exception:
            log.exception("Erreur dans la boucle du worker")
            time.sleep(5)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
