import io
import ipaddress
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.scan import Finding, Host, Scan
from app.services.compare import compare_scans
from app.timeutils import utcnow

LEVEL_ORDER = ["critical", "high", "medium", "low", "info"]
LEVEL_FR = {"critical": "Critique", "high": "Élevé", "medium": "Moyen", "low": "Faible", "info": "Info"}
STATUS_FR = {"new": "Nouveau", "in_progress": "En cours d'analyse", "fixed": "Corrigé", "accepted": "Accepté"}
CRIT_FR = {"low": "Faible", "normal": "Normale", "high": "Élevée"}
FACTOR_FR = {"rule_severity": "sévérité", "host_criticality": "criticité", "exposure": "exposition",
             "cvss": "CVSS", "confidence": "confiance"}
PROFILE_FR = {"discovery": "Découverte rapide (hôtes actifs uniquement)",
              "standard": "Standard (1000 ports courants, services et versions)",
              "deep": "Approfondi (tous les ports, détection d'OS)"}

DISCLAIMER = (
    "Les résultats de ce rapport reflètent l'état observé à un instant donné, depuis un point de vue "
    "réseau donné. Ils ne constituent pas une garantie de sécurité : l'absence de constat ne prouve pas "
    "l'absence de risque, et un port ouvert n'est pas automatiquement une vulnérabilité."
)
LIMITS = [
    "L'analyse reflète l'état observé à un instant donné, depuis le point de vue réseau du scanner.",
    "Un équipement qui ne répond pas peut être éteint, filtré ou trop lent : son silence n'est pas une preuve de disparition.",
    "Un port ouvert n'est pas automatiquement une vulnérabilité : les constats sont des points à examiner.",
    "Les CVE rapprochées par numéro de version sont potentielles (faux positifs possibles).",
    "L'identification des services et des systèmes d'exploitation est probabiliste.",
    "Les adresses MAC ne sont visibles que sur le même segment réseau que le scanner.",
]

_base = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=_base["Heading1"], fontSize=20, spaceAfter=10)
H2 = ParagraphStyle("H2", parent=_base["Heading2"], fontSize=13, spaceBefore=14, spaceAfter=6)
BODY = ParagraphStyle("Body", parent=_base["BodyText"], fontSize=9.5, leading=13)
SMALL = ParagraphStyle("Small", parent=BODY, fontSize=8, leading=10)
NOTE = ParagraphStyle("Note", parent=BODY, backColor=colors.HexColor("#fff3cd"),
                      borderPadding=6, spaceBefore=8, spaceAfter=8)


def p(text, style=BODY):
    return Paragraph(escape("-" if text is None else str(text)), style)


def _table(header, rows, widths_cm):
    data = [[Paragraph(f"<b>{escape(h)}</b>", SMALL) for h in header]]
    data += [[p(v, SMALL) for v in r] for r in rows]
    t = Table(data, colWidths=[w * cm for w in widths_cm], repeatRows=1)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9ecef")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _fmt(dt):
    return dt.strftime("%d/%m/%Y %H:%M UTC") if dt else "-"


def _cap(lines, n=15):
    return lines[:n] + ([f"... et {len(lines) - n} autre(s)"] if len(lines) > n else [])


def _previous_scan(db, scan):
    net = ipaddress.ip_network(scan.target, strict=False)
    candidates = db.scalars(select(Scan).where(Scan.status == "done", Scan.id < scan.id,
                                               Scan.profile == scan.profile)
                            .order_by(Scan.id.desc()).limit(20))
    for c in candidates:
        if ipaddress.ip_network(c.target, strict=False).overlaps(net):
            return c
    return None


def _footer(scan_id):
    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.drawString(1.8 * cm, 1.0 * cm, f"NetSentry AI - Scan #{scan_id} - Rapport indicatif, non exhaustif")
        canvas.drawRightString(A4[0] - 1.8 * cm, 1.0 * cm, f"Page {doc.page}")
        canvas.restoreState()
    return draw


def build_report_pdf(db, scan: Scan, author: str) -> bytes:
    hosts = list(db.scalars(select(Host).where(Host.scan_id == scan.id)
                            .options(selectinload(Host.services)).order_by(Host.id)))
    hosts.sort(key=lambda h: ipaddress.ip_address(h.ip))
    findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan.id)
                               .options(selectinload(Finding.host))
                               .order_by(Finding.score.desc(), Finding.id)))
    open_by_host = {h.id: [s for s in h.services if s.state == "open"] for h in hosts}
    n_open = sum(len(v) for v in open_by_host.values())
    by_level = {lvl: sum(1 for f in findings if f.level == lvl) for lvl in LEVEL_ORDER}

    s = []
    # 1. Informations générales
    s += [p("Rapport d'analyse de sécurité réseau", H1), p("1. Informations générales", H2)]
    s.append(_table(["Élément", "Valeur"], [
        ["Identifiant du scan", f"#{scan.id}"],
        ["Date du scan", _fmt(scan.finished_at or scan.created_at)],
        ["Rapport généré le", _fmt(utcnow())],
        ["Auteur", author],
        ["Version de Nmap", scan.nmap_version],
    ], [5, 12.4]))

    # 2. Résumé exécutif
    s.append(p("2. Résumé exécutif", H2))
    s.append(p(f"{len([h for h in hosts if h.state == 'up'])} équipement(s) actif(s) détecté(s), "
               f"{n_open} port(s) ouvert(s), {len(findings)} constat(s) à examiner."))
    s.append(Spacer(1, 4))
    s.append(_table(["Niveau"] + [LEVEL_FR[x] for x in LEVEL_ORDER],
                    [["Nombre de constats"] + [by_level[x] for x in LEVEL_ORDER]], [4.4, 2.6, 2.6, 2.6, 2.6, 2.6]))
    if findings:
        s.append(Spacer(1, 6))
        s.append(p("Principaux risques à examiner :"))
        s.append(_table(["Niveau", "Score", "Constat", "Équipement"],
                        [[LEVEL_FR[f.level], f.score, f.title, f"{f.host.ip} ({f.key.split('|')[2]})"]
                         for f in findings[:5]], [2.2, 1.6, 9.0, 4.6]))

    # 3. Périmètre et profil
    s.append(p("3. Périmètre analysé et profil de scan", H2))
    s.append(p(f"Cible : {scan.target}"))
    s.append(p(f"Profil : {PROFILE_FR.get(scan.profile, scan.profile)}"))

    # 4. Limites
    s.append(p("4. Limites de l'analyse", H2))
    for line in LIMITS:
        s.append(p("- " + line))
    s.append(p(DISCLAIMER, NOTE))

    # 5. Équipements
    s.append(p("5. Équipements détectés", H2))
    if hosts:
        s.append(_table(["IP", "Nom d'hôte", "MAC", "OS estimé", "État", "Criticité", "Ports ouverts"],
                        [[h.ip, h.hostname, h.mac, h.os_guess, h.state, CRIT_FR.get(h.criticality, h.criticality),
                          len(open_by_host[h.id])] for h in hosts], [2.6, 3.0, 3.0, 3.8, 1.4, 1.8, 1.8]))
    else:
        s.append(p("Aucun équipement détecté."))

    # 6. Ports et services
    s.append(p("6. Ports et services identifiés", H2))
    rows = [[h.ip, f"{v.port}/{v.protocol}", v.name or "inconnu",
             " ".join(x for x in (v.product, v.version) if x) or "-", f"{v.confidence}%"]
            for h in hosts for v in sorted(open_by_host[h.id], key=lambda x: x.port)]
    if rows:
        s.append(_table(["IP", "Port", "Service", "Produit / version", "Confiance"], rows, [2.8, 2.2, 3.0, 7.4, 2.0]))
    elif scan.profile == "discovery":
        s.append(p("Le profil de découverte rapide ne collecte pas les ports."))
    else:
        s.append(p("Aucun port ouvert identifié."))

    # 7. Constats
    s.append(p("7. Constats classés par priorité", H2))
    if not findings:
        s.append(p("Aucun constat pour ce scan."))
    for f in findings:
        factors = " ; ".join(f"{FACTOR_FR.get(x['factor'], x['factor'])} {x['contribution']}" for x in f.factors)
        s.append(KeepTogether([
            Paragraph(f"<b>[{escape(LEVEL_FR[f.level])} - {f.score}/100]</b> {escape(f.title)}", BODY),
            p(f"{f.host.ip} - port {f.key.split('|')[2]} - règle {f.rule_id} v{f.rule_version} - "
              f"statut : {STATUS_FR.get(f.status, f.status)}", SMALL),
            p(f"Risque : {f.justification}", SMALL),
            p(f"Preuves : {f.evidence}", SMALL),
            p(f"Détail du score : {factors}", SMALL),
            p(f"Recommandation : {f.recommendation}", SMALL),
            Spacer(1, 6),
        ]))

    # 8. Recommandations
    s.append(p("8. Recommandations", H2))
    groups = {}
    for f in findings:
        g = groups.setdefault((f.rule_id, f.title), {"rec": f.recommendation,
                              "max": f.score, "level": f.level, "ips": set()})
        g["ips"].add(f.host.ip)
        if f.score > g["max"]:
            g["max"], g["level"] = f.score, f.level
    if groups:
        rows = []
        for (_rid, title), g in sorted(groups.items(), key=lambda kv: -kv[1]["max"]):
            ips = sorted(g["ips"])
            rows.append([LEVEL_FR[g["level"]], title, g["rec"],
                         f"{len(ips)} : " + ", ".join(ips[:6]) + (" ..." if len(ips) > 6 else "")])
        s.append(_table(["Priorité", "Constat", "Recommandation", "Équipements"], rows, [1.8, 4.2, 6.6, 4.8]))
    else:
        s.append(p("Aucune recommandation."))

    # 9. Anomalies
    s.append(p("9. Anomalies détectées", H2))
    s.append(p("Le module de détection d'anomalies (Machine Learning) n'est pas encore activé dans cette "
               "version : aucune anomalie n'est rapportée dans ce document."))

    # 10. Comparaison
    s.append(p("10. Comparaison avec une analyse antérieure", H2))
    prev = _previous_scan(db, scan)
    if prev is None:
        s.append(p("Aucune analyse antérieure comparable (même profil, périmètre recoupant) n'est disponible."))
    else:
        c = compare_scans(db, prev, scan)
        s.append(p(f"Référence : scan #{prev.id} du {_fmt(prev.finished_at)} (cible {prev.target})."))
        for n in c["notes"]:
            s.append(p("Remarque : " + n, SMALL))
        sb, so = c["summary"]["base"], c["summary"]["other"]
        s.append(
            p(f"Constats : {sb['findings']} puis {so['findings']} ; score cumulé : {sb['total_score']} puis {so['total_score']}."))
        sections = [
            ("Nouveaux équipements", [f"{h['ip']} (ports ouverts : {h['open_ports']})" for h in c["new_hosts"]]),
            ("Équipements qui ne répondent plus (hôte éteint, filtré ou délai dépassé : non confirmé disparu)",
             [h["ip"] for h in c["missing_hosts"]]),
            ("Nouveaux ports ouverts", [
             f"{x['ip']} : {x['port']}/{x['protocol']} ({x['service'] or 'inconnu'})" for x in c["new_ports"]]),
            ("Ports qui ne sont plus ouverts", [
             f"{x['ip']} : {x['port']}/{x['protocol']} ({x['service'] or 'inconnu'})" for x in c["closed_ports"]]),
            ("Changements de service ou de version",
             [f"{x['ip']} : {x['port']}/{x['protocol']} {x['before']['product'] or ''} {x['before']['version'] or ''}"
              f" -> {x['after']['product'] or ''} {x['after']['version'] or ''}" for x in c["service_changes"]]),
            ("Nouveaux constats", [
             f"[{LEVEL_FR[x['level']]}] {x['title']} - {x['ip']} ({x['port']})" for x in c["findings"]["new"]]),
            ("Constats non observés lors de ce scan", [
             f"{x['title']} - {x['ip']} ({x['port']})" for x in c["findings"]["resolved"]]),
        ]
        for title, lines in sections:
            s.append(p(f"{title} : {len(lines)}", BODY))
            for line in _cap(lines):
                s.append(p("   - " + line, SMALL))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=1.8 * cm, rightMargin=1.8 * cm,
                            topMargin=1.8 * cm, bottomMargin=1.8 * cm,
                            title=f"NetSentry AI - Scan {scan.id}", author=author)
    foot = _footer(scan.id)
    doc.build(s, onFirstPage=foot, onLaterPages=foot)
    return buf.getvalue()
