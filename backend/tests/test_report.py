import io

from helpers import mk_finding, mk_host, mk_scan
from pypdf import PdfReader

from app.api.findings import _csv_safe
from app.reports.builder import DISCLAIMER, build_report_pdf


def _text(pdf: bytes) -> str:
    pages = PdfReader(io.BytesIO(pdf)).pages
    return " ".join(" ".join(p.extract_text() or "" for p in pages).split())


def test_report_has_required_sections_and_disclaimer(db_session):  # CA-08
    scan = mk_scan(db_session)
    host = mk_host(db_session, scan, "172.30.0.11", [(80, "http", "1.0")])
    mk_finding(db_session, scan, host, "R005", 80, 30)
    pdf = build_report_pdf(db_session, scan, "tester")
    assert pdf.startswith(b"%PDF")
    text = _text(pdf)
    for word in ("Limites", "Constats", "Recommandations", "Comparaison", "garantie", "172.30.0.11"):
        assert word in text
    assert "garantie de sécurité" in DISCLAIMER


def test_report_escapes_untrusted_markup(db_session):
    scan = mk_scan(db_session)
    host = mk_host(db_session, scan, "172.30.0.11", [(81, "http", "<i>unclosed & <b")])
    mk_finding(db_session, scan, host, "R005", 81, 30, evidence="<b>oops & <para")
    assert build_report_pdf(db_session, scan, "<u>x").startswith(b"%PDF")


def test_report_includes_previous_scan_comparison(db_session):
    a, b = mk_scan(db_session), mk_scan(db_session)
    mk_host(db_session, a, "172.30.0.11", [(80, "http", None)])
    mk_host(db_session, b, "172.30.0.11", [(80, "http", None), (8080, "http-proxy", None)])
    assert "Nouveaux ports ouverts" in _text(build_report_pdf(db_session, b, "tester"))


def test_csv_export_neutralizes_formulas():
    assert _csv_safe("=cmd|' /C calc'!A0").startswith("'")
    assert _csv_safe("@SUM(1)").startswith("'")
    assert _csv_safe("normal") == "normal"
