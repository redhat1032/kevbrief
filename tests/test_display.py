from datetime import date

import pytest

from kevbrief import display, enrich


@pytest.mark.parametrize("vendor,product,expected", [
    ("ProFTPD", "ProFTPD", "ProFTPD"),
    ("Strapi", "Strapi", "Strapi"),
    ("Zammad GmbH", "Zammad", "Zammad"),
    ("GitLab", "GitLab Community and Enterprise Editions", "GitLab Community and Enterprise Editions"),
    ("Acme, Inc.", "Acme Router", "Acme Router"),
    ("Apache", "Struts", "Apache Struts"),
    ("Citrix", "NetScaler", "Citrix NetScaler"),
    ("Fortinet", "FortiMail", "Fortinet FortiMail"),   # prefix of a word is not a repeat
    ("D-Link", "DIR-859 Router", "D-Link DIR-859 Router"),
    ("", "Windows", "Windows"),
    ("Microsoft", "", "Microsoft"),
])
def test_vendor_product_does_not_repeat_vendor(vendor, product, expected):
    assert display.vendor_product(vendor, product) == expected


def test_patch_rows_use_deduped_vendor_product():
    kev = enrich.parse_kev({"vulnerabilities": [
        {"cveID": "CVE-2026-0001", "vendorProject": "Zammad GmbH", "product": "Zammad", "dateAdded": "2026-10-05",
         "dueDate": "2026-10-26"}]})
    rows = enrich.build_patch_table([{"cves": ["CVE-2026-0001"], "sources": ["s"]}], kev, {})
    assert rows[0]["vendor_product"] == "Zammad"
    assert rows[0]["vendor"] == "Zammad GmbH" and rows[0]["product"] == "Zammad"


@pytest.mark.parametrize("score,expected", [(None, "—"), (9.8, "9.8"), (10, "10.0"), ("bad", "—")])
def test_fmt_cvss_shows_dash_not_none(score, expected):
    assert display.fmt_cvss(score) == expected


@pytest.mark.parametrize("prob,expected", [
    (None, "—"), (0.12345, "12.3%"), (0.006, "0.6%"), (0.0004, "<0.1%"), (0.99999, ">99.9%"), (0.5, "50.0%"),
])
def test_fmt_epss_is_a_tidy_percent(prob, expected):
    assert display.fmt_epss(prob) == expected


def test_due_status_states():
    today = date(2026, 10, 8)
    assert display.due_status("2026-10-07", today) == {"state": "past", "label": "1d overdue", "days": -1}
    assert display.due_status("2022-05-03", today)["label"] == "past due"
    assert display.due_status("2026-10-08", today)["state"] == "soon"
    assert display.due_status("2026-10-11", today)["label"] == "in 3d"
    assert display.due_status("2026-12-01", today)["state"] == "ok"
    assert display.due_status("", today)["state"] == "none"


def _row(**kw):
    base = {"cve": "CVE-2026-0001", "in_kev": True, "kev_due_date": "2026-10-01", "ransomware_use": "Known",
            "vendor_product": "Zammad", "kev_name": "x", "epss": 0.006, "cvss": None,
            "mentioned_by": "CISA Advisories", "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"}
    base.update(kw)
    return base


def test_patch_table_html_renders_designed_cells():
    out = display.patch_table([_row(), _row(cve="CVE-2026-0002", in_kev=False, ransomware_use="", kev_due_date="",
                                            epss=None, cvss=7.5, vendor_product="")], date(2026, 10, 8))
    assert '<a class="kb-cve" href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001"' in out
    assert "kb-chip-ransom" in out and "kb-row-ransom" in out
    assert "kb-due-past" in out and "7d overdue" in out and "kb-row-past" in out
    assert ">0.6%<" in out and ">7.5<" in out
    assert ">None<" not in out and "None" not in out
    assert out.count('class="kb-cvss kb-band-none">—<') == 1
    assert "\n" not in out  # blank lines would break Streamlit's Markdown HTML passthrough


def test_patch_table_escapes_feed_values():
    out = display.patch_table([_row(vendor_product="<img src=x onerror=alert(1)>", mentioned_by="<b>x</b>")],
                              date(2026, 10, 8))
    assert "<img" not in out and "<b>" not in out and "&lt;img" in out


def test_stat_cards_html():
    out = display.stat_cards([{"label": "In CISA KEV", "value": 13, "sub": "5 due", "tone": "kev"}])
    assert 'kb-stat-kev' in out and '<div class="kb-stat-value">13</div>' in out
