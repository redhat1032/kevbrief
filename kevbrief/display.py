"""Formatting and HTML rendering for the kevbrief UI.

Pure functions (no Streamlit import) so the display rules are unit-tested.
Every value that came from a feed or an API is escaped here.
"""

from __future__ import annotations

import html
import re
from datetime import date
from typing import Any, Dict, Iterable, List, Optional

DASH = "—"
SOON_DAYS = 14

_CORP_SUFFIX_RE = re.compile(
    r"[\s,]+(?:inc\.?|incorporated|llc|l\.l\.c\.|ltd\.?|limited|gmbh|ag|sa|s\.a\.|s\.p\.a\.|spa|bv|b\.v\.|"
    r"co\.?|corp\.?|corporation|company|plc|pty|oy|ab|as|a/s|se|srl|s\.r\.l\.|kk|k\.k\.|sp\. z o\.o\.)$",
    re.IGNORECASE,
)


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


# ─────────────────────────────────────────────
#   Value formatting
# ─────────────────────────────────────────────
def vendor_core(vendor: str) -> str:
    """'Zammad GmbH' -> 'Zammad', 'Acme, Inc.' -> 'Acme'. Strips trailing corporate suffixes."""
    v = (vendor or "").strip()
    prev = None
    while v and v != prev:
        prev = v
        v = _CORP_SUFFIX_RE.sub("", v).strip(" ,")
    return v


def vendor_product(vendor: str, product: str) -> str:
    """Join KEV vendor and product without repeating the vendor name.

    ProFTPD + ProFTPD -> ProFTPD; Zammad GmbH + Zammad -> Zammad;
    GitLab + GitLab Community Edition -> GitLab Community Edition; Apache + Struts -> Apache Struts.
    """
    vendor = (vendor or "").strip()
    product = (product or "").strip()
    if not product:
        return vendor
    if not vendor:
        return product
    core = vendor_core(vendor) or vendor
    p_low = product.lower()
    for name in {vendor.lower(), core.lower()}:
        if p_low == name or re.match(rf"{re.escape(name)}(?![\w])", p_low):
            return product
    # Product already contains the vendor as a whole word (e.g. "Microsoft" + "Windows Microsoft Defender")
    if re.search(rf"(?<![\w]){re.escape(core.lower())}(?![\w])", p_low):
        return product
    return f"{core} {product}"


def fmt_cvss(score: Optional[float]) -> str:
    if score is None:
        return DASH
    try:
        return f"{float(score):.1f}"
    except (TypeError, ValueError):
        return DASH


def fmt_epss(prob: Optional[float]) -> str:
    """0.12345 -> '12.3%'. Never shows a misleading 100.0% or 0.0%."""
    if prob is None:
        return DASH
    try:
        pct = float(prob) * 100
    except (TypeError, ValueError):
        return DASH
    if pct >= 99.95:
        return ">99.9%"
    if pct < 0.1:
        return "<0.1%"
    return f"{pct:.1f}%"


def cvss_band(score: Optional[float]) -> str:
    if score is None:
        return "none"
    s = float(score)
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    return "low"


def epss_band(prob: Optional[float]) -> str:
    if prob is None:
        return "none"
    if prob >= 0.5:
        return "critical"
    if prob >= 0.1:
        return "high"
    if prob >= 0.01:
        return "medium"
    return "low"


def due_status(due: str, today: date) -> Dict[str, Any]:
    """Classify a KEV due date (YYYY-MM-DD) relative to `today`."""
    if not due:
        return {"state": "none", "label": DASH, "days": None}
    try:
        d = date.fromisoformat(due)
    except ValueError:
        return {"state": "none", "label": due, "days": None}
    days = (d - today).days
    if days < 0:
        label = f"{-days}d overdue" if days >= -30 else "past due"
        return {"state": "past", "label": label, "days": days}
    if days == 0:
        return {"state": "soon", "label": "due today", "days": 0}
    if days <= SOON_DAYS:
        return {"state": "soon", "label": f"in {days}d", "days": days}
    return {"state": "ok", "label": f"in {days}d", "days": days}


# ─────────────────────────────────────────────
#   HTML blocks (compact, no blank lines: Streamlit's Markdown would break them)
# ─────────────────────────────────────────────
def _days_title(days: Optional[int]) -> str:
    if days is None:
        return ""
    if days < 0:
        return f"Federal due date passed {-days} days ago"
    return f"Federal due date in {days} days"


def stat_cards(cards: Iterable[Dict[str, Any]]) -> str:
    out = []
    for c in cards:
        out.append(
            f'<div class="kb-stat kb-stat-{esc(c.get("tone", "default"))}">'
            f'<div class="kb-stat-label">{esc(c["label"])}</div>'
            f'<div class="kb-stat-value">{esc(c["value"])}</div>'
            f'<div class="kb-stat-sub">{esc(c.get("sub", ""))}</div></div>'
        )
    return f'<div class="kb-stats">{"".join(out)}</div>'


def patch_table(rows: List[Dict[str, Any]], today: date) -> str:
    """Designed HTML table for the patch-priority rows from enrich.build_patch_table."""
    head = (
        "<thead><tr>"
        '<th class="kb-c-rank">#</th><th>CVE</th><th>KEV</th><th>KEV due</th><th>Ransomware</th>'
        '<th class="kb-num">EPSS</th><th class="kb-num">CVSS</th><th>Vendor / product</th><th>Mentioned by</th>'
        "</tr></thead>"
    )
    body = []
    for n, r in enumerate(rows, 1):
        url = r.get("nvd_url") or f"https://nvd.nist.gov/vuln/detail/{r['cve']}"
        cve_cell = f'<a class="kb-cve" href="{esc(url)}" target="_blank" rel="noopener noreferrer">{esc(r["cve"])}</a>'
        kev_cell = '<span class="kb-chip kb-chip-kev">KEV</span>' if r.get("in_kev") else f'<span class="kb-muted">{DASH}</span>'

        if r.get("in_kev"):
            st = due_status(r.get("kev_due_date", ""), today)
            due_cell = (f'<span class="kb-date">{esc(r.get("kev_due_date") or DASH)}</span>'
                        f'<span class="kb-due kb-due-{st["state"]}" title="{esc(_days_title(st["days"]))}">{esc(st["label"])}</span>')
        else:
            st = {"state": "none"}
            due_cell = f'<span class="kb-muted">{DASH}</span>'

        rw = r.get("ransomware_use") or ""
        if rw == "Known":
            rw_cell = '<span class="kb-chip kb-chip-ransom">Known</span>'
        elif rw:
            rw_cell = f'<span class="kb-muted">{esc(rw)}</span>'
        else:
            rw_cell = f'<span class="kb-muted">{DASH}</span>'

        epss = r.get("epss")
        width = 0 if epss is None else max(2, min(100, round(float(epss) * 100)))
        epss_cell = (f'<span class="kb-epss kb-band-{epss_band(epss)}">{esc(fmt_epss(epss))}</span>'
                     + (f'<span class="kb-bar"><span style="width:{width}%"></span></span>' if epss is not None else ""))
        cvss = r.get("cvss")
        cvss_cell = f'<span class="kb-cvss kb-band-{cvss_band(cvss)}">{esc(fmt_cvss(cvss))}</span>'

        vp = r.get("vendor_product") or ""
        vp_cell = f'<span title="{esc(r.get("kev_name", ""))}">{esc(vp)}</span>' if vp else f'<span class="kb-muted">{DASH}</span>'

        classes = ["kb-row"]
        if r.get("in_kev"):
            classes.append("kb-row-kev")
        if rw == "Known":
            classes.append("kb-row-ransom")
        if st["state"] == "past":
            classes.append("kb-row-past")
        body.append(
            f'<tr class="{" ".join(classes)}">'
            f'<td class="kb-c-rank">{n}</td><td>{cve_cell}</td><td>{kev_cell}</td><td class="kb-c-due">{due_cell}</td>'
            f'<td>{rw_cell}</td><td class="kb-num kb-c-epss">{epss_cell}</td><td class="kb-num">{cvss_cell}</td>'
            f'<td class="kb-c-vp">{vp_cell}</td><td class="kb-c-src">{esc(r.get("mentioned_by", ""))}</td></tr>'
        )
    return f'<div class="kb-table-wrap"><table class="kb-table">{head}<tbody>{"".join(body)}</tbody></table></div>'
