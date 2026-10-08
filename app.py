"""
kevbrief: patch-priority briefing from security news.

Pulls security news feeds, pulls out the CVEs they mention, checks every one
against the CISA Known Exploited Vulnerabilities (KEV) catalog and FIRST EPSS,
and puts the ones to patch first at the top.

Data logic lives in the `kevbrief` package (feeds.py, enrich.py, display.py); this file is layout only.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

from kevbrief import __version__, display, enrich, feeds
from kevbrief.display import esc

SYSTEM_NAME = "kevbrief"
SITE_URL = "https://douglasweant.com"
SITE_LABEL = "douglasweant.com"

st.set_page_config(
    page_title=f"{SYSTEM_NAME} · Patch-priority briefing",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ─────────────────────────────────────────────
#   Styling (dark, custom components)
# ─────────────────────────────────────────────
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root{
  --bg:#07090d; --surface:#0d1117; --surface-2:#111823; --surface-3:#161f2c;
  --border:rgba(148,163,184,.14); --border-strong:rgba(148,163,184,.24);
  --text:#e6edf3; --text-2:#b6c2d1; --muted:#7d8a9c;
  --accent:#22d3ee; --accent-soft:rgba(34,211,238,.12);
  --kev:#fb923c; --kev-soft:rgba(251,146,60,.12);
  --ransom:#f43f5e; --ransom-soft:rgba(244,63,94,.14);
  --soon:#fbbf24; --soon-soft:rgba(251,191,36,.12);
  --ok:#34d399; --ok-soft:rgba(52,211,153,.12);
  --sans:'Inter',system-ui,-apple-system,'Segoe UI',sans-serif;
  --mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
}
.stApp{background:radial-gradient(1200px 500px at 50% -200px,rgba(34,211,238,.08),transparent 70%),var(--bg);color:var(--text);font-family:var(--sans);}
.stApp [data-testid="stMarkdownContainer"],.stApp [data-testid="stSidebar"]{font-family:var(--sans);}
[data-testid="stHeader"]{background:transparent;}
[data-testid="stDecoration"],[data-testid="stToolbar"]{display:none !important;}
.block-container{max-width:1280px;padding-top:1.4rem;padding-bottom:3rem;}
[data-testid="stSidebar"]{background:var(--surface);border-right:1px solid var(--border);}
[data-testid="stSidebar"] h3{font-size:.8rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);font-weight:600;}
a{color:var(--accent);}

/* top bar */
.kb-topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;}
.kb-brand{display:flex;align-items:center;gap:10px;}
.kb-logo{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;
  background:linear-gradient(135deg,#22d3ee,#6366f1);color:#05080c;font-weight:700;font-size:.9rem;font-family:var(--mono);}
.kb-name{font-weight:700;font-size:1.05rem;letter-spacing:-.01em;color:var(--text);}
.kb-ver{font-family:var(--mono);font-size:.7rem;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:1px 8px;}
.kb-site{font-size:.8rem;color:var(--muted) !important;text-decoration:none !important;}
.kb-site:hover{color:var(--accent) !important;}

/* hero */
.kb-hero{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;flex-wrap:wrap;
  padding:22px 24px;border:1px solid var(--border);border-radius:14px;
  background:linear-gradient(180deg,var(--surface-2),var(--surface));margin-bottom:16px;}
.kb-h1{font-size:1.6rem;font-weight:700;letter-spacing:-.02em;margin:0;color:var(--text);line-height:1.2;}
.kb-hero .kb-lede{margin:6px 0 0 0;color:var(--text-2);font-size:.92rem;max-width:720px;}
.kb-hero-meta{display:flex;gap:8px;flex-wrap:wrap;}
.kb-tag{font-size:.72rem;color:var(--text-2);border:1px solid var(--border);background:var(--surface-3);border-radius:999px;padding:4px 10px;white-space:nowrap;}
.kb-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px;background:var(--ok);vertical-align:middle;}
.kb-dot-warn{background:var(--soon);} .kb-dot-bad{background:var(--ransom);}

/* stat cards */
.kb-stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:22px;}
.kb-stat{border:1px solid var(--border);border-radius:12px;background:var(--surface);padding:14px 16px;position:relative;overflow:hidden;}
.kb-stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--border-strong);}
.kb-stat-label{font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:600;}
.kb-stat-value{font-family:var(--mono);font-size:1.9rem;font-weight:600;color:var(--text);margin-top:4px;line-height:1.1;}
.kb-stat-sub{font-size:.75rem;color:var(--muted);margin-top:4px;min-height:1em;}
.kb-stat-accent::before{background:var(--accent);} .kb-stat-kev::before{background:var(--kev);}
.kb-stat-kev .kb-stat-value{color:var(--kev);}
.kb-stat-ransom::before{background:var(--ransom);} .kb-stat-ransom .kb-stat-value{color:var(--ransom);}
@media (max-width:900px){.kb-stats{grid-template-columns:repeat(2,minmax(0,1fr));}}

/* section headers */
.kb-section{display:flex;justify-content:space-between;align-items:baseline;gap:12px;margin:8px 0 10px 0;}
.kb-h2{font-size:1.05rem;font-weight:650;color:var(--text);}
.kb-section .kb-sub{font-size:.78rem;color:var(--muted);}
.kb-note{font-size:.78rem;color:var(--muted);margin:8px 2px 0 2px;line-height:1.5;}
.kb-legend{display:flex;gap:14px;flex-wrap:wrap;font-size:.74rem;color:var(--muted);margin:8px 2px 18px 2px;}

/* patch table */
.kb-table-wrap{border:1px solid var(--border);border-radius:12px;background:var(--surface);max-height:560px;overflow:auto;}
.kb-table{width:100%;border-collapse:separate;border-spacing:0;font-size:.82rem;}
.kb-table thead th{position:sticky;top:0;z-index:1;background:var(--surface-3);color:var(--muted);font-weight:600;
  font-size:.7rem;letter-spacing:.08em;text-transform:uppercase;text-align:left;padding:9px 10px;border-bottom:1px solid var(--border-strong);white-space:nowrap;}
.kb-table td{padding:8px 10px;border-bottom:1px solid var(--border);color:var(--text-2);vertical-align:middle;}
.kb-table tbody tr:last-child td{border-bottom:none;}
.kb-table tbody tr:hover td{background:rgba(148,163,184,.05);}
.kb-row-ransom td:first-child{box-shadow:inset 3px 0 0 var(--ransom);}
.kb-row-kev:not(.kb-row-ransom) td:first-child{box-shadow:inset 3px 0 0 var(--kev);}
.kb-table .kb-num{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums;white-space:nowrap;}
.kb-c-rank{width:28px;color:var(--muted) !important;font-family:var(--mono);font-size:.75rem;text-align:right;}
.kb-c-due{white-space:nowrap;}
.kb-c-epss{white-space:nowrap;}
.kb-c-vp{min-width:150px;color:var(--text) !important;}
.kb-c-src{min-width:110px;font-size:.76rem;color:var(--muted) !important;}
.kb-cve{font-family:var(--mono);font-weight:500;color:var(--accent) !important;text-decoration:none !important;white-space:nowrap;}
.kb-cve:hover{text-decoration:underline !important;}
.kb-muted{color:var(--muted);}
.kb-chip{display:inline-block;font-size:.68rem;font-weight:600;letter-spacing:.04em;border-radius:6px;padding:2px 7px;border:1px solid transparent;white-space:nowrap;}
.kb-chip-kev{color:var(--kev);background:var(--kev-soft);border-color:rgba(251,146,60,.35);}
.kb-chip-ransom{color:#fff;background:var(--ransom);border-color:var(--ransom);}
.kb-date{font-family:var(--mono);font-variant-numeric:tabular-nums;color:var(--text-2);margin-right:8px;}
.kb-due{font-size:.68rem;font-weight:600;border-radius:6px;padding:2px 6px;}
.kb-due-past{color:var(--ransom);background:var(--ransom-soft);}
.kb-due-soon{color:var(--soon);background:var(--soon-soft);}
.kb-due-ok{color:var(--muted);}
.kb-epss{display:inline-block;min-width:50px;text-align:right;} .kb-cvss{display:inline-block;min-width:30px;text-align:right;}
.kb-bar{display:inline-block;width:36px;height:5px;border-radius:3px;background:rgba(148,163,184,.15);margin-left:8px;vertical-align:middle;overflow:hidden;}
.kb-bar span{display:block;height:100%;background:var(--accent);border-radius:3px;}
.kb-band-critical{color:var(--ransom);} .kb-band-high{color:var(--kev);} .kb-band-medium{color:var(--soon);}
.kb-band-low{color:var(--text-2);} .kb-band-none{color:var(--muted);}

/* filter chips */
[data-baseweb="tag"],[data-tag]{background:var(--surface-3) !important;border:1px solid var(--border-strong) !important;color:var(--text-2) !important;}
[data-tag] *{color:var(--text-2) !important;}
[data-tag] svg{fill:var(--muted) !important;}
/* download buttons */
.stDownloadButton > button{background:var(--surface-2) !important;color:var(--text) !important;border:1px solid var(--border-strong) !important;
  border-radius:8px !important;font-size:.82rem !important;padding:.35rem .9rem !important;}
.stDownloadButton > button:hover{border-color:var(--accent) !important;color:var(--accent) !important;}

/* coverage cards */
.kb-card{border:1px solid var(--border);border-radius:12px;background:var(--surface);padding:14px 16px;margin-bottom:6px;}
.kb-card-kev{border-left:3px solid var(--kev);}
.kb-card-meta{display:flex;justify-content:space-between;gap:12px;font-size:.74rem;color:var(--muted);}
.kb-card-src{font-weight:600;color:var(--text-2);}
.kb-card-title{font-size:1rem;font-weight:600;margin:6px 0 4px 0;line-height:1.35;}
.kb-card-title a{color:var(--text) !important;text-decoration:none !important;}
.kb-card-title a:hover{color:var(--accent) !important;}
.kb-card-summary{font-size:.86rem;color:var(--text-2);line-height:1.5;}
.kb-card-chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px;}
.kb-pill{font-size:.68rem;border:1px solid var(--border-strong);border-radius:999px;padding:2px 8px;color:var(--muted);}
.kb-pill-cve{font-family:var(--mono);color:var(--text-2);}
.kb-pill-kev{border-color:rgba(251,146,60,.45);color:var(--kev);background:var(--kev-soft);}
.kb-card-also{font-size:.74rem;color:var(--muted);margin-top:8px;}
.kb-card-also a{color:var(--text-2) !important;}
[data-testid="stBaseButton-secondary"]{background:transparent;border:1px solid var(--border);color:var(--muted);font-size:.78rem;padding:.15rem .7rem;min-height:0;border-radius:8px;}
[data-testid="stBaseButton-secondary"]:hover{border-color:var(--accent);color:var(--accent);}

/* sidebar status */
.kb-health{font-size:.78rem;color:var(--text-2);margin:2px 0;}
.kb-health .kb-count{color:var(--muted);font-family:var(--mono);font-size:.72rem;}
.kb-footer{text-align:center;color:var(--muted);font-size:.74rem;margin-top:28px;padding-top:16px;border-top:1px solid var(--border);}
</style>""", unsafe_allow_html=True)


def html_block(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


# ─────────────────────────────────────────────
#   Cached data access
# ─────────────────────────────────────────────
@st.cache_data(ttl=600, show_spinner="Fetching security news…")
def get_feeds(names: tuple):
    items, health = feeds.fetch_all({n: feeds.FEEDS[n] for n in names})
    return items, health, datetime.now(timezone.utc)


@st.cache_data(ttl=3600, show_spinner="Downloading CISA KEV catalog…")
def get_kev():
    return enrich.load_kev()


@st.cache_data(ttl=3600, show_spinner="Fetching EPSS scores…")
def get_epss(cves: tuple):
    return enrich.fetch_epss(cves)


@st.cache_resource
def get_nvd() -> enrich.NvdClient:
    return enrich.NvdClient(os.environ.get("NVD_API_KEY", ""))


def fmt_dt(d: Any) -> str:
    return d.strftime("%Y-%m-%d %H:%M UTC") if d else "date unknown"


if "saved" not in st.session_state:
    st.session_state.saved = set()


# ─────────────────────────────────────────────
#   Top bar
# ─────────────────────────────────────────────
html_block(
    f'<div class="kb-topbar"><div class="kb-brand"><div class="kb-logo">kb</div>'
    f'<span class="kb-name">{SYSTEM_NAME}</span><span class="kb-ver">v{esc(__version__)}</span></div>'
    f'<a class="kb-site" href="{SITE_URL}" target="_blank" rel="noopener">{SITE_LABEL}</a></div>'
)


# ─────────────────────────────────────────────
#   Sidebar controls
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("### Filters")
    sources = st.multiselect("Sources", list(feeds.FEEDS), default=list(feeds.FEEDS))
    time_window = st.selectbox("Time window", ["Last 24 hours", "Last 3 days", "Last 7 days", "Last 30 days", "All"], index=2)
    themes = st.multiselect("Themes", ["General"] + list(feeds.TAG_KEYWORDS), default=[])
    query = st.text_input("Search", placeholder="CVE-2025-1234, Fortinet, Okta…")
    kev_only = st.checkbox("Only articles that mention a KEV CVE", value=False)
    show_saved = st.checkbox("Show saved only (this session)", value=False)
    use_nvd = st.checkbox("Add CVSS from NVD (rate limited)", value=True)


# ─────────────────────────────────────────────
#   Data pipeline: fetch → enrich everything → filter
# ─────────────────────────────────────────────
active = tuple(sources) if sources else tuple(feeds.FEEDS)
all_items, health, fetched_at = get_feeds(active)
kev, kev_err = get_kev()
all_cves = tuple(sorted({c for i in all_items for c in i["cves"]}))
epss, epss_err = get_epss(all_cves) if all_cves else ({}, None)

nvd: Dict[str, Dict[str, Any]] = {}
nvd_client = get_nvd()
if use_nvd and all_cves:
    # Spend the NVD budget on the CVEs most likely to matter.
    ordered = sorted(all_cves, key=lambda c: enrich.cve_priority_key(c, kev, epss))
    nvd = nvd_client.lookup_many(ordered)

items: List[Dict[str, Any]] = list(all_items)
if time_window != "All":
    days = {"Last 24 hours": 1, "Last 3 days": 3, "Last 7 days": 7, "Last 30 days": 30}[time_window]
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    items = [i for i in items if i["published"] and i["published"] >= cutoff]
if themes:
    sel = set(themes)
    items = [i for i in items if sel.intersection(i["labels"])]
if query:
    q = query.lower().strip()
    items = [i for i in items if q in i["title"].lower() or q in i["summary"].lower()
             or any(q in s.lower() for s in i["sources"]) or any(q in c.lower() for c in i["cves"])]
if kev_only:
    items = [i for i in items if any(c in kev for c in i["cves"])]
if show_saved:
    items = [i for i in items if i["id"] in st.session_state.saved]

items.sort(key=lambda i: enrich.item_priority_key(i, kev, epss))
patch_rows = enrich.build_patch_table(items, kev, epss, nvd)
kev_rows = [r for r in patch_rows if r["in_kev"]]
today = datetime.now(timezone.utc).date()


# ─────────────────────────────────────────────
#   Sidebar status (drawn after fetching so it is current)
# ─────────────────────────────────────────────
def health_line(ok: bool, label: str, count: str = "", tip: str = "") -> str:
    dot = "kb-dot" if ok else "kb-dot kb-dot-bad"
    cnt = f' <span class="kb-count">{esc(count)}</span>' if count else ""
    return f'<div class="kb-health" title="{esc(tip)}"><span class="{dot}"></span>{esc(label)}{cnt}</div>'


with st.sidebar:
    st.markdown("### Data sources")
    lines = [health_line(h["ok"], name, str(h["count"]), h["error"] or f"{h['count']} items") for name, h in health.items()]
    lines.append(health_line(bool(kev), "CISA KEV", f"{len(kev):,}" if kev else "unavailable", kev_err or ""))
    lines.append(health_line(not epss_err, "FIRST EPSS", f"{len(epss)} scored", epss_err or ""))
    if use_nvd:
        key_note = "API key" if nvd_client.api_key else "no key · 5 / 30 s"
        lines.append(health_line(True, "NVD CVSS", f"{len(nvd)}/{len(all_cves)} · {key_note}"))
    html_block("".join(lines))
    if use_nvd and nvd_client.rate_limited:
        st.caption("NVD budget used up; remaining CVSS scores fill in on later reloads. KEV and EPSS are unaffected.")


# ─────────────────────────────────────────────
#   Hero
# ─────────────────────────────────────────────
live = sum(1 for h in health.values() if h["ok"])
src_dot = "kb-dot" if live == len(health) else ("kb-dot kb-dot-warn" if live else "kb-dot kb-dot-bad")
kev_dot = "kb-dot" if kev else "kb-dot kb-dot-bad"
html_block(
    '<div class="kb-hero"><div><div class="kb-h1">Patch-priority briefing</div>'
    '<div class="kb-lede">Every CVE mentioned in today\'s security news, checked against CISA\'s Known Exploited Vulnerabilities '
    'catalog and FIRST EPSS. Patch from the top.</div></div>'
    '<div class="kb-hero-meta">'
    f'<span class="kb-tag"><span class="{src_dot}"></span>{live}/{len(health)} sources live</span>'
    f'<span class="kb-tag"><span class="{kev_dot}"></span>KEV {len(kev):,} entries</span>'
    f'<span class="kb-tag">{esc(time_window)}</span>'
    f'<span class="kb-tag">Updated {esc(fetched_at.strftime("%H:%M UTC"))}</span>'
    '</div></div>'
)

if not kev:
    st.error("Could not download the CISA KEV catalog, so nothing below is KEV-checked. "
             "Check https://www.cisa.gov/known-exploited-vulnerabilities-catalog directly.")


# ─────────────────────────────────────────────
#   Stat cards
# ─────────────────────────────────────────────
past_due = sum(1 for r in kev_rows if display.due_status(r["kev_due_date"], today)["state"] == "past")
due_soon = sum(1 for r in kev_rows if display.due_status(r["kev_due_date"], today)["state"] == "soon")
ransom_known = sum(1 for r in kev_rows if r["ransomware_use"] == "Known")
html_block(display.stat_cards([
    {"label": "Articles", "value": len(items), "sub": f"{len(items) - sum(1 for i in items if i['cves'])} without a CVE id"},
    {"label": "CVEs mentioned", "value": len(patch_rows), "sub": f"{sum(1 for r in patch_rows if r['epss'] is not None)} with EPSS", "tone": "accent"},
    {"label": "In CISA KEV", "value": len(kev_rows), "sub": f"{due_soon} due within {display.SOON_DAYS}d · {past_due} past due", "tone": "kev"},
    {"label": "Known ransomware use", "value": ransom_known, "sub": "per CISA KEV", "tone": "ransom"},
]))


# ─────────────────────────────────────────────
#   Patch these first
# ─────────────────────────────────────────────
html_block(f'<div class="kb-section"><div class="kb-h2">Patch these first</div><span class="kb-sub">{len(patch_rows)} CVEs · '
           f'{len(kev_rows)} in KEV</span></div>')
if not patch_rows:
    st.info("No CVEs mentioned in the current selection. Widen the time window or sources.")
else:
    html_block(display.patch_table(patch_rows, today))
    html_block(
        '<div class="kb-legend">'
        '<span><span class="kb-chip kb-chip-ransom">Known</span> CISA knows of ransomware use</span>'
        '<span><span class="kb-due kb-due-past">past due</span> KEV federal due date has passed</span>'
        f'<span><span class="kb-due kb-due-soon">in 5d</span> due within {display.SOON_DAYS} days</span>'
        '<span>EPSS: chance of exploitation in the next 30 days</span>'
        '<span>CVE ids link to NVD</span></div>'
    )


# ─────────────────────────────────────────────
#   Exports
# ─────────────────────────────────────────────
def briefing_markdown() -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# {SYSTEM_NAME} patch-priority briefing", "", f"Generated {now} • window: {time_window}", ""]
    lines += ["## Patch these first", ""]
    if patch_rows:
        lines += ["| CVE | KEV | KEV due | Ransomware use | EPSS | CVSS | Vendor / product | Mentioned by |",
                  "|---|---|---|---|---|---|---|---|"]
        for r in patch_rows:
            cells = [r["cve"], "yes" if r["in_kev"] else "", r["kev_due_date"] or display.DASH,
                     r["ransomware_use"] or display.DASH, display.fmt_epss(r["epss"]), display.fmt_cvss(r["cvss"]),
                     r["vendor_product"] or display.DASH, r["mentioned_by"]]
            lines.append("| " + " | ".join(str(c).replace("|", "/") for c in cells) + " |")
    else:
        lines.append("No CVEs mentioned in this selection.")
    lines += ["", "## Articles", ""]
    for i in items:
        kev_note = " (CISA KEV)" if any(c in kev for c in i["cves"]) else ""
        lines.append(f"### {i['title']}{kev_note}")
        lines.append(f"- Published: {fmt_dt(i['published'])}")
        lines.append(f"- Sources: {', '.join(i['sources'])}")
        if i["cves"]:
            lines.append(f"- CVEs: {', '.join(i['cves'])}")
        lines += ["", i["summary"], "", f"[Read more]({i['link']})", ""]
    lines += ["---", "KEV is the authority on what is being exploited. News mentions are not an asset inventory."]
    return "\n".join(lines)


patch_df = pd.DataFrame(patch_rows)
if items or patch_rows:
    c1, c2, c3, _ = st.columns([1, 1, 1, 3])
    with c1:
        st.download_button("Patch list CSV", patch_df.to_csv(index=False).encode("utf-8") if not patch_df.empty else b"",
                           file_name="kevbrief_patch_priority.csv", mime="text/csv", disabled=patch_df.empty)
    with c2:
        st.download_button("Briefing .md", briefing_markdown(),
                           file_name="kevbrief_briefing.md", mime="text/markdown")
    with c3:
        art_df = pd.DataFrame([{
            "published": fmt_dt(i["published"]), "sources": ", ".join(i["sources"]), "title": i["title"],
            "link": i["link"], "labels": ", ".join(i["labels"]), "cves": ", ".join(i["cves"]),
            "kev_cves": ", ".join(c for c in i["cves"] if c in kev),
        } for i in items])
        st.download_button("Articles CSV", art_df.to_csv(index=False).encode("utf-8"),
                           file_name="kevbrief_articles.csv", mime="text/csv")

html_block('<div class="kb-note">KEV due dates are the deadlines CISA sets for US federal agencies (BOD 22-01); '
           'treat them as an outer limit, not a target. News mentions are not an asset scan: confirm exposure '
           'against your own inventory.</div>')


# ─────────────────────────────────────────────
#   Supporting coverage
# ─────────────────────────────────────────────
st.write("")
html_block(f'<div class="kb-section"><div class="kb-h2">Supporting coverage</div><span class="kb-sub">{len(items)} articles · KEV-related and '
           f'highest-EPSS first · duplicate stories merged</span></div>')
if not items:
    st.info("No articles matched the current filters.")
else:
    for item in items:
        kev_cves = [c for c in item["cves"] if c in kev]
        link = feeds.safe_url(item["link"])
        title_html = (f'<a href="{esc(link)}" target="_blank" rel="noopener noreferrer">{esc(item["title"])}</a>'
                      if link else esc(item["title"]))
        chips = []
        for c in item["cves"]:
            parts = [c]
            if c in epss:
                parts.append(f"EPSS {display.fmt_epss(epss[c]['epss'])}")
            if (nvd.get(c) or {}).get("cvss") is not None:
                parts.append(f"CVSS {display.fmt_cvss(nvd[c]['cvss'])}")
            cls = "kb-pill kb-pill-cve kb-pill-kev" if c in kev else "kb-pill kb-pill-cve"
            label = (" · ".join(parts)) + (" · KEV" if c in kev else "")
            chips.append(f'<span class="{cls}">{esc(label)}</span>')
        chips += [f'<span class="kb-pill">{esc(t)}</span>' for t in item["labels"]]
        also = ""
        if len(item["sources"]) > 1:
            also_links = " · ".join(
                f'<a href="{esc(feeds.safe_url(u))}" target="_blank" rel="noopener noreferrer">{esc(s)}</a>'
                for s, u in item.get("links", {}).items() if feeds.safe_url(u))
            also = f'<div class="kb-card-also">Also covered by: {also_links}</div>'
        html_block(
            f'<div class="kb-card{" kb-card-kev" if kev_cves else ""}">'
            f'<div class="kb-card-meta"><span class="kb-card-src">{esc(" · ".join(item["sources"]))}</span>'
            f'<span>{esc(fmt_dt(item["published"]))}</span></div>'
            f'<div class="kb-card-title">{title_html}</div>'
            f'<div class="kb-card-summary">{esc(item["summary"])}</div>'
            f'<div class="kb-card-chips">{"".join(chips)}</div>{also}</div>'
        )
        saved = item["id"] in st.session_state.saved
        if st.button("★ Saved" if saved else "☆ Save", key=f"save_{item['id']}"):
            if saved:
                st.session_state.saved.discard(item["id"])
            else:
                st.session_state.saved.add(item["id"])
            st.rerun()


# ─────────────────────────────────────────────
#   Footer
# ─────────────────────────────────────────────
html_block(
    f'<div class="kb-footer">{SYSTEM_NAME} {esc(__version__)} · Data: CISA KEV, FIRST EPSS, NVD · '
    f'News mentions are not an asset scan; CISA KEV is the authority on known exploitation</div>'
)
