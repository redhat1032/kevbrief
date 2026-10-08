"""
kevbrief: patch-priority briefing from security news.

Pulls security news feeds, pulls out the CVEs they mention, checks every one
against the CISA Known Exploited Vulnerabilities (KEV) catalog and FIRST EPSS,
and puts the ones to patch first at the top.

Data logic lives in the `kevbrief` package (feeds.py, enrich.py); this file is UI only.
"""

import html
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

from kevbrief import __version__, enrich, feeds

SYSTEM_NAME = "kevbrief"
SYSTEM_TAGLINE = "Patch-priority briefing • CISA KEV • FIRST EPSS • Security news"

st.set_page_config(
    page_title=f"{SYSTEM_NAME} | Patch-priority briefing",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ─────────────────────────────────────────────
#   Styling (dark theme)
# ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto+Mono:wght@400;600&display=swap');

:root {
    --bg: #020509;
    --bg-elevated: #050a12;
    --card: #050a12;
    --border-soft: rgba(255,255,255,0.06);
    --accent: #1ce0ff;
    --accent-soft: rgba(28,224,255,0.18);
    --accent-strong: rgba(28,224,255,0.35);
    --text-main: #f9fbff;
    --text-muted: #8f9bb5;
    --line: rgba(255,255,255,0.06);
    --kev-color: #ff6b35;
    --kev-bg: rgba(255,107,53,0.12);
    --kev-border: rgba(255,107,53,0.4);
}

.stApp {
    background: radial-gradient(circle at top, #07101d 0, #020508 40%, #000000 100%);
    color: var(--text-main);
    font-family: 'Roboto Mono', monospace;
}

h1, h2, h3, h4 {
    font-family: 'Orbitron', sans-serif;
    color: var(--text-main);
}

.kb-shell {
    max-width: 1120px;
    margin: 0 auto 1.5rem auto;
    padding: 18px 22px;
    border-radius: 26px;
    background: radial-gradient(circle at top left, rgba(45,103,255,0.35), transparent 55%),
                linear-gradient(135deg, rgba(3,8,18,0.95), rgba(3,10,22,0.98));
    border: 1px solid var(--border-soft);
    box-shadow: 0 0 40px rgba(0,0,0,0.8), 0 0 60px rgba(28,224,255,0.18);
}

.kb-header-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
}

.kb-title-block { display: flex; flex-direction: column; gap: 4px; }

.kb-title {
    font-family: 'Orbitron', sans-serif;
    font-size: 1.6rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

.kb-subtitle {
    font-size: 0.8rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.16em;
}

.kb-nav-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 14px;
    border-radius: 999px;
    border: 1px solid var(--border-soft);
    background: rgba(3,9,18,0.9);
    color: var(--text-muted);
    font-size: 0.78rem;
    text-decoration: none;
    backdrop-filter: blur(12px);
}

.kb-nav-btn:hover { border-color: var(--accent); color: var(--accent); }

.kb-meta-row {
    margin-top: 12px;
    padding-top: 10px;
    border-top: 1px solid var(--line);
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
}

.kb-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 999px;
    border: 1px solid var(--accent-strong);
    background: var(--accent-soft);
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--accent);
}

.kb-meta-text { font-size: 0.8rem; color: var(--text-muted); }

.news-card {
    border-radius: 18px;
    padding: 14px 16px;
    margin-bottom: 12px;
    background: linear-gradient(135deg, rgba(3,8,16,0.96), rgba(3,12,26,0.98));
    border: 1px solid var(--border-soft);
    box-shadow: 0 0 24px rgba(0,0,0,0.7);
}

.news-card.kev-flagged {
    border-color: var(--kev-border);
    box-shadow: 0 0 24px rgba(0,0,0,0.7), 0 0 16px var(--kev-bg);
}

.kev-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 9px;
    border-radius: 999px;
    border: 1px solid var(--kev-border);
    background: var(--kev-bg);
    color: var(--kev-color);
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: 600;
    margin-bottom: 6px;
}

.news-meta {
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #7c88a0;
    display: flex;
    justify-content: space-between;
}

.news-title {
    font-size: 1.02rem;
    font-weight: 600;
    margin: 6px 0 4px 0;
    color: #f4f7ff;
}

.news-summary { font-size: 0.86rem; color: #c0c7d6; }

.pill {
    display: inline-block;
    padding: 2px 8px;
    margin-right: 4px;
    margin-top: 4px;
    border-radius: 999px;
    border: 1px solid rgba(124,136,160,0.6);
    font-size: .7rem;
    text-transform: uppercase;
    letter-spacing: .06em;
    color: #a7b4d0;
}

.pill-severity-CRITICAL { border-color: #ff0066; color: #ff4d88; }
.pill-severity-HIGH     { border-color: #ff3300; color: #ff704d; }
.pill-severity-MEDIUM   { border-color: #ffaa00; color: #ffcc66; }
.pill-severity-LOW      { border-color: #33cc33; color: #66ff99; }

.feed-health-ok   { color: #66ff99; font-size: 0.75rem; }
.feed-health-fail { color: #ff704d; font-size: 0.75rem; }

.news-sources { font-size: 0.72rem; color: var(--text-muted); margin-top: 6px; }
.news-title a { color: #f4f7ff; text-decoration: none; }
.news-title a:hover { color: var(--accent); }
.kb-section { font-family: 'Orbitron', sans-serif; letter-spacing: 0.06em; text-transform: uppercase;
              font-size: 0.95rem; color: var(--accent); margin: 18px 0 6px 0; }

.footer-text { color: #555; font-size: .72rem; }
.stDownloadButton > button {
    background: rgba(3, 9, 18, 0.9) !important;
    color: var(--text-main) !important;
    border: 1px solid var(--border-soft) !important;
    border-radius: 14px !important;
    font-family: 'Roboto Mono', monospace !important;
}

.stDownloadButton > button:hover {
    border-color: var(--accent) !important;
    color: var(--accent) !important;
    background: rgba(28, 224, 255, 0.06) !important;
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#   Cached data access
# ─────────────────────────────────────────────
@st.cache_data(ttl=600, show_spinner="Fetching security news…")
def get_feeds(names: tuple):
    return feeds.fetch_all({n: feeds.FEEDS[n] for n in names})


@st.cache_data(ttl=3600, show_spinner="Downloading CISA KEV catalog…")
def get_kev():
    return enrich.load_kev()


@st.cache_data(ttl=3600, show_spinner="Fetching EPSS scores…")
def get_epss(cves: tuple):
    return enrich.fetch_epss(cves)


@st.cache_resource
def get_nvd() -> enrich.NvdClient:
    return enrich.NvdClient(os.environ.get("NVD_API_KEY", ""))


def esc(text: Any) -> str:
    return html.escape(str(text or ""), quote=True)


def fmt_dt(d: Any) -> str:
    return d.strftime("%Y-%m-%d %H:%M UTC") if d else "date unknown"


# ─────────────────────────────────────────────
#   Session state (per browser session only)
# ─────────────────────────────────────────────
if "saved" not in st.session_state:
    st.session_state.saved = set()


# ─────────────────────────────────────────────
#   Header
# ─────────────────────────────────────────────
st.markdown(f"""
<div class="kb-shell">
  <div class="kb-header-row">
    <div class="kb-title-block">
      <div class="kb-subtitle">Live tool</div>
      <div class="kb-title">{SYSTEM_NAME}</div>
    </div>
    <a class="kb-nav-btn" href="https://douglasweant.com" target="_self">← douglasweant.com</a>
  </div>
  <div class="kb-meta-row">
    <div class="kb-pill">Patch priority</div>
    <div class="kb-meta-text">{SYSTEM_TAGLINE}</div>
  </div>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#   Sidebar controls
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("### Controls")
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
all_items, health = get_feeds(active)
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


# ─────────────────────────────────────────────
#   Sidebar status (drawn after fetching so it is current)
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("---")
    st.markdown("**Data sources**")
    for name, h in health.items():
        cls, icon = ("feed-health-ok", "●") if h["ok"] else ("feed-health-fail", "✗")
        tip = f"{h['count']} items" if h["ok"] else esc(h["error"])
        st.markdown(f"<span class='{cls}' title='{tip}'>{icon} {esc(name)} ({h['count']})</span>", unsafe_allow_html=True)
    kev_line = (f"<span class='feed-health-ok'>● CISA KEV ({len(kev):,} CVEs)</span>" if kev
                else f"<span class='feed-health-fail' title='{esc(kev_err)}'>✗ CISA KEV unavailable</span>")
    st.markdown(kev_line, unsafe_allow_html=True)
    epss_ok = not epss_err
    st.markdown(f"<span class='{'feed-health-ok' if epss_ok else 'feed-health-fail'}'>"
                f"{'●' if epss_ok else '✗'} FIRST EPSS ({len(epss)} scored)</span>", unsafe_allow_html=True)
    if use_nvd:
        key_note = "API key" if nvd_client.api_key else "no API key, 5 lookups / 30 s"
        st.markdown(f"<span class='feed-health-ok'>● NVD CVSS ({len(nvd)}/{len(all_cves)}, {key_note})</span>",
                    unsafe_allow_html=True)
        if nvd_client.rate_limited:
            st.caption("NVD budget used up; remaining CVSS scores fill in on later reloads. KEV and EPSS are unaffected.")


# ─────────────────────────────────────────────
#   Summary metrics
# ─────────────────────────────────────────────
if not kev:
    st.error("Could not download the CISA KEV catalog, so nothing below is KEV-checked. "
             "Check https://www.cisa.gov/known-exploited-vulnerabilities-catalog directly.")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Articles", len(items))
m2.metric("CVEs mentioned", len(patch_rows))
m3.metric("In CISA KEV", len(kev_rows))
m4.metric("KEV with known ransomware use", sum(1 for r in kev_rows if r["ransomware_use"] == "Known"))


# ─────────────────────────────────────────────
#   Patch these first
# ─────────────────────────────────────────────
st.markdown("<div class='kb-section'>Patch these first</div>", unsafe_allow_html=True)
st.caption("CVEs mentioned in the articles below. KEV-listed first (known ransomware use, then newest additions), "
           "then by EPSS exploit probability. KEV due dates are the deadlines CISA sets for US federal agencies; "
           "treat them as an outer limit, not a target.")

patch_df = pd.DataFrame(patch_rows)
if patch_df.empty:
    st.info("No CVEs mentioned in the current selection. Widen the time window or sources.")
else:
    view = patch_df.assign(
        kev=patch_df["in_kev"].map({True: "KEV", False: ""}),
        epss_pct=patch_df["epss"].map(lambda v: v * 100 if pd.notna(v) else None),
    )[["cve", "kev", "kev_due_date", "ransomware_use", "epss_pct", "cvss", "vendor_product", "mentioned_by", "nvd_url"]]
    st.dataframe(
        view,
        hide_index=True,
        width="stretch",
        column_config={
            "cve": st.column_config.TextColumn("CVE"),
            "kev": st.column_config.TextColumn("KEV"),
            "kev_due_date": st.column_config.TextColumn("KEV due date"),
            "ransomware_use": st.column_config.TextColumn("Ransomware use"),
            "epss_pct": st.column_config.NumberColumn("EPSS", format="%.1f%%",
                                                      help="FIRST EPSS: probability of exploitation in the next 30 days"),
            "cvss": st.column_config.NumberColumn("CVSS", format="%.1f"),
            "vendor_product": st.column_config.TextColumn("Vendor / product (KEV)"),
            "mentioned_by": st.column_config.TextColumn("Mentioned by"),
            "nvd_url": st.column_config.LinkColumn("NVD", display_text="details"),
        },
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
            epss_s = f"{r['epss'] * 100:.1f}%" if r["epss"] is not None else ""
            cvss_s = f"{r['cvss']}" if r["cvss"] is not None else ""
            cells = [r["cve"], "yes" if r["in_kev"] else "", r["kev_due_date"], r["ransomware_use"], epss_s, cvss_s,
                     r["vendor_product"], r["mentioned_by"]]
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


if items or patch_rows:
    c1, c2, c3, _ = st.columns([1, 1, 1, 3])
    with c1:
        st.download_button("⬇️ Patch table CSV", patch_df.to_csv(index=False).encode("utf-8") if not patch_df.empty else b"",
                           file_name="kevbrief_patch_priority.csv", mime="text/csv", disabled=patch_df.empty)
    with c2:
        st.download_button("⬇️ Briefing Markdown", briefing_markdown(),
                           file_name="kevbrief_briefing.md", mime="text/markdown")
    with c3:
        art_df = pd.DataFrame([{
            "published": fmt_dt(i["published"]), "sources": ", ".join(i["sources"]), "title": i["title"],
            "link": i["link"], "labels": ", ".join(i["labels"]), "cves": ", ".join(i["cves"]),
            "kev_cves": ", ".join(c for c in i["cves"] if c in kev),
        } for i in items])
        st.download_button("⬇️ Articles CSV", art_df.to_csv(index=False).encode("utf-8"),
                           file_name="kevbrief_articles.csv", mime="text/csv")

st.markdown("---")


# ─────────────────────────────────────────────
#   Supporting coverage
# ─────────────────────────────────────────────
st.markdown("<div class='kb-section'>Supporting coverage</div>", unsafe_allow_html=True)
if not items:
    st.info("No articles matched the current filters.")
else:
    st.caption(f"{len(items)} articles, KEV-related and highest-EPSS first. Duplicate stories across sources are merged.")
    for item in items:
        kev_cves = [c for c in item["cves"] if c in kev]
        kev_class = "kev-flagged" if kev_cves else ""
        kev_badge = f'<div class="kev-badge">⚠ CISA KEV: {esc(", ".join(kev_cves))}</div>' if kev_cves else ""
        link = feeds.safe_url(item["link"])
        title_html = f'<a href="{esc(link)}" target="_blank" rel="noopener noreferrer">{esc(item["title"])}</a>' if link else esc(item["title"])
        source_links = " · ".join(
            f'<a href="{esc(feeds.safe_url(u))}" target="_blank" rel="noopener noreferrer">{esc(s)}</a>'
            for s, u in item.get("links", {}).items() if feeds.safe_url(u)
        )
        st.markdown(f"""
<div class="news-card {kev_class}">
  {kev_badge}
  <div class="news-meta">
    <span>{esc(", ".join(item["sources"]))}</span>
    <span>{esc(fmt_dt(item["published"]))}</span>
  </div>
  <div class="news-title">{title_html}</div>
  <div class="news-summary">{esc(item["summary"])}</div>
  {f'<div class="news-sources">Also covered by: {source_links}</div>' if len(item["sources"]) > 1 else ''}
</div>
""", unsafe_allow_html=True)

        pills = [f"<span class='pill'>{esc(t)}</span>" for t in item["labels"]]
        for c in item["cves"]:
            n = nvd.get(c) or {}
            sev = n.get("severity", "")
            cls = f" pill-severity-{esc(sev)}" if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else ""
            parts = [c]
            if c in kev:
                parts.append("KEV")
            if c in epss:
                parts.append(f"EPSS {epss[c]['epss'] * 100:.1f}%")
            if n.get("cvss") is not None:
                parts.append(f"CVSS {n['cvss']}")
            pills.append(f"<span class='pill{cls}'>{esc(' • '.join(parts))}</span>")
        st.markdown(" ".join(pills), unsafe_allow_html=True)

        saved = item["id"] in st.session_state.saved
        if st.button("★ Saved" if saved else "☆ Save", key=f"save_{item['id']}"):
            if saved:
                st.session_state.saved.discard(item["id"])
            else:
                st.session_state.saved.add(item["id"])
            st.rerun()
        st.markdown("<br/>", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#   Footer
# ─────────────────────────────────────────────
st.markdown("---")
st.markdown(
    f"<center class='footer-text'>{SYSTEM_NAME} {__version__} • News mentions are not an asset scan; "
    f"CISA KEV is the authority on known exploitation • EPSS by FIRST.org</center>",
    unsafe_allow_html=True,
)
