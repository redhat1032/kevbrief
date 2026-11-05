"""Offline smoke test: the Streamlit page renders from fixtures with no network access."""
from pathlib import Path

from streamlit.testing.v1 import AppTest

from conftest import fixture_bytes
from kevbrief import enrich, feeds

APP = str(Path(__file__).resolve().parents[1] / "app.py")


def test_app_renders_offline(monkeypatch):
    raw = (feeds.parse_feed("The Hacker News", fixture_bytes("thehackernews_rss.xml"))
           + feeds.parse_feed("BleepingComputer", fixture_bytes("bleepingcomputer_rss.xml")))
    health = {n: {"ok": True, "count": 1, "error": None} for n in feeds.FEEDS}
    kev = {"CVE-2026-88779": {"date_added": "2026-10-07", "due_date": "2026-10-28", "vendor": "Citrix",
                              "product": "NetScaler", "name": "x", "ransomware": "Unknown", "required_action": "x"}}
    monkeypatch.setattr(feeds, "fetch_all", lambda f: (feeds.dedupe([dict(i) for i in raw]), health))
    monkeypatch.setattr(enrich, "load_kev", lambda: (kev, None))
    monkeypatch.setattr(enrich, "fetch_epss", lambda c: ({"CVE-2026-88779": {"epss": 0.5, "percentile": 0.9}}, None))
    monkeypatch.setattr(enrich.NvdClient, "lookup", lambda self, c: None)

    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    at.sidebar.selectbox[0].set_value("All").run()
    assert not at.exception, [e.value for e in at.exception]
    html = " ".join(m.value for m in at.markdown)
    # stat card and designed patch table (no st.dataframe / st.metric any more)
    assert '<div class="kb-stat-label">In CISA KEV</div><div class="kb-stat-value">1</div>' in html
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2026-88779"' in html
    assert '<span class="kb-date">2026-10-28</span>' in html
    assert "Citrix NetScaler" in html and ">None<" not in html
    assert not at.dataframe
    # top-right site link, no email address anywhere
    assert 'class="kb-site" href="https://douglasweant.com"' in html
    assert "@" not in html.split("</style>", 1)[1]
    assert "<script>" not in html and "onerror" not in html
