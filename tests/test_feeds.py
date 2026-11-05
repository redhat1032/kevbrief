from datetime import datetime, timezone

from conftest import fixture_bytes
from kevbrief import feeds


# ── Dates ──────────────────────────────────────────────────────────────
def test_schneier_atom_iso_dates_are_parsed_not_1970():
    items = feeds.parse_feed("Schneier on Security", fixture_bytes("schneier_atom.xml"))
    assert len(items) == 2
    # Recorded feed: <published>2026-10-08T11:07:35Z</published>
    assert items[0]["published"] == datetime(2026, 10, 8, 11, 7, 35, tzinfo=timezone.utc)
    assert all(i["published"].year == 2026 for i in items)


def test_rss_dates_with_offset_are_converted_to_utc():
    items = feeds.parse_feed("SecurityWeek", fixture_bytes("securityweek_rss.xml"))
    assert items[0]["published"] == datetime(2026, 10, 8, 15, 28, 6, tzinfo=timezone.utc)


def test_missing_date_is_none_not_epoch():
    xml = b"<rss version='2.0'><channel><item><title>x</title><link>https://a.example/x</link></item></channel></rss>"
    assert feeds.parse_feed("t", xml)[0]["published"] is None


# ── Tags ───────────────────────────────────────────────────────────────
def test_partial_words_do_not_trigger_tags():
    for text in ["New laws on cookie banners", "William Smith joins board", "Miami hospital outage",
                 "Entrance exam scores", "Encryption best practices", "Employee benefits portal redesign",
                 "Firmware update released for printers", "Strategic pivot announced"]:
        assert feeds.label_article(text) == ["General"], text


def test_whole_words_still_tag():
    assert "Cloud / IAM" in feeds.label_article("AWS IAM keys leaked")
    assert "Ransomware" in feeds.label_article("LockBit ransomware returns")
    assert "Patch Now" in feeds.label_article("Microsoft patches zero-day")
    assert "Vulnerabilities" in feeds.label_article("Details of CVE-2026-1234 published")


def test_cve_extraction_dedupes_and_uppercases():
    assert feeds.extract_cves("cve-2026-1234 and CVE-2026-1234, CVE-2025-123456") == ["CVE-2025-123456", "CVE-2026-1234"]


# ── HTML stripping ─────────────────────────────────────────────────────
def test_strip_html_removes_tags_scripts_and_decodes_entities():
    raw = '<p>Citrix fixed <b>CVE-1</b> in ADC &amp; Gateway.</p><script>alert(1)</script><img src=x onerror="alert(2)">'
    out = feeds.strip_html(raw)
    assert out == "Citrix fixed CVE-1 in ADC & Gateway."
    assert "<" not in out and "alert" not in out


def test_parsed_items_have_plain_text_title_and_summary():
    items = feeds.parse_feed("The Hacker News", fixture_bytes("thehackernews_rss.xml"))
    citrix = items[0]
    assert "<" not in citrix["summary"] and "alert" not in citrix["summary"]
    assert citrix["cves"] == ["CVE-2026-88779"]


def test_wordpress_footer_is_removed():
    items = feeds.parse_feed("SecurityWeek", fixture_bytes("securityweek_rss.xml"))
    assert "appeared first on" not in items[0]["summary"]
    assert items[0]["summary"].startswith("The security defects could lead")


def test_summary_is_truncated_on_a_word_boundary():
    out = feeds.strip_html("word " * 200, max_len=50)
    assert len(out) <= 51 and out.endswith("…") and not out.endswith(" …")


def test_safe_url_rejects_non_http():
    assert feeds.safe_url("javascript:alert(1)") == ""
    assert feeds.safe_url("https://a.example/") == "https://a.example/"


# ── De-duplication ─────────────────────────────────────────────────────
def test_normalize_link_ignores_scheme_www_tracking_and_fragment():
    a = feeds.normalize_link("https://www.Example.com/a/b/?utm_source=rss&id=7#top")
    b = feeds.normalize_link("http://example.com/a/b?id=7")
    assert a == b == "example.com/a/b?id=7"


def test_normalize_title_ignores_case_and_punctuation():
    assert feeds.normalize_title("Citrix Patches Flaw (CVE-1)!") == feeds.normalize_title("citrix patches flaw — cve 1")


def test_dedupe_merges_same_story_across_sources():
    thn = feeds.parse_feed("The Hacker News", fixture_bytes("thehackernews_rss.xml"))
    bc = feeds.parse_feed("BleepingComputer", fixture_bytes("bleepingcomputer_rss.xml"))
    merged = feeds.dedupe(thn + bc)
    # 5 raw items -> 2 stories: Citrix (same title) and hospital (same title + same link)
    assert len(merged) == 2
    by_title = {m["title"]: m for m in merged}
    citrix = next(m for t, m in by_title.items() if "Citrix" in t)
    hospital = next(m for t, m in by_title.items() if "hospital" in t.lower())
    assert citrix["sources"] == ["The Hacker News", "BleepingComputer"]  # earliest report kept first
    assert citrix["cves"] == ["CVE-2026-88779"]
    assert set(hospital["sources"]) == {"The Hacker News", "BleepingComputer"}
    assert "Patch Now" in citrix["labels"]  # merged from BleepingComputer's text


def test_dedupe_sorts_newest_first_with_undated_last():
    t = lambda h: datetime(2026, 1, 1, h, tzinfo=timezone.utc)
    mk = lambda title, pub: {"title": title, "link": f"https://x.example/{title}", "published": pub,
                             "sources": ["s"], "links": {}, "labels": ["General"], "cves": [], "summary": ""}
    out = feeds.dedupe([mk("a", t(1)), mk("b", None), mk("c", t(5))])
    assert [i["title"] for i in out] == ["c", "a", "b"]


# ── Network isolation ──────────────────────────────────────────────────
def test_fetch_all_isolates_a_failing_feed(monkeypatch):
    class Resp:
        def __init__(self, content, status=200):
            self.content, self.status_code = content, status

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")

    def fake_get(url, **kw):
        assert kw.get("timeout")
        return Resp(b"", 404) if "dead" in url else Resp(fixture_bytes("securityweek_rss.xml"))

    monkeypatch.setattr(feeds.requests, "get", fake_get)
    items, health = feeds.fetch_all({"Good": "https://good.example/feed", "Dead": "https://dead.example/feed"})
    assert len(items) == 2
    assert health["Good"]["ok"] and not health["Dead"]["ok"]
    assert "404" in health["Dead"]["error"]
