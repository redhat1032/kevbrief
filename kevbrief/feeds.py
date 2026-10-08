"""Fetch, clean, tag and de-duplicate security news feeds.

Nothing in this module imports Streamlit, so it can be tested on its own.
"""

from __future__ import annotations

import calendar
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit

import feedparser
import requests

from . import __version__

USER_AGENT = f"kevbrief/{__version__} (+https://github.com/redhat1032/kevbrief)"
FETCH_TIMEOUT = 15  # seconds per feed

FEEDS: Dict[str, str] = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "SANS ISC": "https://isc.sans.edu/rssfeed_full.xml",
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
}

# Whole-word / whole-phrase keywords only. Keep these specific: broad words
# such as "update" or "employee" tag almost every article.
TAG_KEYWORDS: Dict[str, List[str]] = {
    "Ransomware": ["ransomware", "ransom", "lockbit", "extortion", "akira", "qilin", "black basta"],
    "Supply Chain": ["supply chain", "supply-chain", "npm", "pypi", "dependency confusion", "solarwinds"],
    "Cloud / IAM": ["aws", "azure", "gcp", "iam", "entra", "okta", "sso", "oauth", "identity provider"],
    "Patch Now": ["patch", "patches", "patched", "zero-day", "zero-days", "0-day", "out-of-band",
                  "actively exploited", "kev", "emergency update", "security update", "security updates"],
    "Malware": ["malware", "trojan", "botnet", "infostealer", "stealer", "backdoor", "rat", "loader"],
    "Vulnerabilities": ["vulnerability", "vulnerabilities", "flaw", "flaws", "rce",
                        "remote code execution", "privilege escalation", "authentication bypass"],
    "Insider Threat": ["insider", "insider threat", "insiders", "data exfiltration", "rogue employee"],
}

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

_TAG_PATTERNS = {
    tag: re.compile(r"(?<![\w-])(?:" + "|".join(re.escape(k) for k in kws) + r")(?![\w-])", re.IGNORECASE)
    for tag, kws in TAG_KEYWORDS.items()
}

_BLOCK_TAGS = {"p", "br", "div", "li", "ul", "ol", "h1", "h2", "h3", "h4", "h5", "h6",
               "tr", "td", "th", "table", "blockquote", "pre", "section", "article", "figure"}
_SKIP_TAGS = {"script", "style", "noscript", "iframe", "svg"}
# WordPress feeds append "The post <title> appeared first on <site>." to every summary.
_WP_FOOTER_RE = re.compile(r"\s*The post .{0,400}? appeared first on .{0,120}?\.?\s*$", re.DOTALL)
_TRACKING_PARAMS = {"ref", "source", "src", "rss", "feed", "cmp", "mc_cid", "mc_eid", "fbclid", "gclid"}


# ─────────────────────────────────────────────
#   Text cleaning
# ─────────────────────────────────────────────
class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in _SKIP_TAGS:
            self._skip += 1
        elif tag in _BLOCK_TAGS:
            self.parts.append(" ")

    def handle_startendtag(self, tag: str, attrs: Any) -> None:
        if tag in _BLOCK_TAGS:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS:
            self._skip = max(0, self._skip - 1)
        elif tag in _BLOCK_TAGS:
            self.parts.append(" ")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def strip_html(text: Optional[str], max_len: Optional[int] = None) -> str:
    """Return plain text: tags removed, entities decoded, whitespace collapsed.

    The result is plain text, not safe HTML. Escape it before putting it in markup.
    """
    if not text:
        return ""
    parser = _TextExtractor()
    try:
        parser.feed(text)
        parser.close()
        out = "".join(parser.parts)
    except Exception:  # malformed markup: fall back to a crude strip
        out = re.sub(r"<[^>]*>", " ", text)
    out = re.sub(r"\s+", " ", out).strip()
    out = _WP_FOOTER_RE.sub("", out).strip()
    if max_len and len(out) > max_len:
        cut = out[:max_len].rsplit(" ", 1)[0].rstrip(" ,;:.-")
        out = cut + "…"
    return out


def normalize_title(title: str) -> str:
    """Lower-case, punctuation-free title used to spot the same story across feeds."""
    text = strip_html(title).lower()
    text = re.sub(r"[^\w\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def normalize_link(url: str) -> str:
    """Scheme-less, www-less link with tracking parameters and fragments removed."""
    if not url:
        return ""
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = parts.path.rstrip("/") or "/"
    query = [
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith("utm_") and k.lower() not in _TRACKING_PARAMS
    ]
    q = urlencode(sorted(query))
    return f"{host}{path}" + (f"?{q}" if q else "")


def safe_url(url: str) -> str:
    """Only allow http(s) links through to the UI."""
    return url if urlsplit(url or "").scheme in ("http", "https") else ""


# ─────────────────────────────────────────────
#   Per-entry helpers
# ─────────────────────────────────────────────
def entry_datetime(entry: Any) -> Optional[datetime]:
    """Timezone-aware UTC publish time from feedparser's parsed dates (RSS or Atom)."""
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        t = entry.get(key)
        if t:
            try:
                return datetime.fromtimestamp(calendar.timegm(t), tz=timezone.utc)
            except (OverflowError, ValueError, TypeError):
                continue
    return None


def label_article(title: str, summary: str = "") -> List[str]:
    text = f"{title} {summary}"
    labels = [tag for tag, pat in _TAG_PATTERNS.items() if pat.search(text)]
    if CVE_RE.search(text) and "Vulnerabilities" not in labels:
        labels.append("Vulnerabilities")
    return labels or ["General"]


def extract_cves(text: str) -> List[str]:
    return sorted({m.upper() for m in CVE_RE.findall(text or "")})


def parse_feed(name: str, content: Any) -> List[Dict[str, Any]]:
    """Turn raw feed bytes/text into clean item dicts."""
    parsed = feedparser.parse(content)
    items: List[Dict[str, Any]] = []
    for e in parsed.entries:
        title = strip_html(e.get("title", ""))
        link = (e.get("link") or "").strip()
        if not (title and link):
            continue
        raw_summary = e.get("summary") or e.get("description") or ""
        full_summary = strip_html(raw_summary)
        published = entry_datetime(e)
        items.append({
            "id": hashlib.sha1(normalize_link(link).encode()).hexdigest()[:16],
            "title": title,
            "link": link,
            "summary": strip_html(raw_summary, max_len=420),
            "published": published,
            "sources": [name],
            "links": {name: link},
            "labels": label_article(title, full_summary),
            "cves": extract_cves(f"{title} {full_summary}"),
        })
    return items


# ─────────────────────────────────────────────
#   De-duplication
# ─────────────────────────────────────────────
_MIN_DT = datetime.min.replace(tzinfo=timezone.utc)


def _sort_key_newest(item: Dict[str, Any]) -> datetime:
    return item.get("published") or _MIN_DT


def dedupe(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge items that share a normalized link or a normalized title.

    The earliest-published copy is kept; sources, links, labels and CVEs are merged.
    Result is sorted newest first, undated items last.
    """
    ordered = sorted(items, key=lambda i: (i.get("published") is None, i.get("published") or _MIN_DT))
    by_link: Dict[str, Dict[str, Any]] = {}
    by_title: Dict[str, Dict[str, Any]] = {}
    out: List[Dict[str, Any]] = []
    for item in ordered:
        lk, tk = normalize_link(item["link"]), normalize_title(item["title"])
        existing = (lk and by_link.get(lk)) or (tk and by_title.get(tk))
        if existing:
            for s in item["sources"]:
                if s not in existing["sources"]:
                    existing["sources"].append(s)
            for s, url in item.get("links", {}).items():
                existing.setdefault("links", {}).setdefault(s, url)
            existing["labels"] = _merge_labels(existing["labels"], item["labels"])
            existing["cves"] = sorted(set(existing["cves"]) | set(item["cves"]))
            if len(item.get("summary", "")) > len(existing.get("summary", "")):
                existing["summary"] = item["summary"]
            target = existing
        else:
            target = dict(item, sources=list(item["sources"]), links=dict(item.get("links", {})))
            out.append(target)
        if lk:
            by_link.setdefault(lk, target)
        if tk:
            by_title.setdefault(tk, target)
    out.sort(key=_sort_key_newest, reverse=True)
    return out


def _merge_labels(a: List[str], b: List[str]) -> List[str]:
    merged = [x for x in a if x != "General"] + [x for x in b if x != "General" and x not in a]
    return merged or ["General"]


# ─────────────────────────────────────────────
#   Network
# ─────────────────────────────────────────────
def fetch_feed(name: str, url: str, timeout: float = FETCH_TIMEOUT) -> Tuple[str, List[Dict[str, Any]], Optional[str]]:
    """Fetch one feed. Returns (name, items, error message or None). Never raises."""
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
        items = parse_feed(name, r.content)
        return name, items, None if items else "feed returned no entries"
    except Exception as e:  # network, HTTP or parse failure: isolate per feed
        return name, [], f"{type(e).__name__}: {e}"[:200]


def fetch_all(feeds: Dict[str, str]) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Fetch feeds concurrently, then de-duplicate. Returns (items, health)."""
    if not feeds:
        return [], {}
    raw: List[Dict[str, Any]] = []
    health: Dict[str, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(8, len(feeds))) as pool:
        for name, items, err in pool.map(lambda kv: fetch_feed(*kv), feeds.items()):
            health[name] = {"ok": err is None, "count": len(items), "error": err}
            raw.extend(items)
    return dedupe(raw), health
