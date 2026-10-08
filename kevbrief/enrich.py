"""CVE enrichment: CISA KEV (authoritative), FIRST EPSS, and optional, paced NVD CVSS lookups.

Nothing in this module imports Streamlit, so it can be tested on its own.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import requests

from .feeds import USER_AGENT

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{}"

_HEADERS = {"User-Agent": USER_AGENT}


# ─────────────────────────────────────────────
#   CISA KEV
# ─────────────────────────────────────────────
def parse_kev(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for v in payload.get("vulnerabilities", []) or []:
        cve = (v.get("cveID") or "").strip().upper()
        if not cve:
            continue
        out[cve] = {
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown") or "Unknown",
            "required_action": v.get("requiredAction", ""),
        }
    return out


def load_kev(timeout: float = 20) -> Tuple[Dict[str, Dict[str, Any]], Optional[str]]:
    """Download the full KEV catalog once. Returns (cve -> entry, error or None)."""
    try:
        r = requests.get(KEV_URL, timeout=timeout, headers=_HEADERS)
        r.raise_for_status()
        kev = parse_kev(r.json())
        return kev, None if kev else "KEV catalog was empty"
    except Exception as e:
        return {}, f"{type(e).__name__}: {e}"[:200]


# ─────────────────────────────────────────────
#   FIRST EPSS (public, no key)
# ─────────────────────────────────────────────
def parse_epss(payload: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
    out: Dict[str, Dict[str, float]] = {}
    for row in payload.get("data", []) or []:
        try:
            out[row["cve"].upper()] = {
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
                "date": row.get("date", ""),
            }
        except (KeyError, TypeError, ValueError):
            continue
    return out


def fetch_epss(cves: Iterable[str], chunk: int = 50, timeout: float = 15) -> Tuple[Dict[str, Dict[str, float]], Optional[str]]:
    """Batch-query EPSS. Returns (cve -> score, error or None). Partial results survive errors."""
    ids = sorted({c.upper() for c in cves})
    out: Dict[str, Dict[str, float]] = {}
    err: Optional[str] = None
    for i in range(0, len(ids), chunk):
        batch = ids[i:i + chunk]
        try:
            r = requests.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=timeout, headers=_HEADERS)
            r.raise_for_status()
            out.update(parse_epss(r.json()))
        except Exception as e:
            err = f"{type(e).__name__}: {e}"[:200]
    return out, err


# ─────────────────────────────────────────────
#   NVD (optional, rate limited)
# ─────────────────────────────────────────────
def parse_nvd(payload: Dict[str, Any]) -> Dict[str, Any]:
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return {}
    metrics = vulns[0].get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            data = m.get("cvssData", {})
            sev = data.get("baseSeverity") or m.get("baseSeverity") or ""
            return {"cvss": data.get("baseScore"), "severity": sev.upper(), "cvss_version": data.get("version", "")}
    return {}


class NvdClient:
    """Non-blocking NVD lookups inside NVD's published rolling limits.

    NVD allows 5 requests per 30 s without an API key and 50 with one. Instead of
    sleeping (which freezes the page), lookups beyond the budget return None and are
    retried on a later page load. A 403/429 pauses all lookups for one window.
    Successful results are cached for the life of the process.
    """

    WINDOW = 30.0

    def __init__(self, api_key: str = "", clock: Callable[[], float] = time.monotonic,
                 getter: Callable[..., Any] = requests.get) -> None:
        self.api_key = api_key
        self.limit = 50 if api_key else 5
        self._clock = clock
        self._get = getter
        self._calls: deque = deque()
        self._blocked_until = 0.0
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.rate_limited = False

    def _take_slot(self) -> bool:
        with self._lock:
            now = self._clock()
            if now < self._blocked_until:
                return False
            while self._calls and now - self._calls[0] >= self.WINDOW:
                self._calls.popleft()
            if len(self._calls) >= self.limit:
                return False
            self._calls.append(now)
            return True

    def lookup(self, cve: str) -> Optional[Dict[str, Any]]:
        cve = cve.upper()
        if cve in self._cache:
            return self._cache[cve]
        if not self._take_slot():
            self.rate_limited = True
            return None
        headers = dict(_HEADERS)
        if self.api_key:
            headers["apiKey"] = self.api_key
        try:
            r = self._get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=10)
        except Exception:
            return None
        if r.status_code in (403, 429):
            with self._lock:
                self._blocked_until = self._clock() + self.WINDOW
            self.rate_limited = True
            return None
        if not r.ok:
            return None
        try:
            result = parse_nvd(r.json())
        except ValueError:
            return None
        self._cache[cve] = result
        return result

    def lookup_many(self, cves: Iterable[str]) -> Dict[str, Dict[str, Any]]:
        self.rate_limited = False
        out: Dict[str, Dict[str, Any]] = {}
        for c in cves:
            res = self.lookup(c)
            if res is not None:
                out[c.upper()] = res
        return out


# ─────────────────────────────────────────────
#   Priority
# ─────────────────────────────────────────────
def cve_priority_key(cve: str, kev: Dict[str, Dict[str, Any]], epss: Dict[str, Dict[str, float]],
                     nvd: Optional[Dict[str, Dict[str, Any]]] = None) -> Tuple:
    """Lower sorts first: KEV (ransomware-linked first, newest additions first), then EPSS, then CVSS."""
    nvd = nvd or {}
    k = kev.get(cve)
    e = (epss.get(cve) or {}).get("epss")
    c = (nvd.get(cve) or {}).get("cvss")
    added = k["date_added"] if k else ""
    return (
        0 if k else 1,
        0 if k and k.get("ransomware") == "Known" else 1,
        _neg_date(added),
        -(e if e is not None else -1.0),
        -(c if c is not None else -1.0),
        cve,
    )


def _neg_date(iso: str) -> str:
    # Sort newer YYYY-MM-DD first by inverting digits.
    return "".join(chr(ord("9") - ord(ch) + ord("0")) if ch.isdigit() else ch for ch in iso) if iso else "~"


def build_patch_table(items: List[Dict[str, Any]], kev: Dict[str, Dict[str, Any]],
                      epss: Dict[str, Dict[str, float]],
                      nvd: Optional[Dict[str, Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """One row per CVE mentioned in `items`, sorted so the first rows are the ones to patch first."""
    nvd = nvd or {}
    mentions: Dict[str, Dict[str, Any]] = {}
    for it in items:
        for cve in it.get("cves", []):
            m = mentions.setdefault(cve, {"sources": set(), "articles": 0})
            m["sources"].update(it.get("sources", []))
            m["articles"] += 1
    rows = []
    for cve in sorted(mentions, key=lambda c: cve_priority_key(c, kev, epss, nvd)):
        k = kev.get(cve) or {}
        e = epss.get(cve) or {}
        n = nvd.get(cve) or {}
        rows.append({
            "cve": cve,
            "in_kev": bool(k),
            "kev_date_added": k.get("date_added", ""),
            "kev_due_date": k.get("due_date", ""),
            "ransomware_use": k.get("ransomware", "") if k else "",
            "vendor_product": " ".join(x for x in (k.get("vendor"), k.get("product")) if x),
            "kev_name": k.get("name", ""),
            "required_action": k.get("required_action", ""),
            "epss": e.get("epss"),
            "epss_percentile": e.get("percentile"),
            "cvss": n.get("cvss"),
            "severity": n.get("severity", ""),
            "mentioned_by": ", ".join(sorted(mentions[cve]["sources"])),
            "articles": mentions[cve]["articles"],
            "nvd_url": NVD_DETAIL_URL.format(cve),
        })
    return rows


def item_priority_key(item: Dict[str, Any], kev: Dict[str, Dict[str, Any]],
                      epss: Dict[str, Dict[str, float]]) -> Tuple:
    """Article sort: KEV-related first, then highest EPSS, then any CVE, then newest."""
    cves = item.get("cves", [])
    in_kev = any(c in kev for c in cves)
    top_epss = max(((epss.get(c) or {}).get("epss") or 0.0 for c in cves), default=0.0)
    ts = item["published"].timestamp() if item.get("published") else 0.0
    return (0 if in_kev else 1, -top_epss, 0 if cves else 1, -ts)
