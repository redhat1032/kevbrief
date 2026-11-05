from datetime import datetime, timezone

from kevbrief import enrich

KEV_PAYLOAD = {"vulnerabilities": [
    {"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "VPN", "dateAdded": "2026-10-01",
     "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Unknown", "vulnerabilityName": "Acme VPN RCE",
     "requiredAction": "Apply updates"},
    {"cveID": "CVE-2026-0002", "vendorProject": "Acme", "product": "Mail", "dateAdded": "2026-09-01",
     "dueDate": "2026-09-22", "knownRansomwareCampaignUse": "Known", "vulnerabilityName": "Acme Mail RCE",
     "requiredAction": "Apply updates"},
]}
EPSS_PAYLOAD = {"status": "OK", "data": [
    {"cve": "CVE-2026-0001", "epss": "0.12", "percentile": "0.9", "date": "2026-10-08"},
    {"cve": "CVE-2026-0003", "epss": "0.80", "percentile": "0.99", "date": "2026-10-08"},
    {"cve": "CVE-2026-0004", "epss": "0.01", "percentile": "0.2", "date": "2026-10-08"},
]}


def _item(title, cves, sources, hour=0):
    return {"title": title, "cves": cves, "sources": sources,
            "published": datetime(2026, 10, 8, hour, tzinfo=timezone.utc)}


def test_parse_kev_and_epss():
    kev = enrich.parse_kev(KEV_PAYLOAD)
    assert kev["CVE-2026-0001"]["due_date"] == "2026-10-22"
    assert kev["CVE-2026-0002"]["ransomware"] == "Known"
    epss = enrich.parse_epss(EPSS_PAYLOAD)
    assert epss["CVE-2026-0003"]["epss"] == 0.80


def test_every_item_is_kev_checked_not_just_the_first_40():
    kev = enrich.parse_kev(KEV_PAYLOAD)
    items = [_item(f"filler {n}", [], ["s"]) for n in range(100)]
    items.append(_item("late KEV story", ["CVE-2026-0001"], ["Late Feed"]))
    rows = enrich.build_patch_table(items, kev, {})
    assert rows[0]["cve"] == "CVE-2026-0001" and rows[0]["in_kev"]
    assert rows[0]["mentioned_by"] == "Late Feed"


def test_patch_table_order_and_columns():
    kev = enrich.parse_kev(KEV_PAYLOAD)
    epss = enrich.parse_epss(EPSS_PAYLOAD)
    items = [
        _item("a", ["CVE-2026-0003", "CVE-2026-0004"], ["Feed A"]),
        _item("b", ["CVE-2026-0001"], ["Feed A"]),
        _item("c", ["CVE-2026-0001", "CVE-2026-0002"], ["Feed B"]),
        _item("d", ["CVE-2026-0005"], ["Feed C"]),
    ]
    rows = enrich.build_patch_table(items, kev, epss)
    # KEV + known ransomware, then KEV newest, then highest EPSS, then lower EPSS, then unscored
    assert [r["cve"] for r in rows] == ["CVE-2026-0002", "CVE-2026-0001", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"]
    top = rows[1]
    assert top["kev_due_date"] == "2026-10-22"
    assert top["epss"] == 0.12
    assert top["mentioned_by"] == "Feed A, Feed B" and top["articles"] == 2
    assert rows[4]["epss"] is None and not rows[4]["in_kev"]


def test_item_priority_puts_kev_articles_first():
    kev = enrich.parse_kev(KEV_PAYLOAD)
    epss = enrich.parse_epss(EPSS_PAYLOAD)
    items = [_item("news", [], ["s"], hour=23), _item("epss", ["CVE-2026-0003"], ["s"], hour=5),
             _item("kev", ["CVE-2026-0001"], ["s"], hour=1)]
    items.sort(key=lambda i: enrich.item_priority_key(i, kev, epss))
    assert [i["title"] for i in items] == ["kev", "epss", "news"]


def test_fetch_epss_batches_and_survives_errors(monkeypatch):
    calls = []

    class Resp:
        def __init__(self, payload):
            self.payload = payload

        def raise_for_status(self):
            pass

        def json(self):
            return self.payload

    def fake_get(url, params=None, **kw):
        calls.append(params["cve"])
        if len(calls) == 2:
            raise TimeoutError("boom")
        return Resp(EPSS_PAYLOAD)

    monkeypatch.setattr(enrich.requests, "get", fake_get)
    out, err = enrich.fetch_epss([f"CVE-2026-{n:04d}" for n in range(1, 121)], chunk=50)
    assert len(calls) == 3
    assert "CVE-2026-0003" in out and err and "boom" in err


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class NvdResp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self.ok = status < 400
        self._payload = payload or {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "version": "3.1"}}]}}}]}

    def json(self):
        return self._payload


def test_nvd_budget_without_key_is_five_per_window_and_never_sleeps():
    clock, calls = FakeClock(), []
    client = enrich.NvdClient("", clock=clock, getter=lambda *a, **k: calls.append(1) or NvdResp())
    got = client.lookup_many([f"CVE-2026-{n:04d}" for n in range(10)])
    assert len(got) == 5 and len(calls) == 5 and client.rate_limited
    assert got["CVE-2026-0000"] == {"cvss": 9.8, "severity": "CRITICAL", "cvss_version": "3.1"}
    # cached results cost nothing; new ones wait for the window to roll
    assert client.lookup("CVE-2026-0000")["cvss"] == 9.8 and len(calls) == 5
    clock.t += 31
    assert client.lookup("CVE-2026-0007") is not None and len(calls) == 6


def test_nvd_403_pauses_lookups_for_a_window():
    clock, calls = FakeClock(), []
    client = enrich.NvdClient("key", clock=clock, getter=lambda *a, **k: calls.append(1) or NvdResp(403))
    assert client.lookup("CVE-2026-0001") is None
    assert client.lookup("CVE-2026-0002") is None
    assert len(calls) == 1 and client.rate_limited
    clock.t += 31
    client.lookup("CVE-2026-0003")
    assert len(calls) == 2


def test_parse_nvd_prefers_newest_cvss():
    payload = {"vulnerabilities": [{"cve": {"metrics": {
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "version": "2.0"}, "baseSeverity": "MEDIUM"}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "version": "3.1"}}]}}}]}
    assert enrich.parse_nvd(payload)["cvss"] == 7.5
    assert enrich.parse_nvd({"vulnerabilities": []}) == {}
