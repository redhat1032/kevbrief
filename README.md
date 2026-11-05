# kevbrief

**A patch-priority briefing built from security news.**

kevbrief reads a handful of security news feeds, pulls out every CVE they mention,
checks each one against the [CISA Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
and [FIRST EPSS](https://www.first.org/epss/), and puts the ones to patch first at the top.
The news articles are still there, but as supporting coverage under the patch list.

It is a small Streamlit app with a custom dark interface. No account, database or API key is required.

## What it does

1. **Fetches news** from 8 feeds concurrently (15 s timeout each; one dead feed never blocks the rest):
   The Hacker News, Krebs on Security, BleepingComputer, Dark Reading, SecurityWeek,
   SANS Internet Storm Center, CISA Advisories, Schneier on Security.
2. **Cleans it**: strips HTML from titles and summaries (before display *and* export),
   reads RSS and Atom dates correctly, and merges the same story reported by several outlets
   (matched by normalized link or normalized title) into one card that lists every source.
3. **Tags it** with whole-word keyword matching (Ransomware, Patch Now, Vulnerabilities, Cloud / IAM, ...).
4. **Enriches every CVE** it finds:
   - **CISA KEV**: one cached download of the full catalog (refreshed hourly). Gives date added,
     federal due date, vendor/product and whether CISA knows of ransomware use.
   - **FIRST EPSS**: probability of exploitation in the next 30 days, batch-queried from the
     public API (no key needed).
   - **NVD CVSS** (optional): paced to NVD's limits (5 requests / 30 s without a key, 50 with one).
     Lookups over budget are skipped, not waited on, and fill in on later reloads.
     KEV and EPSS never depend on NVD.
5. **Shows "Patch these first"**: one row per CVE: KEV status, KEV due date, ransomware use,
   EPSS, CVSS, vendor/product, and which sources mentioned it. Order: KEV with known ransomware
   use, then other KEV entries (newest additions first), then by EPSS, then CVSS.
6. **Exports** the patch table (CSV), a Markdown briefing, and the article list (CSV).

## Run it locally

Requires Python 3.11 or newer.

```bash
git clone https://github.com/redhat1032/kevbrief.git
cd kevbrief
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Optional: an [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) raises the CVSS lookup budget.

```bash
export NVD_API_KEY=your-key
```

On Streamlit Community Cloud, put `NVD_API_KEY = "your-key"` in the app's Secrets; top-level
secrets are exposed as environment variables.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

The tests run offline against recorded feed snippets in `tests/fixtures/` (including the Atom
date case, partial-word tags, cross-source de-duplication and HTML stripping), plus a smoke test
that renders the full Streamlit page with the network mocked out. GitHub Actions runs them on
Python 3.11, 3.12 and 3.13.

## Project layout

| Path | Purpose |
|---|---|
| `app.py` | Streamlit UI only |
| `kevbrief/feeds.py` | Fetching, HTML stripping, dates, tags, de-duplication |
| `kevbrief/enrich.py` | KEV, EPSS, paced NVD lookups, patch-priority ordering |
| `kevbrief/display.py` | Value formatting (EPSS %, CVSS, due dates, vendor/product) and the HTML for stat cards and the patch table |
| `tests/` | pytest suite and recorded fixtures |
| `.streamlit/config.toml` | Dark theme settings |

## Limitations

- **News mentions are not an asset scan.** kevbrief only knows about CVEs that made the news in
  these feeds. It does not know what software you run. Use it to decide what to check first, then
  confirm exposure against your own inventory or scanner.
- **CISA KEV is the authority** on known exploitation. If a CVE is in KEV, treat it as exploited
  regardless of what EPSS or CVSS say. KEV due dates are deadlines for US federal agencies under
  BOD 22-01; for everyone else they are an outer limit, not a target.
- **EPSS is a probability, not a verdict.** A low EPSS score does not mean a CVE is safe to ignore.
- **Coverage depends on the feeds.** Articles that describe a vulnerability without a CVE ID are
  shown but not scored. Feed URLs change; the sidebar shows which sources are failing.
- **Saved articles last for the browser session only.** Nothing is written to disk on the server.
- **Keyword tags are a rough guide**, not classification.

## Credits

Vulnerability data from [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
[FIRST EPSS](https://www.first.org/epss/) and the [NVD](https://nvd.nist.gov/). This product uses
the NVD API but is not endorsed or certified by the NVD. News content belongs to its publishers;
kevbrief links to the original articles.

## License

MIT © 2026 Douglas Weant. See [LICENSE](LICENSE).
