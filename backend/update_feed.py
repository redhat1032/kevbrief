import requests
import json
import os
from datetime import datetime
import re

import xml.etree.ElementTree as ET

# CISA Known Exploited Vulnerabilities (KEV) Catalog
# https://www.cisa.gov/known-exploited-vulnerabilities-catalog
FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# BleepingComputer RSS Feed
RSS_FEED_URL = "https://www.bleepingcomputer.com/feed/"

INTEL_FILE_PATH = r"C:\Users\dwean\Downloads\threatlumen_intel.md"

def fetch_feed():
    try:
        response = requests.get(FEED_URL, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching CISA feed: {e}")
        return None

def fetch_rss_feed():
    """
    Fetches the BleepingComputer RSS feed with custom headers.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    try:
        response = requests.get(RSS_FEED_URL, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.content
        else:
            print(f"Error fetching RSS feed: Status {response.status_code}")
            return None
    except Exception as e:
        print(f"Error fetching RSS feed: {e}")
        return None

def parse_rss_items(xml_content, existing_titles):
    """
    Parses RSS XML content and returns a list of formatted markdown entries.
    """
    new_entries = []
    if not xml_content:
        return new_entries

    try:
        root = ET.fromstring(xml_content)
        channel = root.find("channel")
        if channel is None:
            return new_entries

        items = channel.findall("item")
        print(f"Processing {len(items)} RSS items...")

        for item in items:
            title = item.find("title").text
            pubDate = item.find("pubDate").text
            link = item.find("link").text
            description = item.find("description").text
            
            # Simple deduplication check by title
            if title in existing_titles:
                 continue
            
            # Format date (RSS is like "Tue, 20 Jan 2026 14:35:31 -0500")
            # We want YYYY-MM-DD for consistency
            try:
                # Remove timezone part for simple parsing or handle it
                # "Tue, 20 Jan 2026 14:35:31 -0500" -> split " -" -> parse
                dt_str = pubDate.split(' -')[0].split(' +')[0]
                dt = datetime.strptime(dt_str, "%a, %d %b %Y %H:%M:%S")
                formatted_date = dt.strftime("%Y-%m-%d")
            except Exception:
                formatted_date = pubDate # Fallback

            # Construct Markdown Block
            # We'll map RSS fields to our Threat Model loosely
            entry = (
                f"\n---\n\n"
                f"## {title}\n"
                f"- **Published:** {formatted_date}\n"
                f"- **Source:** Bleeping Computer\n"
                f"- **Vendor/Product:** General - News\n"
                f"- **Tags:** Cybersecurity, News, RSS\n"
                f"- **CVEs:** \n" # News usually doesn't have a structured CVE field
                f"\n"
                f"**Description:** {description}\n\n"
                f"**Action Required:** Review article for details.\n"
                f"\n[Read more]({link})\n"
            )
            new_entries.append(entry)

    except Exception as e:
        print(f"Error parsing RSS items: {e}")

    return new_entries

def parse_feed_and_update(feed_data):
    # 1. RSS Feed
    rss_content = fetch_rss_feed()
    
    # Read existing file 
    existing_content = ""
    existing_titles = set()
    if os.path.exists(INTEL_FILE_PATH):
        with open(INTEL_FILE_PATH, "r", encoding="utf-8") as f:
            existing_content = f.read()
            # Extract basic titles for dedupe
            # "## Title"
            titles = re.findall(r'^##\s+(.+)$', existing_content, re.MULTILINE)
            existing_titles.update(titles)
            # Also extract raw content strings just in case
            
            
    # Process RSS
    rss_entries = parse_rss_items(rss_content, existing_titles)
    
    # 2. CISA Feed
    cisa_entries = []
    if feed_data and "vulnerabilities" in feed_data:
        items = feed_data["vulnerabilities"]
        print(f"Processing {len(items)} CISA items...")
        
        # Sort CISA items by dateAdded descending
        try:
            items.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
        except:
            pass

        processed_items = items[:50] 

        for item in processed_items:
            cve_id = item.get("cveID")
            vuln_name = item.get("vulnerabilityName")
            date_added = item.get("dateAdded") # YYYY-MM-DD
            description = item.get("shortDescription")
            required_action = item.get("requiredAction")
            vendor = item.get("vendorProject")
            product = item.get("product")
            
            title = f"{cve_id}: {vuln_name}"
            
            if title in existing_titles or cve_id in existing_content:
                continue

            # Construct Markdown Block
            entry = (
                f"\n---\n\n"
                f"## {title}\n"
                f"- **Published:** {date_added}\n"
                f"- **Source:** CISA KEV\n"
                f"- **Vendor/Product:** {vendor} - {product}\n"
                f"- **Tags:** Cybersecurity, Exploited, Critical\n"
                f"- **CVEs:** {cve_id}\n"
                f"\n"
                f"**Description:** {description}\n\n"
                f"**Action Required:** {required_action}\n"
            )
            
            notes = item.get("notes")
            if notes:
                links = [link.strip() for link in notes.split(';') if link.strip().startswith('http')]
                if links:
                     entry += f"\n[More Info]({links[0]})\n"
            
            cisa_entries.append(entry)

    all_new_entries = rss_entries + cisa_entries
    
    if all_new_entries:
        # Prepend new entries
        combined_content = "".join(all_new_entries) + existing_content
        
        with open(INTEL_FILE_PATH, "w", encoding="utf-8") as f:
            f.write(combined_content)
            
        print(f"Added {len(rss_entries)} RSS entries and {len(cisa_entries)} CISA entries to {INTEL_FILE_PATH}")
    else:
        print("No new entries found.")

    return len(all_new_entries)

if __name__ == "__main__":
    data = fetch_feed()
    # parse_feed_and_update handles None data gracefully for CISA part
    parse_feed_and_update(data)

