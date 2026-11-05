import re
from typing import List
from datetime import datetime
from typing import List
from models import ThreatItem

def normalize_date(date_str: str) -> str:
    """
    Standardizes date strings to YYYY-MM-DD.
    """
    if not date_str or date_str == "Unknown":
        return "1970-01-01"
    
    # Try ISO first (or simple YYYY-MM-DD)
    try:
        # Check if it's already basically YYYY-MM-DD (ignoring time if present)
        # Some might be YYYY-MM-DD HH:MM
        if len(date_str) >= 10 and date_str[4] == '-' and date_str[7] == '-':
             # It's likely ISO-ish
             return date_str[:10]
    except:
        pass

    # Try Legacy format: "Wed, 28 Jan 04 12:00:00 +0000"
    try:
        # Note: %y is 2-digit year. "04" -> 2004.
        # We need to handle the timestamp part carefully.
        # Python's strptime might need exact format.
        # Let's try flexible parsing or specific format
        dt = datetime.strptime(date_str.split(' +')[0], "%a, %d %b %y %H:%M:%S")
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        pass
    
    return date_str

def parse_intel_file(filepath: str) -> List[ThreatItem]:
    """
    Parses the threatlumen_intel.md file and returns a list of ThreatItem objects.
    """
    threats = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return []

    # Split by the separator line "---"
    # The first split might be empty or header info, so we skip if not a threat block
    blocks = content.split('\n---\n')

    for block in blocks:
        block = block.strip()
        if not block:
            continue
            
        # Check if this block looks like a threat entry (starts with ##)
        if not block.startswith('## '):
             # Try to find the first ## in case there is some leading text
            match = re.search(r'##\s+(.+)', block)
            if not match:
                continue
        
        # Extract Title
        title_match = re.search(r'##\s+(.+)', block)
        if not title_match:
            continue
        title = title_match.group(1).strip()

        # Extract Published Date
        # - **Published:** 2026-01-19 17:21
        pub_match = re.search(r'- \*\*Published:\*\*\s+(.+)', block)
        raw_date = pub_match.group(1).strip() if pub_match else "Unknown"
        published_date = normalize_date(raw_date)

        # Extract Source
        source_match = re.search(r'- \*\*Source:\*\*\s+(.+)', block)

        source = source_match.group(1).strip() if source_match else "Unknown"

        # Extract Tags
        tags = []
        tags_match = re.search(r'- \*\*Tags:\*\*\s+(.+)', block)
        if tags_match:
            tags_raw = tags_match.group(1).strip()
            tags = [t.strip() for t in tags_raw.split(',')]

        # Extract CVEs
        cves = []
        cves_match = re.search(r'- \*\*CVEs:\*\*\s+(.+)', block)
        if cves_match:
            cves_raw = cves_match.group(1).strip()
            # Often looks like "CVE-2025-61937 (CRITICAL 10.0), CVE-..."
            # Let's extract just the CVE IDs usually, but keeping the full string is also informative.
            # For this MVP let's keep the raw string split by comma? 
            # Or regex extract actual CVE-XXXX-XXXX patterns.
            # Let's simple split by comma for now to keep context like "(CRITICAL 10.0)"
            cves = [c.strip() for c in cves_raw.split(',')]

        # Extract Link
        link = ""
        link_match = re.search(r'\[Read more\]\((.+)\)', block)
        if link_match:
            link = link_match.group(1).strip()
        
        # Extract Description
        # Description is everything between the metadata lines and the [Read more] link.
        # simpler approach: Get all text that doesn't start with '#' or '-' or '[' or is composed of '---'
        lines = block.split('\n')
        desc_lines = []
        in_metadata = True
        
        for line in lines:
            line = line.strip()
            if line.startswith('## '):
                continue
            if line.startswith('# '): # Skip top level headers
                continue
            if line.startswith('- **'):
                continue
            if line.startswith('[Read more]'):
                continue
            if not line:
                continue
            
            # If we reached here, it's likely content
            desc_lines.append(line)
            
        description = " ".join(desc_lines)
        if len(description) > 300:
             description = description[:297] + "..."

        # Determine Severity
        severity = "info"
        lower_tags = [t.lower() for t in tags]
        
        if cves:
            # If any CVE entry contains CRITICAL or HIGH, set severity accordingly
            full_cve_str = " ".join(cves).upper()
            if "CRITICAL" in full_cve_str or "10.0" in full_cve_str:
                severity = "critical"
            elif "HIGH" in full_cve_str:
                severity = "high"
            elif "MEDIUM" in full_cve_str:
                severity = "medium"
            else:
                 severity = "low"
        elif "ransomware" in lower_tags or "vulnerabilities" in lower_tags:
            severity = "high"
        
        threat_item = ThreatItem(
            title=title,
            published_date=published_date,
            source=source,
            tags=tags,
            description=description,
            link=link,
            cves=cves,
            severity=severity
        )
        threats.append(threat_item)
        
    return threats

if __name__ == "__main__":
    # Test run
    path = r"C:\Users\dwean\Downloads\threatlumen_intel.md"
    items = parse_intel_file(path)
    print(f"Parsed {len(items)} items.")
    if items:
        print(f"Sample: {items[0]}")
