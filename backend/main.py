from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from models import ThreatItem, ThreatResponse, Stats
from ingestor import parse_intel_file
from update_feed import fetch_feed, parse_feed_and_update
import os

app = FastAPI(title="ThreatLumen Nexus API")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For dev, allow all. In prod, lock this down.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global store for threats (in-memory caching)
THREATS: List[ThreatItem] = []
INTEL_FILE_PATH = r"C:\Users\dwean\Downloads\threatlumen_intel.md"

@app.on_event("startup")
async def load_data():
    global THREATS
    if os.path.exists(INTEL_FILE_PATH):
        # Startup Feed Update
        print("Fetching latest threat intelligence feeds...")
        try:
             # Run sync in async context is okay for startup or use run_in_executor if needed
             # For simplicity and given it's a local tool, direct call is fine but might block briefly
             xml = fetch_feed()
             if xml:
                 parse_feed_and_update(xml)
        except Exception as e:
            print(f"Startup feed update failed: {e}")

        THREATS = parse_intel_file(INTEL_FILE_PATH)
        # Sort by published_date descending (newest first)
        # normalize_date ensures YYYY-MM-DD format which is lexically sortable
        THREATS.sort(key=lambda x: x.published_date, reverse=True)
        print(f"Loaded {len(THREATS)} threats from {INTEL_FILE_PATH}")
    else:
        print(f"Warning: Intel file not found at {INTEL_FILE_PATH}")

@app.get("/api/threats", response_model=ThreatResponse)
async def get_threats(tag: Optional[str] = None, severity: Optional[str] = None):
    results = THREATS
    
    if tag:
        results = [t for t in results if tag.lower() in [xt.lower() for xt in t.tags]]
    
    if severity:
        results = [t for t in results if t.severity.lower() == severity.lower()]

    return ThreatResponse(
        threats=results,
        total=len(results)
    )

@app.get("/api/stats", response_model=Stats)
async def get_stats():
    total = len(THREATS)
    critical_count = sum(1 for t in THREATS if t.severity == 'critical')
    
    # Heuristic for ransomware count
    ransomware_count = sum(1 for t in THREATS if "Ransomware" in t.tags)
    
    # Count unique sources
    sources = set(t.source for t in THREATS)
    
    return Stats(
        total_threats=total,
        critical_count=critical_count,
        ransomware_count=ransomware_count,
        sources_count=len(sources)
    )

@app.get("/api/reload")
async def reload_intel():
    await load_data()
    return {"message": "Reloaded intelligence data", "count": len(THREATS)}

@app.post("/api/fetch-feed")
async def trigger_feed_fetch():
    """
    Triggers the download and parsing of the latest CISA feed.
    """
    xml_content = fetch_feed()
    if not xml_content:
        raise HTTPException(status_code=500, detail="Failed to fetch feed from CISA")
    
    count = parse_feed_and_update(xml_content)
    
    # Reload the data into memory
    await load_data()
    
    return {"message": "Feed fetched and updated", "new_entries": count, "total_threats": len(THREATS)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
