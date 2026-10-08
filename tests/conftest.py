import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(ROOT))


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()
