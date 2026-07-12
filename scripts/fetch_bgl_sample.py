"""Download the public Loghub BGL 2k structured sample for external evaluation."""

from __future__ import annotations

import hashlib
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
URL = "https://raw.githubusercontent.com/logpai/loghub/master/BGL/BGL_2k.log_structured.csv"
EXPECTED_SHA256 = "3fe74103c0b02a28514534e2a47257a3f770135ca61afd425bbd3b9d6a31fe26"
TARGET = ROOT / "datasets" / "external" / "BGL_2k.log_structured.csv"


def main() -> None:
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(URL, timeout=30) as response:
        payload = response.read()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != EXPECTED_SHA256:
        raise RuntimeError(f"Checksum mismatch: expected {EXPECTED_SHA256}, got {digest}")
    TARGET.write_bytes(payload)
    print(f"Downloaded {len(payload)} bytes to {TARGET}")


if __name__ == "__main__":
    main()
