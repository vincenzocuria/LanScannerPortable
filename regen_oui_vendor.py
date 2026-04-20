"""Rigenera oui_vendor.zlib da manuf Wireshark (serve solo in sviluppo)."""
import pathlib
import re
import urllib.request
import zlib

URL = "https://www.wireshark.org/download/automated/data/manuf"
ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT / "oui_vendor.zlib"

def main():
    req = urllib.request.Request(URL, headers={"User-Agent": "LanScanner-regen/1"})
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = r.read().decode("utf-8", "replace")
    seen = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        octets = parts[0].strip().split(":")
        if len(octets) < 3:
            continue
        key = "".join(octets[:3]).upper()
        if len(key) != 6 or not re.fullmatch(r"[0-9A-F]{6}", key):
            continue
        vendor = parts[-1].strip() if len(parts) >= 3 else parts[1].strip()
        if not vendor:
            continue
        if key not in seen or len(vendor) > len(seen[key]):
            seen[key] = vendor[:120]
    blob = zlib.compress(
        "\n".join(f"{k}\t{v}" for k, v in sorted(seen.items())).encode("utf-8"), 9
    )
    OUT.write_bytes(blob)
    print("OK", OUT, len(seen), "OUIs,", len(blob), "bytes")

if __name__ == "__main__":
    main()
