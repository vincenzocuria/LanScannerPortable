"""Rigenera oui_vendor.zlib da manuf Wireshark (serve solo in sviluppo).

Formato: una riga per prefisso "<esadecimale>\t<produttore>". Il prefisso ha 6 cifre per i
blocchi MA-L (/24), 7 per MA-M (/28) e 9 per MA-S (/36): scan_lan cerca prima il più lungo.
"""
import pathlib
import re
import urllib.request
import zlib

URL = "https://www.wireshark.org/download/automated/data/manuf"
ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT / "oui_vendor.zlib"
SUPPORTED_BITS = {24: 6, 28: 7, 36: 9}


def parse_manuf(raw: str) -> dict:
    seen = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        prefix, _, bits_s = parts[0].strip().partition("/")
        bits = int(bits_s) if bits_s.isdigit() else 24
        digits = SUPPORTED_BITS.get(bits)
        if digits is None:
            continue
        key = re.sub(r"[^0-9A-Fa-f]", "", prefix).upper()[:digits]
        if len(key) != digits:
            continue
        vendor = parts[-1].strip() if len(parts) >= 3 else parts[1].strip()
        if not vendor:
            continue
        if key not in seen or len(vendor) > len(seen[key]):
            seen[key] = vendor[:120]
    return seen


def main():
    req = urllib.request.Request(URL, headers={"User-Agent": "LanScanner-regen/1"})
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = r.read().decode("utf-8", "replace")
    seen = parse_manuf(raw)
    blob = zlib.compress(
        "\n".join(f"{k}\t{v}" for k, v in sorted(seen.items())).encode("utf-8"), 9
    )
    OUT.write_bytes(blob)
    by_len = {n: sum(1 for k in seen if len(k) == n) for n in sorted(SUPPORTED_BITS.values())}
    print("OK", OUT, len(seen), "prefissi", by_len, len(blob), "bytes")


if __name__ == "__main__":
    main()
