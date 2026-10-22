import math
import struct

MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
SECTOR, MINI, CUTOFF = 512, 64, 4096
FREE, END, FATSECT, NOSTREAM = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF


def write_cfb(tree: dict) -> bytes:
    entries = [{"name": "Root Entry", "type": 5, "kids": [], "data": b""}]

    def add(node, parent):
        for name, value in node.items():
            entries.append({"name": name, "type": 1 if isinstance(value, dict) else 2, "kids": [],
                            "data": b"" if isinstance(value, dict) else bytes(value)})
            entries[parent]["kids"].append(len(entries) - 1)
            if isinstance(value, dict):
                add(value, len(entries) - 1)

    add(tree, 0)
    for e in entries:
        e.update(left=NOSTREAM, right=NOSTREAM, child=NOSTREAM, start=END, size=len(e["data"]))
    for e in entries:
        kids = sorted(e["kids"], key=lambda i: (len(entries[i]["name"]), entries[i]["name"].upper()))
        if kids:
            e["child"] = kids[0]
            for a, b in zip(kids, kids[1:]):
                entries[a]["right"] = b

    ministream, minifat = bytearray(), []
    for e in entries:
        if e["type"] == 2 and 0 < e["size"] < CUTOFF:
            n = math.ceil(e["size"] / MINI)
            e["start"] = len(minifat)
            minifat += list(range(len(minifat) + 1, len(minifat) + n)) + [END]
            ministream += e["data"].ljust(n * MINI, b"\0")

    sectors, fat = [], []

    def alloc(data: bytes, pad: bytes = b"\0") -> int:
        n = math.ceil(len(data) / SECTOR)
        if not n:
            return END
        start = len(fat)
        fat.extend(list(range(start + 1, start + n)) + [END])
        sectors.append(data.ljust(n * SECTOR, pad))
        return start

    for e in entries:
        if e["type"] == 2 and e["size"] >= CUTOFF:
            e["start"] = alloc(e["data"])
    entries[0]["start"] = alloc(bytes(ministream))
    entries[0]["size"] = len(ministream)
    minifat_bytes = struct.pack(f"<{len(minifat)}I", *minifat)
    minifat_start = alloc(minifat_bytes, b"\xff")
    n_minifat = math.ceil(len(minifat_bytes) / SECTOR)
    directory = b"".join(_entry(e) for e in entries)
    directory += _empty_entry() * (-len(entries) % 4)
    dir_start = alloc(directory)

    n_fat = 1
    while len(fat) + n_fat > n_fat * (SECTOR // 4):
        n_fat += 1
    if n_fat > 109:
        raise ValueError("fixture too large for a header-only DIFAT")
    fat_start = len(fat)
    fat.extend([FATSECT] * n_fat)
    sectors.append(struct.pack(f"<{len(fat)}I", *fat).ljust(n_fat * SECTOR, b"\xff"))

    difat = list(range(fat_start, fat_start + n_fat)) + [FREE] * (109 - n_fat)
    header = struct.pack("<8s16sHHHHH6sIIIIIIIII109I", MAGIC, b"\0" * 16, 0x3E, 3, 0xFFFE, 9, 6, b"\0" * 6,
                         0, n_fat, dir_start, 0, CUTOFF, minifat_start if minifat else END, n_minifat, END, 0, *difat)
    return header + b"".join(sectors)


def _entry(e: dict) -> bytes:
    if len(e["name"]) > 31:
        raise ValueError("CFB names are at most 31 characters")
    name = e["name"].encode("utf-16-le")
    start = e["start"] if e["type"] != 1 else 0
    return struct.pack("<64sHBBIII16sIQQIQ", name, len(name) + 2, e["type"], 1, e["left"], e["right"], e["child"],
                       b"\0" * 16, 0, 0, 0, start, e["size"] if e["type"] != 1 else 0)


def _empty_entry() -> bytes:
    return struct.pack("<64sHBBIII16sIQQIQ", b"", 0, 0, 0, NOSTREAM, NOSTREAM, NOSTREAM, b"\0" * 16, 0, 0, 0, 0, 0)
