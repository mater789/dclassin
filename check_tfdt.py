#!/usr/bin/env python3
"""Efficiently check all tfdt boxes in repaired MP4."""
import struct, os, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

path = os.path.expanduser("~/Desktop/repaired_final.mp4")
size = os.path.getsize(path)

with open(path, "rb") as f:
    # Scan for tfdt in 1MB chunks (fast)
    chunk_size = 1024 * 1024
    offset = 0
    tfdt_list = []

    while offset < size:
        f.seek(offset)
        data = f.read(chunk_size + 100)  # extra to handle boundary crossing
        pos = 0
        while True:
            idx = data.find(b"tfdt", pos)
            if idx < 0:
                break
            # Found a tfdt, extract its base time
            abs_pos = offset + idx
            version = data[idx + 8]
            if version == 0 and idx + 16 <= len(data):
                base_time = struct.unpack(">I", data[idx + 12:idx + 16])[0]
            elif version == 1 and idx + 20 <= len(data):
                base_time = struct.unpack(">Q", data[idx + 12:idx + 20])[0]
            else:
                pos = idx + 1
                continue
            tfdt_list.append((abs_pos, base_time))
            pos = idx + 1
        offset += chunk_size

    tfdt_list.sort()

    print(f"Total tfdt found: {len(tfdt_list)}")
    print(f"\nFirst 3:")
    for p, t in tfdt_list[:3]:
        print(f"  offset={p} tfdt={t}  time={t/90000:.1f}s  min={t/90000/60:.1f}")
    print(f"\nLast 3:")
    for p, t in tfdt_list[-3:]:
        print(f"  offset={p} tfdt={t}  time={t/90000:.1f}s  min={t/90000/60:.1f}")

    max_tfdt = max(t[1] for t in tfdt_list) if tfdt_list else 0
    max_time_90000 = max_tfdt / 90000
    print(f"\nMax tfdt: {max_tfdt} = {max_time_90000:.0f}s = {max_time_90000/60:.1f} min")

    # Check if all tfdt values are the same
    unique = set(t[1] for t in tfdt_list)
    print(f"Unique tfdt values: {len(unique)}")
    if len(unique) < 3:
        print(f"  Values: {sorted(unique)}")
