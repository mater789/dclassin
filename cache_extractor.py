#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ijkplayer cache file extractor — fallback when Frida is unavailable.

Parses ijkio cache files to extract playable MP4 data.

The ijkio cache format (from ijkplayer source):
  [Header: URL string + metadata]
  [Tree: serialized IjkAVTreeNode entries mapping logical→physical positions]
  [Data blocks: raw media bytes in download order (NOT logical order)]

Each tree node corresponds to an IjkCacheEntry:
  struct IjkCacheEntry { int64_t logical_pos; int64_t physical_pos; int64_t size; }

Strategy (multi-pass):
  1. Detect cache format version by scanning header patterns.
  2. Extract URL from the header.
  3. Parse the tree to get logical→physical mappings.
  4. Reassemble data in logical order → valid fMP4/MP4.
  5. If tree parsing fails, fall back to MP4 box scanning.
"""

import os
import re
import struct
import logging
from pathlib import Path
from typing import List, Tuple, Optional, BinaryIO

logger = logging.getLogger("cache_extractor")

# -------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------
# IjkCacheEntry size: 3 × int64_t = 24 bytes
CACHE_ENTRY_SIZE = 24

# Common ISOBMFF box types
FTYP = b"ftyp"
MOOV = b"moov"
MOOF = b"moof"
MDAT = b"mdat"
SIDX = b"sidx"
FREE = b"free"
SKIP = b"skip"

BOX_TYPES = {FTYP, MOOV, MOOF, MDAT, SIDX, FREE, SKIP}


# -------------------------------------------------------------------
# Heuristic cache format detection
# -------------------------------------------------------------------
def detect_cache_version(data: bytes) -> str:
    """
    Try to detect the ijkio cache format version.
    Returns "tree_v1", "tree_v2", "raw_mp4", or "unknown".
    """
    if len(data) < 64:
        return "unknown"

    # Check if this is raw fMP4 (starts with ftyp box)
    if data[4:8] == FTYP and data[0:4] != b"\x00\x00\x00\x00":
        box_size = struct.unpack(">I", data[0:4])[0]
        if 20 <= box_size <= 256:
            return "raw_mp4"

    # Look for URL in first 4KB
    head = data[:4096]
    url_match = re.search(rb"(https?|rtmp|rtsp)://[^\x00]{10,200}", head)
    if url_match:
        url_end = url_match.end()
        rest = head[url_end:url_end+128]
        # After URL, there should be tree metadata
        return "tree_v1" if url_match.start() < 256 else "tree_v2"

    return "unknown"


def extract_url(data: bytes) -> Optional[str]:
    """Try to extract the media URL from the cache header."""
    # Search first 64KB for URL patterns
    head = data[:65536]
    for pattern in [rb"(https?://[^\x00]{10,500})",
                    rb"(rtmp://[^\x00]{10,500})",
                    rb"(rtsp://[^\x00]{10,500})"]:
        match = re.search(pattern, head)
        if match:
            return match.group(1).decode("utf-8", errors="replace")
    return None


# -------------------------------------------------------------------
# Tree parser — IjkAVTreeNode → IjkCacheEntry
# -------------------------------------------------------------------
def parse_ijk_tree(data: bytes, tree_offset: int,
                   tree_size: int) -> List[Tuple[int, int, int]]:
    """
    Parse serialized IjkAVTreeNode tree.

    Each node is roughly:
      - IjkCacheEntry entry (24 bytes: logical_pos, physical_pos, size)
      - int64_t height (8 bytes)
      - pointers to left/right children (16 bytes for 32-bit, not serialized)

    In the serialized form, nodes may be stored inline or in a flat list.
    We scan for plausible (logical_pos, physical_pos, size) triples.

    Returns list of (logical_pos, physical_pos, size).
    """
    entries = []
    end = min(tree_offset + tree_size, len(data))
    pos = tree_offset

    while pos + CACHE_ENTRY_SIZE <= end:
        logical = struct.unpack("<q", data[pos:pos+8])[0]
        physical = struct.unpack("<q", data[pos+8:pos+16])[0]
        size = struct.unpack("<q", data[pos+16:pos+24])[0]

        # Validate: all three should be reasonable
        if (0 <= logical < 10 * 1024 * 1024 * 1024 and  # < 10 GB
            0 <= physical < len(data) and
            0 < size < 100 * 1024 * 1024 and             # < 100 MB per chunk
            physical + size <= len(data)):
            entries.append((logical, physical, size))
            pos += CACHE_ENTRY_SIZE
        else:
            # Skip one byte and try again (the tree might have padding/non-entry data)
            pos += 8

    return entries


def scan_for_tree_region(data: bytes) -> Tuple[int, int]:
    """
    Scan the file for the tree region by looking for
    dense clusters of valid IjkCacheEntry-like triples.

    Returns (offset, size) of the tree region.
    """
    best_offset = 0
    best_count = 0
    best_run = 0

    # Scan in 8-byte steps
    for offset in range(0, min(len(data), 65536), 8):
        if offset + 24 > len(data):
            break
        logical = struct.unpack("<q", data[offset:offset+8])[0]
        physical = struct.unpack("<q", data[offset+8:offset+16])[0]
        size = struct.unpack("<q", data[offset+16:offset+24])[0]
        if (0 <= logical < 10 * 1024 * 1024 * 1024 and
            0 <= physical < len(data) and
            0 < size < 100 * 1024 * 1024 and
            physical + size <= len(data)):
            best_run += 1
            if best_run > best_count:
                best_count = best_run
                best_offset = offset - (best_run - 1) * 24
        else:
            best_run = 0

    if best_count >= 3:
        return (best_offset, best_count * 24)
    return (0, 0)


# -------------------------------------------------------------------
# MP4 box scanner (fallback)
# -------------------------------------------------------------------
def scan_mp4_boxes(data: bytes) -> Tuple[bytes, bytes]:
    """
    Scan for MP4 boxes when tree parsing fails.
    Returns (init_boxes, media_data) or (b"", b"").
    """
    init_boxes = b""
    media_data = b""
    pos = 0

    while pos < len(data) - 7:
        box_size = struct.unpack(">I", data[pos:pos+4])[0]
        box_type = data[pos+4:pos+8]
        if box_size < 8 or box_size > len(data) - pos:
            pos += 1
            continue
        if box_type not in BOX_TYPES:
            pos += box_size
            continue
        if box_type in (MOOF, MDAT):
            media_data += data[pos:pos+box_size]
        else:
            init_boxes += data[pos:pos+box_size]
        pos += box_size

    return init_boxes, media_data


def build_valid_fmp4(init_boxes: bytes, media_data: bytes) -> bytes:
    """Reconstruct a valid fMP4 from init boxes and media data."""
    if not init_boxes:
        return media_data  # best effort
    if not media_data:
        return init_boxes

    # Extract ftyp from init boxes
    ftyp = b""
    pos = 0
    while pos < len(init_boxes) - 7:
        box_size = struct.unpack(">I", init_boxes[pos:pos+4])[0]
        box_type = init_boxes[pos+4:pos+8]
        if box_type == FTYP:
            ftyp = init_boxes[pos:pos+box_size]
            break
        pos += box_size

    # Build synthetic moov from non-ftyp init boxes
    non_ftyp = b""
    pos = 0
    while pos < len(init_boxes) - 7:
        box_size = struct.unpack(">I", init_boxes[pos:pos+4])[0]
        box_type = init_boxes[pos+4:pos+8]
        if box_type != FTYP and box_type in BOX_TYPES:
            non_ftyp += init_boxes[pos:pos+box_size]
        pos += box_size

    moov_box = struct.pack(">I", 8 + len(non_ftyp)) + b"moov" + non_ftyp

    return ftyp + moov_box + media_data


# -------------------------------------------------------------------
# Main extractor
# -------------------------------------------------------------------
class CacheExtractor:
    """
    Extract playable video from ijkplayer cache file.
    """

    def __init__(self, cache_path: str):
        self.cache_path = Path(cache_path)
        self.url: Optional[str] = None
        self.format_version = "unknown"
        self.entries: List[Tuple[int, int, int]] = []

    def analyze(self) -> dict:
        """Analyze the cache file without extracting. Returns diagnostics."""
        if not self.cache_path.exists():
            return {"error": f"File not found: {self.cache_path}"}

        with open(self.cache_path, "rb") as f:
            data = f.read()

        self.format_version = detect_cache_version(data)
        self.url = extract_url(data)

        info = {
            "path": str(self.cache_path),
            "size": len(data),
            "format": self.format_version,
            "url": self.url,
        }

        if self.format_version in ("tree_v1", "tree_v2"):
            tree_offset, tree_size = scan_for_tree_region(data)
            if tree_size > 0:
                self.entries = parse_ijk_tree(data, tree_offset, tree_size)
                info["tree_entries"] = len(self.entries)
                if self.entries:
                    sorted_entries = sorted(self.entries, key=lambda e: e[0])
                    info["logical_size"] = max(e[0] + e[2] for e in sorted_entries)
                    info["physical_size"] = max(e[1] + e[2] for e in sorted_entries)
                    info["coverage"] = sum(e[2] for e in self.entries) / max(info["logical_size"], 1)

        return info

    def extract(self, output_path: Optional[str] = None) -> Optional[str]:
        """
        Extract playable video from cache file.

        Returns the output path on success, None on failure.
        """
        if not self.cache_path.exists():
            logger.error("Cache file not found: %s", self.cache_path)
            return None

        output = Path(output_path) if output_path else \
            self.cache_path.with_suffix(".extracted.mp4")

        with open(self.cache_path, "rb") as f:
            data = f.read()

        self.format_version = detect_cache_version(data)
        self.url = extract_url(data)

        logger.info("Cache format: %s, URL: %s",
                     self.format_version,
                     (self.url or "?")[:80])

        result = None

        # Strategy 1: Tree-based extraction
        if self.format_version in ("tree_v1", "tree_v2"):
            result = self._extract_tree(data, output)

        # Strategy 2: MP4 box scanning fallback
        if result is None:
            logger.info("Tree extraction failed, trying MP4 box scan...")
            result = self._extract_mp4_scan(data, output)

        if result:
            logger.info("Extracted to: %s", result)
        else:
            logger.error("All extraction strategies failed")

        return result

    def _extract_tree(self, data: bytes, output: Path) -> Optional[str]:
        """Extract using tree-based logical→physical mapping."""
        tree_offset, tree_size = scan_for_tree_region(data)
        if tree_size == 0:
            logger.warning("No tree region found")
            return None

        self.entries = parse_ijk_tree(data, tree_offset, tree_size)
        if len(self.entries) < 3:
            logger.warning("Too few tree entries (%d)", len(self.entries))
            return None

        # Sort by logical position
        self.entries.sort(key=lambda e: e[0])

        # Determine total logical file size
        logical_size = max(e[0] + e[2] for e in self.entries)

        # Reassemble in logical order
        result = bytearray()
        for logical_pos, physical_pos, size in self.entries:
            # Fill gaps with zeros
            if logical_pos > len(result):
                result.extend(b"\x00" * (logical_pos - len(result)))
            elif logical_pos < len(result):
                # Overlapping — prefer the newer data
                pass
            result.extend(data[physical_pos:physical_pos+size])

        # Trim to logical size
        result = bytes(result[:logical_size])

        with open(output, "wb") as f:
            f.write(result)

        logger.info("Tree extraction: %d entries, %d bytes -> %s",
                     len(self.entries), len(result), output)
        return str(output)

    def _extract_mp4_scan(self, data: bytes, output: Path) -> Optional[str]:
        """Fallback: scan for MP4 boxes."""
        init_boxes, media_data = scan_mp4_boxes(data)
        if not init_boxes and not media_data:
            return None

        result = build_valid_fmp4(init_boxes, media_data)
        if len(result) < 1024:
            return None

        with open(output, "wb") as f:
            f.write(result)

        logger.info("MP4 scan extraction: %d bytes -> %s", len(result), output)
        return str(output)


# -------------------------------------------------------------------
# Standalone
# -------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(
        description="Extract video from ijkplayer cache files")
    parser.add_argument("cache_file", help="Path to ijkplayer cache file")
    parser.add_argument("-o", "--output", help="Output path", default=None)
    parser.add_argument("--analyze", action="store_true",
                        help="Only analyze, don't extract")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    extractor = CacheExtractor(args.cache_file)

    if args.analyze:
        info = extractor.analyze()
        for k, v in info.items():
            print(f"  {k}: {v}")
    else:
        result = extractor.extract(args.output)
        if result:
            print(f"Extracted: {result}")
        else:
            print("Extraction failed")
