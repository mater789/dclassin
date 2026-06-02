#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pure Python HLS (m3u8) video stream downloader.
Parses m3u8 playlists, downloads TS segments (with optional AES-128 decryption),
and concatenates them into a single video file.  Supports variant playlists
(auto-selects best quality), parallel segment downloads, and optional ffmpeg
remux to MP4.
"""

import os
import re
import sys
import time
import json
import logging
import threading
import subprocess
from pathlib import Path
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict, Any, Tuple, Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import IncompleteRead, ProtocolError as Urllib3ProtocolError

# ---------------------------------------------------------------------------
# Optional AES-128 decryption
# ---------------------------------------------------------------------------
try:
    from Crypto.Cipher import AES as _AES

    HAS_AES = True
except ImportError:
    HAS_AES = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("hls_downloader")


# ===================================================================
# HLS Playlist Parser
# ===================================================================
class HLSPlaylist:
    """Parse a single HLS (m3u8) playlist."""

    def __init__(self, url: str, content: str = ""):
        self.url = url
        self.content = content
        self.is_variant: bool = False
        self.segments: List[Dict[str, Any]] = []
        self.variants: List[Dict[str, Any]] = []
        self.target_duration: int = 0
        self.version: int = 1
        self._discontinuity: bool = False
        if content:
            self._parse()

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------
    @classmethod
    def from_url(cls, url: str, session: requests.Session = None,
                 timeout: int = 30) -> "HLSPlaylist":
        s = session or requests.Session()
        resp = s.get(url, timeout=timeout)
        resp.raise_for_status()
        # strip BOM if present
        text = resp.text.lstrip("﻿").strip()
        return cls(url, text)

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------
    def _parse(self):
        lines = self.content.splitlines()
        if not lines or lines[0].strip() != "#EXTM3U":
            raise ValueError("Invalid m3u8 – must start with #EXTM3U")

        i = 0
        current_key_uri: Optional[str] = None
        current_key_iv: Optional[bytes] = None
        seg_duration: float = 0.0
        seg_title: str = ""

        while i < len(lines):
            raw = lines[i].strip()
            # skip empty
            if not raw:
                i += 1
                continue

            # -- tags that carry information --
            if raw.startswith("#EXT-X-TARGETDURATION:"):
                self.target_duration = int(raw.split(":")[1])

            elif raw.startswith("#EXT-X-VERSION:"):
                self.version = int(raw.split(":")[1])

            elif raw.startswith("#EXT-X-DISCONTINUITY"):
                self._discontinuity = True

            elif raw.startswith("#EXT-X-STREAM-INF:"):
                self.is_variant = True
                attrs = _parse_attrs(raw)
                i += 1
                # next non-comment line is the uri
                while i < len(lines) and lines[i].strip().startswith("#"):
                    i += 1
                if i < len(lines):
                    uri = lines[i].strip()
                    self.variants.append(
                        dict(
                            url=urljoin(self.url, uri),
                            bandwidth=int(attrs.get("BANDWIDTH", 0)),
                            resolution=attrs.get("RESOLUTION", ""),
                            codecs=attrs.get("CODECS", ""),
                        )
                    )

            elif raw.startswith("#EXTINF:"):
                m = re.match(r"#EXTINF:\s*([\d.]+)", raw)
                if m:
                    seg_duration = float(m.group(1))
                title_m = re.search(r",\s*(.+)$", raw)
                seg_title = title_m.group(1).strip() if title_m else ""

            elif raw.startswith("#EXT-X-KEY:"):
                attrs = _parse_attrs(raw)
                method = attrs.get("METHOD", "NONE")
                if method == "AES-128":
                    raw_uri = attrs.get("URI", "")
                    current_key_uri = urljoin(self.url, raw_uri.strip('"'))
                    # optional IV
                    iv_str = attrs.get("IV")
                    if iv_str:
                        # IV format: 0x followed by 32 hex chars
                        current_key_iv = bytes.fromhex(iv_str.lstrip("0x").zfill(32))
                    else:
                        current_key_iv = None
                else:
                    current_key_uri = None
                    current_key_iv = None

            elif raw.startswith("#EXT-X-MAP:"):
                # #EXT-X-MAP is for fMP4 – not handled here
                pass

            elif raw.startswith("#EXT-X-ENDLIST"):
                pass

            # -- non-comment line = segment URI --
            elif not raw.startswith("#"):
                seg_url = urljoin(self.url, raw)
                self.segments.append(
                    dict(
                        url=seg_url,
                        duration=seg_duration,
                        title=seg_title or Path(raw).stem,
                        key_uri=current_key_uri,
                        key_iv=current_key_iv,
                        discontinuity=self._discontinuity,
                    )
                )
                # reset per-segment values
                seg_duration = 0.0
                seg_title = ""
                self._discontinuity = False

            i += 1


# ===================================================================
# Actual Downloader
# ===================================================================
class HLSDownloader:
    """Download an HLS stream and produce a single .ts (or .mp4) file."""

    def __init__(
        self,
        output_dir: str = "downloads",
        max_workers: int = 10,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        retries: int = 10,
        verify_ssl: bool = True,
        min_speed: float = 51200.0,  # bytes/sec (50 KB/s) – abort segment if slower
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers
        self.connect_timeout = 15
        self.read_timeout = timeout    # per-chunk read timeout
        self.retries = retries
        self.verify_ssl = verify_ssl
        self.min_speed = min_speed

        self.session = requests.Session()
        self.session.headers.update(headers or {})
        if "User-Agent" not in self.session.headers:
            self.session.headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
        self.session.headers.setdefault("Referer", "https://www.classin.com/")

        # Enlarge connection pool so concurrent workers don't starve each other.
        # pool_connections = max hosts cached, pool_maxsize = max conns per host.
        pool_size = max(max_workers * 2, 20)
        adapter = HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size,
            max_retries=Retry(total=0),  # we handle retries ourselves
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        # Optional referer for ClassIn CDNs
        self._extra_headers = {}
        if "Referer" not in self.session.headers:
            self._extra_headers["Referer"] = "https://www.classin.com/"

    # ------------------------------------------------------------------
    # Connection pool management
    # ------------------------------------------------------------------
    def _clear_connection_pool(self):
        """Drop cached connections so retries hit a fresh CDN edge node."""
        try:
            for prefix in ("https://", "http://"):
                adapter = self.session.adapters.get(prefix)
                if adapter and hasattr(adapter, 'poolmanager'):
                    adapter.poolmanager.clear()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def download(self, url: str, output: Optional[str] = None,
                 quality: str = "best",
                 progress_callback: Optional[Callable] = None) -> Path:
        """
        Download an HLS stream.

        Parameters
        ----------
        url : str
            URL of the master or media m3u8 playlist.
        output : str, optional
            Output file path.  Extension controls container (.ts / .mp4).
            If omitted a timestamp-based name is used.
        quality : str
            For variant playlists: ``"best"``, ``"worst"``, or a target
            bandwidth value.
        progress_callback : callable, optional
            Called with (completed, total, bytes_per_sec, status) during download.
            ``status`` is one of "downloading", "merging", "done", "error".

        Returns
        -------
        Path to the final video file.
        """
        # Direct MP4 download (progressive download, not HLS)
        url_path = url.split("?")[0]
        if url_path.lower().endswith(".mp4") or ".mp4?" in url.lower():
            return self._download_mp4(url, output, progress_callback)

        logger.info("Fetching playlist: %s", url)
        playlist = HLSPlaylist.from_url(url, session=self.session)

        if playlist.is_variant:
            logger.info("Variant playlist (%d qualities)", len(playlist.variants))
            chosen = self._select_variant(playlist.variants, quality)
            logger.info("Selected: %s @ %s bps",
                        chosen["resolution"] or "?",
                        _fmt_bps(chosen["bandwidth"]))
            logger.info("Fetching sub-playlist: %s", chosen["url"])
            playlist = HLSPlaylist.from_url(chosen["url"], session=self.session)

        if not playlist.segments:
            raise ValueError("No media segments found in playlist")

        n_segments = len(playlist.segments)
        logger.info("Segments to download: %d", n_segments)

        # figure output path
        output_path = self._resolve_output(output, url)

        # temporary segment directory
        tmp = self.output_dir / f".tmp_{int(time.time() * 1000)}"
        tmp.mkdir(parents=True, exist_ok=True)

        # download all segments
        seg_files = self._download_segments(playlist, tmp,
                                            progress_callback=progress_callback)

        # concatenate
        if progress_callback:
            progress_callback(n_segments, n_segments, 0.0, "merging")
        self._concatenate(seg_files, output_path)

        # cleanup tmp
        _rmtree(tmp)

        # optional remux to mp4
        if output_path.suffix.lower() != ".mp4":
            mp4 = output_path.with_suffix(".mp4")
            if self._remux_mp4(output_path, mp4):
                output_path.unlink(missing_ok=True)
                output_path = mp4

        logger.info("Done: %s  (%.1f MiB)", output_path,
                     output_path.stat().st_size / 1024 / 1024)
        if progress_callback:
            size_mb = output_path.stat().st_size / 1024 / 1024
            progress_callback(n_segments, n_segments, 0.0, "done")
        return output_path.resolve()

    # ------------------------------------------------------------------
    # Variant selection
    # ------------------------------------------------------------------
    @staticmethod
    def _select_variant(variants: List[Dict], quality: str) -> Dict:
        if quality == "best":
            return max(variants, key=lambda v: v["bandwidth"])
        if quality == "worst":
            return min(variants, key=lambda v: v["bandwidth"])
        try:
            target = int(quality)
            return min(variants, key=lambda v: abs(v["bandwidth"] - target))
        except ValueError:
            return max(variants, key=lambda v: v["bandwidth"])

    # ------------------------------------------------------------------
    # Output path resolution
    # ------------------------------------------------------------------
    def _resolve_output(self, output: Optional[str], source_url: str) -> Path:
        if output:
            p = Path(output)
            if p.suffix:
                return p
            return p.with_suffix(".ts")
        # derive name from URL
        parsed = urlparse(source_url)
        stem = Path(parsed.path).stem or "video"
        # clean invalid filename chars
        safe = re.sub(r'[<>:"/\\|?*]', "_", stem)
        return self.output_dir / f"{safe}_{int(time.time())}.ts"

    # ------------------------------------------------------------------
    # Segment download
    # ------------------------------------------------------------------
    def _download_segments(self, playlist: HLSPlaylist,
                           tmp_dir: Path,
                           progress_callback: Optional[Callable] = None
                           ) -> List[Path]:
        """Return sorted list of downloaded segment paths."""

        key_cache: Dict[str, bytes] = {}
        _start_time = time.time()
        _bytes_downloaded = [0]  # mutable for closure access
        _lock = threading.Lock()  # guard _bytes_downloaded

        def _get_key(key_uri: str) -> bytes:
            if key_uri not in key_cache:
                logger.info("Downloading AES-128 key: %s", key_uri)
                resp = self.session.get(
                    key_uri,
                    timeout=(self.connect_timeout, self.read_timeout),
                )
                resp.raise_for_status()
                key_cache[key_uri] = resp.content
            return key_cache[key_uri]

        def _dl_one(idx: int, seg: Dict) -> Tuple[int, Optional[Path], Optional[str]]:
            url = seg["url"]
            dest = tmp_dir / f"seg_{idx:06d}.ts"

            for attempt in range(1, self.retries + 1):
                try:
                    # ── stream the segment to disk + track speed ──
                    resp = self.session.get(
                        url,
                        stream=True,                          # ★ 关键：流式下载
                        timeout=(self.connect_timeout, self.read_timeout),
                    )
                    resp.raise_for_status()

                    seg_data = bytearray()
                    seg_start = time.time()
                    last_progress = seg_start
                    last_bytes = 0
                    last_data_time = seg_start

                    for chunk in resp.iter_content(chunk_size=65536):
                        if chunk:
                            seg_data.extend(chunk)
                            last_data_time = time.time()
                            # ── speed check every 5 seconds ──
                            now = time.time()
                            if now - last_progress >= 5:
                                interval = now - last_progress
                                bytes_in_interval = len(seg_data) - last_bytes
                                speed = bytes_in_interval / interval if interval > 0 else 0
                                last_progress = now
                                last_bytes = len(seg_data)
                                if speed < self.min_speed and (now - seg_start) > 10:
                                    # Too slow — abort and retry
                                    resp.close()
                                    raise IOError(
                                        f"Segment {idx} speed {speed/1024:.0f} KB/s "
                                        f"below minimum {self.min_speed/1024:.0f} KB/s"
                                    )
                        else:
                            # Empty chunk = potential stall
                            if time.time() - last_data_time > max(self.read_timeout * 2, 60):
                                resp.close()
                                raise IOError(
                                    f"Segment {idx} stalled: no data for "
                                    f"{max(self.read_timeout * 2, 60):.0f}s"
                                )

                    data = bytes(seg_data)

                    # decrypt if needed
                    key_uri = seg.get("key_uri")
                    if key_uri and HAS_AES:
                        key = _get_key(key_uri)
                        iv = seg.get("key_iv")
                        if iv is None:
                            iv = idx.to_bytes(16, byteorder="big")
                        cipher = _AES.new(key, _AES.MODE_CBC, iv=iv)
                        data = cipher.decrypt(data)
                    elif key_uri and not HAS_AES:
                        return idx, None, (
                            "AES-128 encrypted but pycryptodome not installed. "
                            "Run: pip install pycryptodome"
                        )

                    dest.write_bytes(data)
                    with _lock:
                        _bytes_downloaded[0] += len(data)
                    return idx, dest, None

                except (
                    requests.RequestException,
                    IOError, ConnectionError, TimeoutError,
                    IncompleteRead, Urllib3ProtocolError,
                    Exception,  # catch-all — any error triggers resume+retry
                ) as exc:
                    if attempt < self.retries:
                        self._clear_connection_pool()
                        wait = min(2 ** attempt, 60)
                        logger.warning("Retry %d/%d for seg %d after %.0fs  (%s: %s)",
                                       attempt, self.retries, idx, wait,
                                       type(exc).__name__, exc)
                        time.sleep(wait)
                    else:
                        return idx, None, str(exc)

            return idx, None, "max retries exceeded"

        n = len(playlist.segments)
        results: List[Optional[Path]] = [None] * n
        errors: List[Optional[str]] = [None] * n

        if self.max_workers > 1 and n > 1:
            with ThreadPoolExecutor(max_workers=min(self.max_workers, n)) as pool:
                fut_map = {pool.submit(_dl_one, i, playlist.segments[i]): i
                           for i in range(n)}
                for fut in as_completed(fut_map):
                    i, path, err = fut.result()
                    results[i] = path
                    errors[i] = err
                    done = sum(1 for r in results if r is not None)
                    elapsed = time.time() - _start_time
                    speed = _bytes_downloaded[0] / elapsed if elapsed > 0 else 0
                    logger.info("Progress: %d / %d segments", done, n)
                    if progress_callback:
                        progress_callback(done, n, speed, "downloading")
        else:
            for i in range(n):
                _, path, err = _dl_one(i, playlist.segments[i])
                results[i] = path
                errors[i] = err
                done = i + 1
                elapsed = time.time() - _start_time
                speed = _bytes_downloaded[0] / elapsed if elapsed > 0 else 0
                if done % max(1, n // 20) == 0 or done == n:
                    logger.info("Progress: %d / %d segments", done, n)
                    if progress_callback:
                        progress_callback(done, n, speed, "downloading")

        # check errors
        for i, (path, err) in enumerate(zip(results, errors)):
            if err:
                raise RuntimeError(f"Segment {i} failed: {err}")

        return [p for p in results if p is not None]  # type: ignore

    # ------------------------------------------------------------------
    # Concatenation
    # ------------------------------------------------------------------
    @staticmethod
    def _concatenate(segments: List[Path], output: Path):
        """Merge TS segments using chunked copy to avoid large RAM allocations."""
        logger.info("Merging %d segments -> %s", len(segments), output)
        with open(output, "wb") as dst:
            for seg in segments:
                with open(seg, "rb") as src:
                    while True:
                        chunk = src.read(2 * 1024 * 1024)  # 2 MiB chunks
                        if not chunk:
                            break
                        dst.write(chunk)

    # ------------------------------------------------------------------
    # Direct MP4 download — chunked via Range requests
    # ------------------------------------------------------------------
    def _download_mp4(self, url: str, output: Optional[str] = None,
                      progress_callback: Optional[Callable] = None) -> Path:
        """
        Download an MP4 file using parallel Range requests.

        Each chunk (default 20 MiB) gets its own HTTP connection and timeout,
        so a single stalled connection never blocks the whole download.
        """
        output_path = self._resolve_output(output, url)
        if output_path.suffix.lower() != ".mp4":
            output_path = output_path.with_suffix(".mp4")

        chunk_size = 20 * 1024 * 1024  # 20 MiB per chunk

        # ── 1. HEAD request to discover total size ──
        logger.info("Probing: %s", url)
        try:
            head = self.session.head(url, timeout=(self.connect_timeout, self.read_timeout))
            head.raise_for_status()
        except Exception:
            # Some CDNs reject HEAD — fall back to GET with Range 0-0
            head = self.session.get(
                url,
                headers={"Range": "bytes=0-0"},
                timeout=(self.connect_timeout, self.read_timeout),
            )
            head.raise_for_status()

        total = int(head.headers.get("Content-Length", 0))
        accept_ranges = head.headers.get("Accept-Ranges", "").lower()
        # Also check if server responded 206 to our Range probe
        supports_range = accept_ranges == "bytes" or head.status_code == 206

        if total == 0:
            raise ValueError("Cannot determine file size — server returned Content-Length: 0")

        logger.info("Total size: %.1f MiB  (Range support: %s)",
                     total / 1048576, "yes" if supports_range else "no")

        if not supports_range:
            # Fallback: single-connection streaming (server doesn't support Range)
            logger.warning("Server doesn't support Range — falling back to single connection")
            return self._download_mp4_stream(url, output_path, total, progress_callback)

        # ── 2. Check for existing partial file ──
        resume_from = 0
        if output_path.exists():
            resume_from = output_path.stat().st_size
            if resume_from > 0:
                logger.info("Resuming from byte %d (%.1f MB) — will re-download final chunk",
                             resume_from, resume_from / 1048576)

        # ── 3. Build chunk list (skip already-downloaded chunks) ──
        chunks: List[Tuple[int, int, int]] = []  # (start, end, index)
        idx = 0
        pos = 0
        while pos < total:
            end = min(pos + chunk_size - 1, total - 1)
            if end >= resume_from:  # only download chunks we don't have yet
                chunks.append((pos, end, idx))
            idx += 1
            pos = end + 1

        total_chunks = idx
        pending = len(chunks)
        logger.info("Chunks: %d total, %d to download (%.1f MiB each)",
                     total_chunks, pending, chunk_size / 1048576)

        # ── 4. Download chunks in parallel ──
        tmp_dir = self.output_dir / f".tmp_mp4_{int(time.time() * 1000)}"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        _bytes_done = [0]
        _lock = threading.Lock()
        _start = time.time()

        def _dl_chunk(start: int, end: int, cidx: int) -> Tuple[int, Optional[Path], Optional[str]]:
            """Download one byte-range chunk to a temp segment file."""
            seg_path = tmp_dir / f"chunk_{cidx:06d}.bin"
            headers = {"Range": f"bytes={start}-{end}"}

            for attempt in range(1, self.retries + 1):
                try:
                    resp = self.session.get(
                        url,
                        headers=headers,
                        stream=True,
                        timeout=(self.connect_timeout, self.read_timeout),
                    )
                    resp.raise_for_status()

                    expected = end - start + 1
                    data = bytearray()
                    last_data = time.time()

                    for chunk in resp.iter_content(chunk_size=65536):
                        if chunk:
                            data.extend(chunk)
                            last_data = time.time()
                        elif time.time() - last_data > max(self.read_timeout * 2, 60):
                            resp.close()
                            raise IOError("Chunk stalled")

                    if len(data) != expected:
                        raise IOError(
                            f"Chunk size mismatch: got {len(data)}, expected {expected}"
                        )

                    seg_path.write_bytes(data)
                    with _lock:
                        _bytes_done[0] += len(data)
                    return cidx, seg_path, None

                except Exception as exc:
                    if attempt < self.retries:
                        self._clear_connection_pool()
                        wait = min(2 ** attempt, 60)
                        logger.warning("Chunk %d retry %d/%d after %.0fs (%s: %s)",
                                       cidx, attempt, self.retries, wait,
                                       type(exc).__name__, exc)
                        time.sleep(wait)
                    else:
                        return cidx, None, str(exc)

            return cidx, None, "max retries"

        # Submit all chunks
        workers = min(self.max_workers, pending) if pending > 0 else 1
        chunk_results: Dict[int, Path] = {}
        chunk_errors: List[str] = []

        with ThreadPoolExecutor(max_workers=workers) as pool:
            fut_map = {
                pool.submit(_dl_chunk, s, e, i): i
                for s, e, i in chunks
            }
            for fut in as_completed(fut_map):
                cidx, seg_path, err = fut.result()
                if err:
                    chunk_errors.append(f"Chunk {cidx}: {err}")
                elif seg_path:
                    chunk_results[cidx] = seg_path

                done = len(chunk_results)
                if progress_callback:
                    pct = resume_from + _bytes_done[0]
                    elapsed = time.time() - _start
                    speed = _bytes_done[0] / elapsed if elapsed > 0 else 0
                    progress_callback(pct, total, speed, "downloading_mp4")
                logger.info("Chunks: %d/%d done", done, pending)

        if chunk_errors:
            _rmtree(tmp_dir)
            raise RuntimeError(f"Failed chunks: {'; '.join(chunk_errors[:5])}")

        # ── 5. Assemble final file ──
        logger.info("Assembling %d chunks -> %s", total_chunks, output_path)

        # Read existing partial file content (if resuming)
        existing_data = b""
        if resume_from > 0 and output_path.exists():
            existing_data = output_path.read_bytes()
            if len(existing_data) != resume_from:
                logger.warning("Existing file size mismatch, restarting from scratch")
                existing_data = b""
                resume_from = 0

        with open(output_path, "wb") as dst:
            if existing_data:
                dst.write(existing_data)
            for cidx in sorted(chunk_results.keys()):
                seg_path = chunk_results[cidx]
                with open(seg_path, "rb") as src:
                    while True:
                        buf = src.read(2 * 1024 * 1024)
                        if not buf:
                            break
                        dst.write(buf)

        # Clean up
        _rmtree(tmp_dir)

        size_mb = output_path.stat().st_size / 1048576
        logger.info("MP4 done: %s  (%.1f MiB)", output_path, size_mb)
        if progress_callback:
            progress_callback(total, total, 0, "done")
        return output_path.resolve()

    # ------------------------------------------------------------------
    # Fallback: single-connection streaming (for servers without Range)
    # ------------------------------------------------------------------
    def _download_mp4_stream(self, url: str, output_path: Path, total: int,
                             progress_callback: Optional[Callable] = None) -> Path:
        """Single-connection streaming download with speed monitoring."""
        resume_from = 0
        if output_path.exists():
            resume_from = output_path.stat().st_size
            if resume_from > 0:
                logger.info("Resuming from byte %d", resume_from)

        downloaded = resume_from

        for attempt in range(1, self.retries + 1):
            last_speed_check = time.time()
            bytes_at_last_check = downloaded
            attempt_start = time.time()

            try:
                headers = {}
                if resume_from > 0:
                    headers["Range"] = f"bytes={resume_from}-"

                resp = self.session.get(
                    url, stream=True,
                    timeout=(self.connect_timeout, self.read_timeout),
                    headers=headers,
                )
                resp.raise_for_status()

                if resp.status_code != 206 and resume_from > 0:
                    logger.warning("Server doesn't support resume, restarting")
                    resume_from = 0
                    downloaded = 0

                mode = "ab" if resume_from > 0 else "wb"
                with open(output_path, mode) as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)

                            now = time.time()
                            if now - last_speed_check >= 5:
                                interval = now - last_speed_check
                                speed = (downloaded - bytes_at_last_check) / interval \
                                    if interval > 0 else 0
                                last_speed_check = now
                                bytes_at_last_check = downloaded
                                if speed < self.min_speed and (now - attempt_start) > 15:
                                    resp.close()
                                    raise IOError(
                                        f"Speed {speed/1024:.0f} KB/s below min"
                                    )

                            if progress_callback and total > 0:
                                attempt_elapsed = time.time() - attempt_start
                                attempt_speed = (downloaded - resume_from) / attempt_elapsed \
                                    if attempt_elapsed > 0 else 0
                                progress_callback(downloaded, total, attempt_speed, "downloading_mp4")

                if downloaded >= total:
                    if progress_callback:
                        progress_callback(downloaded, downloaded, 0, "done")
                    return output_path.resolve()

                raise IOError(f"Incomplete: {downloaded}/{total} bytes")

            except Exception as exc:
                resume_from = output_path.stat().st_size if output_path.exists() else 0
                downloaded = resume_from
                if attempt < self.retries:
                    self._clear_connection_pool()
                    wait = min(2 ** attempt, 60)
                    logger.warning("Stream retry %d/%d: %s: %s",
                                   attempt, self.retries, type(exc).__name__, exc)
                    if progress_callback:
                        progress_callback(downloaded, total, 0, "retrying")
                    time.sleep(wait)
                else:
                    raise

        raise RuntimeError("Max retries exceeded")

    # ------------------------------------------------------------------
    # Optional ffmpeg remux
    # ------------------------------------------------------------------
    @staticmethod
    def _remux_mp4(ts_path: Path, mp4_path: Path) -> bool:
        """Remux .ts -> .mp4 via ffmpeg (copy-codec, faststart)."""
        try:
            r = subprocess.run(
                ["ffmpeg", "-i", str(ts_path),
                 "-c", "copy",
                 "-movflags", "+faststart",
                 "-y",
                 str(mp4_path)],
                capture_output=True, text=True, timeout=600,
            )
            if r.returncode == 0:
                logger.info("Remuxed to MP4")
                return True
            logger.warning("ffmpeg remux failed:\n%s", r.stderr[:500])
        except FileNotFoundError:
            logger.info("ffmpeg not found – keeping .ts container")
        except subprocess.TimeoutExpired:
            logger.warning("ffmpeg timed out – keeping .ts container")
        return False


# ===================================================================
# Helpers
# ===================================================================
def _parse_attrs(line: str) -> Dict[str, str]:
    """Parse ``KEY="VALUE"`` or ``KEY=VALUE`` attribute lists from HLS tags."""
    attrs: Dict[str, str] = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([^",\s]+))', line):
        attrs[m.group(1)] = m.group(2) or m.group(3) or ""
    return attrs


def _fmt_bps(bps: int) -> str:
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.1f} Mbps"
    return f"{bps // 1000} Kbps"


def _rmtree(path: Path):
    """Remove a directory tree."""
    for child in path.iterdir():
        if child.is_dir():
            _rmtree(child)
        else:
            child.unlink()
    path.rmdir()


# ===================================================================
# Standalone CLI
# ===================================================================
def main_entry(args: Optional[List[str]] = None):
    """Entry point for ``python hls_downloader.py <url>``."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Download HLS (m3u8) video streams")
    parser.add_argument("url", help="m3u8 playlist URL")
    parser.add_argument("-o", "--output", default=None,
                        help="Output file path")
    parser.add_argument("-q", "--quality", default="best",
                        help="Quality: best / worst / bandwidth")
    parser.add_argument("-d", "--output-dir", default="downloads",
                        help="Output directory (default: downloads)")
    parser.add_argument("-w", "--workers", type=int, default=10,
                        help="Parallel download workers (default: 10)")
    parser.add_argument("--verbose", action="store_true",
                        help="Verbose logging")

    opts = parser.parse_args(args)

    logging.basicConfig(
        level=logging.DEBUG if opts.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    dl = HLSDownloader(output_dir=opts.output_dir, max_workers=opts.workers)
    result = dl.download(opts.url, output=opts.output, quality=opts.quality)
    print(f"\n[OK] 视频已保存: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main_entry())
