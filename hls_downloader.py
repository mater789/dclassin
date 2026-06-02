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
        min_speed: float = 1024.0,   # bytes/sec – abort segment if slower than this
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

                    for chunk in resp.iter_content(chunk_size=65536):
                        if chunk:
                            seg_data.extend(chunk)
                            # ── speed check every 5 seconds ──
                            now = time.time()
                            if now - last_progress >= 5:
                                elapsed = now - seg_start
                                speed = len(seg_data) / elapsed if elapsed > 0 else 0
                                last_progress = now
                                if speed < self.min_speed and elapsed > 10:
                                    # Too slow — abort and retry
                                    resp.close()
                                    raise IOError(
                                        f"Segment {idx} speed {speed/1024:.0f} KB/s "
                                        f"below minimum {self.min_speed/1024:.0f} KB/s"
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

                except requests.RequestException as exc:
                    if attempt < self.retries:
                        wait = min(2 ** attempt, 60)
                        logger.warning("Retry %d/%d for seg %d after %.0fs  (%s)",
                                       attempt, self.retries, idx, wait, exc)
                        time.sleep(wait)
                    else:
                        return idx, None, str(exc)
                except (IOError, ConnectionError, TimeoutError) as exc:
                    if attempt < self.retries:
                        wait = min(2 ** attempt, 60)
                        logger.warning("Retry %d/%d for seg %d after %.0fs  (%s)",
                                       attempt, self.retries, idx, wait, exc)
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
    # Direct MP4 download (progressive download)
    # ------------------------------------------------------------------
    def _download_mp4(self, url: str, output: Optional[str] = None,
                      progress_callback: Optional[Callable] = None) -> Path:
        """Download a single MP4 file with resume + retry support."""
        output_path = self._resolve_output(output, url)
        if output_path.suffix.lower() != ".mp4":
            output_path = output_path.with_suffix(".mp4")

        # Check for existing partial download
        resume_from = 0
        if output_path.exists():
            resume_from = output_path.stat().st_size
            if resume_from > 0:
                logger.info("Resuming from byte %d (%.1f MB)", resume_from, resume_from / 1048576)

        total = 0
        downloaded = resume_from
        start_time = time.time()
        chunk_timeout = (self.connect_timeout, self.read_timeout)
        speed_check_interval = 5  # seconds between speed checks
        last_speed_check = time.time()
        bytes_at_last_check = downloaded

        for attempt in range(1, self.retries + 1):
            try:
                headers = {}
                if resume_from > 0:
                    headers["Range"] = f"bytes={resume_from}-"

                logger.info("Downloading MP4 (attempt %d/%d): %s", attempt, self.retries, url)
                resp = self.session.get(url, stream=True, timeout=chunk_timeout, headers=headers)
                resp.raise_for_status()

                # Handle resume response
                if resp.status_code == 206:
                    content_range = resp.headers.get("Content-Range", "")
                    if "bytes" in content_range:
                        try:
                            total = int(content_range.split("/")[-1])
                        except ValueError:
                            total = resume_from + int(resp.headers.get("content-length", 0))
                else:
                    total = int(resp.headers.get("content-length", 0))
                    if resume_from > 0:
                        # Server doesn't support resume, restart from 0
                        logger.warning("Server doesn't support resume, restarting")
                        resume_from = 0
                        downloaded = 0

                # Open file in append mode if resuming
                mode = "ab" if resume_from > 0 else "wb"
                seg_start = time.time()
                with open(output_path, mode) as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)

                            # ── periodic speed check ──
                            now = time.time()
                            if now - last_speed_check >= speed_check_interval:
                                interval = now - last_speed_check
                                bytes_in_interval = downloaded - bytes_at_last_check
                                speed = bytes_in_interval / interval if interval > 0 else 0
                                last_speed_check = now
                                bytes_at_last_check = downloaded
                                elapsed = now - seg_start
                                if speed < self.min_speed and elapsed > 15:
                                    resp.close()
                                    raise IOError(
                                        f"MP4 download speed {speed/1024:.0f} KB/s "
                                        f"below minimum {self.min_speed/1024:.0f} KB/s"
                                    )

                            if progress_callback and total > 0:
                                elapsed = time.time() - start_time
                                speed = downloaded / elapsed if elapsed > 0 else 0
                                progress_callback(downloaded, total, speed, "downloading_mp4")

                # Verify download
                if total > 0 and downloaded < total:
                    raise IOError(f"Incomplete download: {downloaded}/{total} bytes")

                if progress_callback:
                    progress_callback(downloaded, downloaded, 0.0, "done")

                size_mb = output_path.stat().st_size / 1048576
                logger.info("MP4 done: %s  (%.1f MiB)", output_path, size_mb)
                return output_path.resolve()

            except (requests.RequestException, IOError, ConnectionError, TimeoutError) as exc:
                resume_from = output_path.stat().st_size if output_path.exists() else 0
                downloaded = resume_from
                if attempt < self.retries:
                    wait = min(2 ** attempt, 60)
                    logger.warning("MP4 download interrupted (attempt %d/%d): %s", attempt, self.retries, exc)
                    logger.info("Will resume from byte %d after %.0fs...", resume_from, wait)
                    if progress_callback:
                        progress_callback(downloaded, total or downloaded * 2, 0, "retrying")
                    time.sleep(wait)
                else:
                    logger.error("MP4 download failed after %d attempts: %s", self.retries, exc)
                    raise

        # Should not reach here
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
