#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida-based video capture for ClassIn ijkplayer courses.

Hooks avformat_open_input and av_read_frame in avformat-58.dll
to capture video URL and decrypted packet data. The captured
packets are written to a structured binary file (.dcap) that
can later be remuxed into a playable MP4 by remuxer.py.
"""

import os
import sys
import json
import time
import struct
import base64
import logging
import threading
from pathlib import Path
from typing import Optional, Callable, List, Dict
from dataclasses import dataclass, field

import frida

logger = logging.getLogger("frida_capture")

# -------------------------------------------------------------------
# Capture file format (.dcap)
# -------------------------------------------------------------------
DCAP_MAGIC = b"DCAP"
DCAP_VERSION = 1
PKT_MAGIC = b"PKT\x00"

# -------------------------------------------------------------------
# Stream info dataclass
# -------------------------------------------------------------------
@dataclass
class FridaStreamInfo:
    """Info about a captured video stream."""
    url: str
    source: str = "frida"
    timestamp: str = field(default_factory=lambda: time.strftime("%H:%M:%S"))
    filepath: str = ""          # path to .dcap capture file
    codec_info: List[Dict] = field(default_factory=list)

# -------------------------------------------------------------------
# Packet writer — writes structured .dcap files
# -------------------------------------------------------------------
class PacketWriter:
    """Writes captured AVPackets to a structured binary file."""

    def __init__(self, output_dir: str = "captures"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._file = None
        self._lock = threading.Lock()
        self._packet_count = 0
        self._url = ""
        self._started = False

    def start_session(self, url: str, streams: List[Dict]):
        """Begin a new capture session."""
        with self._lock:
            if self._file:
                self._close()
            self._url = url
            self._packet_count = 0

            # Generate filename from URL and timestamp
            ts = time.strftime("%Y%m%d_%H%M%S")
            safe_name = url.split("?")[0].split("/")[-1][:40] or "video"
            # Replace unsafe chars
            safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in safe_name)
            fname = f"{ts}_{safe_name}.dcap"
            fpath = self.output_dir / fname

            self._file = open(fpath, "wb")
            self._write_header(url, streams)
            self._started = True
            logger.info("Capture started: %s (%d streams)", fpath, len(streams))
            return str(fpath)

    def _write_header(self, url: str, streams: List[Dict]):
        f = self._file
        # Magic + version
        f.write(struct.pack("<4sI", DCAP_MAGIC, DCAP_VERSION))
        # URL (length-prefixed UTF-8)
        url_bytes = url.encode("utf-8")
        f.write(struct.pack("<I", len(url_bytes)))
        f.write(url_bytes)
        # Stream count
        f.write(struct.pack("<I", len(streams)))
        # Each stream
        for st in streams:
            f.write(struct.pack("<i", st.get("index", 0)))
            f.write(struct.pack("<i", st.get("codec_type", -1)))
            f.write(struct.pack("<i", st.get("codec_id", 0)))
            edata = b""
            edata_b64 = st.get("extradata_b64")
            if edata_b64:
                try:
                    edata = base64.b64decode(edata_b64)
                except Exception:
                    edata = b""
            f.write(struct.pack("<I", len(edata)))
            if edata:
                f.write(edata)
        f.flush()

    def write_packet(self, stream_index: int, pts: int, dts: int, data: bytes):
        """Write a single packet."""
        with self._lock:
            if not self._file:
                return
            self._file.write(struct.pack("<4siqqI",
                PKT_MAGIC, stream_index, pts, dts, len(data)))
            self._file.write(data)
            self._packet_count += 1

    def end_session(self):
        """Close the current session cleanly."""
        with self._lock:
            if self._file:
                self._close()

    def _close(self):
        if self._file:
            # Write footer with packet count
            self._file.write(b"END\x00")
            self._file.write(struct.pack("<I", self._packet_count))
            self._file.flush()
            self._file.close()
            self._file = None
            self._started = False
            logger.info("Capture ended: %d packets", self._packet_count)

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def is_active(self) -> bool:
        return self._started


# -------------------------------------------------------------------
# Frida capturer
# -------------------------------------------------------------------
class FridaCapturer:
    """
    Attaches to ClassIn process and hooks FFmpeg functions to capture
    video URL and packet data.
    """

    HOOK_SCRIPT = str(Path(__file__).parent / "frida_hook.js")

    def __init__(self, on_stream: Optional[Callable] = None,
                 on_error: Optional[Callable] = None,
                 output_dir: str = "captures"):
        self.on_stream = on_stream
        self.on_error = on_error
        self.output_dir = output_dir

        self._session: Optional[frida.Session] = None
        self._script: Optional[frida.Script] = None
        self._running = False
        self._writer = PacketWriter(output_dir)
        self._current_url = ""
        self._current_filepath = ""
        self._stream_info_cache: Dict[int, str] = {}  # sid -> url
        self._frida_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Process discovery
    # ------------------------------------------------------------------
    @staticmethod
    def find_classin() -> Optional[frida.Process]:
        """Find a running ClassIn process."""
        try:
            device = frida.get_local_device()
            for proc in device.enumerate_processes():
                if proc.name.lower() == "classin.exe":
                    return proc
        except Exception as exc:
            logger.debug("Failed to enumerate processes: %s", exc)
        return None

    @staticmethod
    def find_classin_with_module() -> Optional[frida.Process]:
        """Find ClassIn process that has avformat-58.dll loaded (Frida 17.x compatible)."""
        try:
            device = frida.get_local_device()
            for proc in device.enumerate_processes():
                if proc.name.lower() == "classin.exe":
                    try:
                        session = device.attach(proc.pid)
                        script = session.create_script("""
                            (function() {
                                try {
                                    Process.getModuleByName('avformat-58.dll');
                                    send({type: 'found'});
                                } catch(e) {
                                    send({type: 'not_found'});
                                }
                            })();
                        """)
                        result = {"has_module": False}
                        def on_msg(msg, data):
                            if msg.get("payload", {}).get("type") == "found":
                                result["has_module"] = True
                        script.on("message", on_msg)
                        script.load()
                        import time
                        time.sleep(0.15)
                        script.unload()
                        session.detach()
                        if result["has_module"]:
                            return proc
                    except Exception:
                        pass
        except Exception as exc:
            logger.debug("Failed to find ClassIn with module: %s", exc)
        return None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self, proc: Optional[frida.Process] = None) -> bool:
        """Start Frida capture."""
        if self._running:
            return True

        if proc is None:
            proc = self.find_classin()
            if proc is None:
                msg = "ClassIn.exe not found. Please start ClassIn first."
                logger.warning(msg)
                if self.on_error:
                    self.on_error(msg)
                return False

        try:
            device = frida.get_local_device()
            self._session = device.attach(proc.pid)
            logger.info("Attached to ClassIn (PID %d)", proc.pid)

            # Wait for avformat-58.dll to be loaded
            self._wait_for_module("avformat-58.dll", timeout=10.0)

            # Load hook script
            hook_code = Path(self.HOOK_SCRIPT).read_text(encoding="utf-8")
            self._script = self._session.create_script(hook_code)
            self._script.on("message", self._on_message)
            self._script.load()

            self._running = True
            logger.info("Frida hooks installed")
            return True

        except frida.ProcessNotFoundError:
            msg = "ClassIn process not found."
            logger.error(msg)
            if self.on_error:
                self.on_error(msg)
            return False
        except Exception as exc:
            msg = f"Frida attach failed: {exc}"
            logger.error(msg)
            if self.on_error:
                self.on_error(msg)
            return False

    def stop(self):
        """Stop capture and detach."""
        self._running = False
        self._writer.end_session()

        if self._script:
            try:
                self._script.unload()
            except Exception:
                pass
            self._script = None

        if self._session:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None

        logger.info("Frida capture stopped")

    def _wait_for_module(self, name: str, timeout: float = 10.0):
        """Wait for a DLL to be loaded in the target process (Frida 17.x compatible)."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                script = self._session.create_script("""
                    (function() {
                        try {
                            var mod = Process.getModuleByName('%s');
                            send({type: 'ok', name: mod.name, base: mod.base.toString()});
                        } catch(e) {
                            send({type: 'waiting'});
                        }
                    })();
                """ % name)
                result = {"found": False}

                def on_msg(msg, data):
                    payload = msg.get("payload", {})
                    if payload.get("type") == "ok":
                        result["found"] = True
                        result["name"] = payload.get("name", "")
                        result["base"] = payload.get("base", "")

                script.on("message", on_msg)
                script.load()
                time.sleep(0.1)
                script.unload()

                if result["found"]:
                    logger.info("Module %s loaded at %s", result["name"], result["base"])
                    return True
            except Exception as exc:
                logger.debug("Module check error: %s", exc)
            time.sleep(0.3)
        logger.warning("Timeout waiting for module: %s", name)
        return False

    # ------------------------------------------------------------------
    # Frida message handler
    # ------------------------------------------------------------------
    def _on_message(self, message, data):
        """Handle messages from the Frida hook script."""
        msg_type = message.get("type", "unknown")

        if msg_type == "error":
            payload = message.get("payload", {})
            err_msg = payload.get("msg", str(message))
            logger.error("Frida error: %s", err_msg)
            return

        if msg_type == "send":
            payload = message.get("payload", {})
            ptype = payload.get("type", "")

            if ptype == "url":
                self._handle_url(payload)

            elif ptype == "streams":
                self._handle_streams(payload)

            elif ptype == "pkt":
                self._handle_packet(payload, data)

            elif ptype == "end":
                self._handle_end(payload)

            elif ptype in ("ready", "hooks_installed", "status"):
                logger.debug("Frida: %s", ptype)

            elif ptype == "error":
                logger.error("Frida JS error: %s", payload.get("msg", ""))

            else:
                logger.debug("Frida msg: %s", ptype)

    def _handle_url(self, payload: dict):
        url = payload.get("url", "")
        if not url:
            return
        sid = payload.get("sid", 0)
        self._current_url = url
        self._stream_info_cache[sid] = url
        logger.info("Video URL captured: %s", url[:120])

        # Extract real URL from ijkplayer protocol wrapper
        # ijkio:cache:ffio:https://... → https://...
        real_url = url
        if "ijkio:cache:ffio:" in url:
            real_url = url.split("ijkio:cache:ffio:", 1)[1]
            logger.info("Real URL extracted: %s", real_url[:120])
        elif "ijkio:" in url:
            # Other ijkio schemes: try to find http/https
            import re
            match = re.search(r'(https?://.+)', url)
            if match:
                real_url = match.group(1)
                logger.info("Real URL extracted: %s", real_url[:120])

        # Create a StreamInfo-like object for the callback
        info = FridaStreamInfo(url=real_url)
        if self.on_stream:
            self.on_stream(info)

    def _handle_streams(self, payload: dict):
        sid = payload.get("sid", 0)
        streams = payload.get("streams", [])
        url = self._stream_info_cache.get(sid, self._current_url)

        # Log what we found
        type_names = {0: "video", 1: "audio", 2: "subtitle"}
        parts = []
        for s in streams:
            tn = type_names.get(s.get("codec_type"), "unknown")
            parts.append(f"{tn}(idx={s['index']}, codec={s['codec_id']})")
        logger.info("Streams for %s: %s", url[:80] if url else "?", ", ".join(parts))

        # Start a packet capture file
        fpath = self._writer.start_session(url, streams)
        self._current_filepath = fpath

        # Update the StreamInfo with filepath
        if self.on_stream:
            info = FridaStreamInfo(
                url=url,
                filepath=fpath,
                codec_info=streams
            )
            self.on_stream(info)

    def _handle_packet(self, payload: dict, data: bytes):
        if not data:
            return
        stream_index = payload.get("si", 0)
        pts = int(payload.get("pts", "0"))
        dts = int(payload.get("dts", "0"))

        self._writer.write_packet(stream_index, pts, dts, data)

        # Progress log every 300 packets
        count = payload.get("n", 0)
        if count % 300 == 0:
            logger.debug("Packets: %d (last stream=%d, size=%d)",
                         count, stream_index, len(data))

    def _handle_end(self, payload: dict):
        count = payload.get("pkt_count", self._writer.packet_count)
        logger.info("Session ended: %d total packets", count)
        self._writer.end_session()

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    @property
    def is_active(self) -> bool:
        return self._running

    @property
    def current_url(self) -> str:
        return self._current_url

    @property
    def packet_count(self) -> int:
        return self._writer.packet_count


# -------------------------------------------------------------------
# Standalone entry point
# -------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    def on_stream(info: FridaStreamInfo):
        print(f"\n>>> STREAM: {info.url}")
        if info.filepath:
            print(f"    Capture file: {info.filepath}")
        if info.codec_info:
            for st in info.codec_info:
                print(f"    Stream {st['index']}: type={st['codec_type']}, codec={st['codec_id']}")

    def on_error(msg: str):
        print(f"ERROR: {msg}")

    cap = FridaCapturer(on_stream=on_stream, on_error=on_error, output_dir="captures")
    print("Starting Frida capture... Press Ctrl+C to stop.")
    print("Make sure ClassIn is running and playing an ijkplayer video.")

    if cap.start():
        try:
            while cap.is_active:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\nStopping...")
        finally:
            cap.stop()
    else:
        print("Failed to start capture.")
