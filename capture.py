#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HLS 流地址捕获模块

提供三种捕获方式（可同时运行）：
  1. ProxyCapture  — 本地 HTTP 代理，自动设置 Windows 系统代理，捕获 HTTP 流量中的 m3u8 URL
  2. CDPCapture    — 通过 Chrome DevTools Protocol 连接 ClassIn 调试端口
  3. Manual        — 用户手动粘贴 URL

其中 ProxyCapture 是最可靠的方式，不依赖 ClassIn 版本，也不需要额外依赖。
"""

import os
import re
import sys
import json
import time
import socket
import select
import logging
import struct
import threading
import subprocess
from pathlib import Path
from typing import List, Optional, Set, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

try:
    from websocket import create_connection, WebSocketTimeoutException
    HAS_WEBSOCKET = True
except ImportError:
    HAS_WEBSOCKET = False

try:
    import frida
    HAS_FRIDA = True
except ImportError:
    HAS_FRIDA = False

logger = logging.getLogger("capture")

# try Windows registry for proxy settings
try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# ===================================================================
#  Shared data
# ===================================================================
@dataclass
class StreamInfo:
    url: str
    source: str = "proxy"       # proxy / cdp / manual
    timestamp: str = field(default_factory=lambda: time.strftime("%H:%M:%S"))


# ===================================================================
#  Proxy-based capture  (most reliable)
# ===================================================================
class ProxyCapturer:
    """
    Socket-based HTTP forward proxy that captures m3u8 URLs.

    - HTTP GET: forwards request, inspects URL for .m3u8
    - CONNECT (HTTPS): establishes tunnel, logs hostname only
    - Can optionally set Windows system proxy automatically
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8888,
                 on_stream: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.on_stream = on_stream
        self._server: Optional[socket.socket] = None
        self._running = False
        self._threads: List[threading.Thread] = []
        self._seen_urls: Set[str] = set()
        self._old_proxy: Optional[dict] = None  # saved Win proxy settings

        # diagnostics
        self.request_count = 0
        self.recent_hosts: List[str] = []

    # ------------------------------------------------------------------
    #  Lifecycle
    # ------------------------------------------------------------------
    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(100)
        self._server.settimeout(1.0)
        self._running = True
        logger.info("Proxy listening on %s:%d", self.host, self.port)
        while self._running:
            try:
                client, addr = self._server.accept()
                t = threading.Thread(target=self._handle_client,
                                     args=(client,), daemon=True)
                t.start()
                self._threads.append(t)
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._running = False
        self._restore_proxy()
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    #  Windows proxy helpers
    # ------------------------------------------------------------------
    def set_system_proxy(self):
        """Configure Windows to route traffic through this proxy."""
        if not HAS_WINREG:
            logger.warning("winreg not available – cannot set system proxy")
            return False
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0, winreg.KEY_ALL_ACCESS,
            )
            # save current
            try:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
                self._old_proxy = dict(enabled=enabled, server=server)
            except FileNotFoundError:
                self._old_proxy = dict(enabled=0, server="")

            # set new
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ,
                              f"127.0.0.1:{self.port}")
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ,
                              "localhost;127.*;10.*;192.168.*")
            winreg.CloseKey(key)

            # notify Windows
            self._notify_proxy_change()
            logger.info("System proxy set to 127.0.0.1:%d", self.port)
            return True
        except Exception as exc:
            logger.error("Failed to set system proxy: %s", exc)
            return False

    def _restore_proxy(self):
        if not HAS_WINREG or self._old_proxy is None:
            return
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0, winreg.KEY_ALL_ACCESS,
            )
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD,
                              self._old_proxy["enabled"])
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ,
                              self._old_proxy.get("server", ""))
            winreg.CloseKey(key)
            self._notify_proxy_change()
            logger.info("System proxy restored")
        except Exception:
            pass

    @staticmethod
    def _notify_proxy_change():
        """Notify Windows that proxy settings changed."""
        try:
            import ctypes
            ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
            ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
        except Exception:
            pass

    # ------------------------------------------------------------------
    #  Connection handler
    # ------------------------------------------------------------------
    def _handle_client(self, client: socket.socket):
        """Read first line and dispatch to HTTP or CONNECT handler."""
        try:
            client.settimeout(15)
            data = client.recv(8192)
            if not data:
                return

            first_line = data.split(b"\r\n")[0].decode("utf-8", errors="replace")
            parts = first_line.split()
            if len(parts) < 2:
                return

            method = parts[0].upper()
            target = parts[1]  # full URL for GET, host:port for CONNECT

            if method == "CONNECT":
                self._handle_connect(client, data, target)
            else:
                self._handle_http(client, data, method, target)
        except Exception as exc:
            logger.debug("Handler error: %s", exc)
        finally:
            try:
                client.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    #  HTTP handler – fully relay + check for m3u8
    # ------------------------------------------------------------------
    def _handle_http(self, client: socket.socket, data: bytes,
                     method: str, url: str):
        """Forward HTTP request and relay response."""
        self.request_count += 1
        parsed = urlparse(url)
        if parsed.hostname:
            self.recent_hosts.append(parsed.hostname)
            if len(self.recent_hosts) > 100:
                self.recent_hosts = self.recent_hosts[-50:]

        # check for m3u8 in URL
        self._check_m3u8(url)

        # parse target
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        if not host:
            self._send_error(client, 400, "Bad URL")
            return

        # connect to remote
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(30)
            remote.connect((host, port))
        except Exception as exc:
            logger.debug("Cannot connect to %s:%d – %s", host, port, exc)
            self._send_error(client, 502, f"Bad Gateway: {exc}")
            return

        # rewrite request line (strip absolute URL -> path)
        headers = data.split(b"\r\n", 1)
        new_first = f"{method} {path} HTTP/1.1".encode()
        rest = headers[1] if len(headers) > 1 else b""
        remote.send(new_first + b"\r\n" + rest)

        # relay bidirectional
        self._relay(client, remote)

    # ------------------------------------------------------------------
    #  CONNECT handler – tunnel for HTTPS, log hostname
    # ------------------------------------------------------------------
    def _handle_connect(self, client: socket.socket, data: bytes,
                        host_port: str):
        """Establish SSL tunnel. We can't inspect content, just log host."""
        host, _, port_str = host_port.partition(":")
        port = int(port_str) if port_str else 443

        # log hostname for diagnostics
        self.request_count += 1
        self.recent_hosts.append(f"[HTTPS] {host}:{port}")
        if len(self.recent_hosts) > 100:
            self.recent_hosts = self.recent_hosts[-50:]
        logger.debug("HTTPS CONNECT: %s:%d", host, port)

        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(30)
            remote.connect((host, port))
            client.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._relay(client, remote, read_timeout=30)
        except Exception as exc:
            logger.debug("CONNECT error %s:%d – %s", host, port, exc)
            self._send_error(client, 502, "Tunnel failed")

    # ------------------------------------------------------------------
    #  Bidirectional relay (for both HTTP responses and HTTPS tunnel)
    # ------------------------------------------------------------------
    def _relay(self, client: socket.socket, remote: socket.socket,
               read_timeout: int = 60):
        """Relay data in both directions until both sides close."""
        client.setblocking(False)
        remote.setblocking(False)
        deadline = time.time() + read_timeout
        try:
            while self._running and time.time() < deadline:
                r, _, x = select.select([client, remote], [],
                                        [client, remote], 0.5)
                if x:
                    break
                for sock in r:
                    try:
                        buf = sock.recv(65536)
                    except (BlockingIOError, OSError):
                        buf = b""
                    if not buf:
                        deadline = 0  # connection closed
                        break
                    # send to the other side
                    dst = remote if sock is client else client
                    try:
                        dst.send(buf)
                    except OSError:
                        deadline = 0
                        break
        except (OSError, ValueError):
            pass
        finally:
            try:
                remote.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    #  m3u8 detection
    # ------------------------------------------------------------------
    def _check_m3u8(self, url: str):
        if ".m3u8" in url.lower() and url not in self._seen_urls:
            self._seen_urls.add(url)
            logger.info("[STREAM] Proxy captured: %s", url)
            if self.on_stream:
                self.on_stream(StreamInfo(url=url, source="proxy"))

    # ------------------------------------------------------------------
    #  Error response helper
    # ------------------------------------------------------------------
    @staticmethod
    def _send_error(client: socket.socket, code: int, msg: str):
        try:
            body = f"<h1>{code} {msg}</h1>".encode()
            client.send(
                f"HTTP/1.1 {code} {msg}\r\nContent-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
        except OSError:
            pass


# ===================================================================
#  CDP-based capture  (fragile – depends on ClassIn build flags)
# ===================================================================
class CDPCapturer:
    """
    Monitor network requests from an Electron app via CDP.
    Requires ClassIn to be started with --remote-debugging-port=9222.
    """

    def __init__(self, port: int = 9222, on_stream: Optional[Callable] = None):
        self.port = port
        self.on_stream = on_stream
        self.streams: List[StreamInfo] = []
        self._seen_urls: Set[str] = set()
        self._running = False
        self._proc: Optional[subprocess.Popen] = None
        self._cdp_threads: List[threading.Thread] = []

    # ------------------------------------------------------------------
    #  Lifecycle
    # ------------------------------------------------------------------
    def can_connect(self) -> bool:
        """Check if the CDP port is already open."""
        try:
            r = requests.get(f"http://127.0.0.1:{self.port}/json/version",
                             timeout=2)
            return r.status_code == 200
        except Exception:
            return False

    def start_classin(self) -> bool:
        """Kill existing ClassIn, launch with debug port. Returns True on success."""
        exe = self._find_classin()
        if not exe:
            logger.warning("ClassIn not found")
            return False

        self._kill_process("ClassIn.exe")
        logger.info("Launching ClassIn with debug port %d", self.port)

        try:
            self._proc = subprocess.Popen(
                [exe, f"--remote-debugging-port={self.port}", "--no-first-run"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            logger.error("Cannot launch ClassIn: %s", exc)
            return False

        # wait up to 30s for the debug port
        for _ in range(30):
            if self.can_connect():
                logger.info("ClassIn debug port ready")
                return True
            time.sleep(1)

        logger.warning("ClassIn launched but debug port not responding")
        return False

    def start(self, block: bool = True):
        """Main capture loop."""
        if not HAS_WEBSOCKET:
            raise RuntimeError("websocket-client required for CDP capture")

        self._running = True
        if block:
            try:
                self._capture_loop()
            finally:
                self.stop()
        else:
            t = threading.Thread(target=self._capture_loop, daemon=True)
            t.start()

    def stop(self):
        self._running = False
        # Don't kill the ClassIn process - user may be using it
        # The debug port will be available for reconnection

    # ------------------------------------------------------------------
    #  Internal – CDP loop (polls for new targets, monitors each page)
    # ------------------------------------------------------------------
    def _capture_loop(self):
        if not self.can_connect():
            logger.error("CDP: cannot connect to port %d", self.port)
            return

        self._running = True
        monitored: Set[str] = set()  # set of ws_urls we are monitoring
        self._cdp_threads: List[threading.Thread] = []

        while self._running:
            try:
                r = requests.get(f"http://127.0.0.1:{self.port}/json", timeout=5)
                targets = r.json()
            except Exception as exc:
                logger.debug("CDP: list targets error – %s", exc)
                time.sleep(2)
                continue

            for target in targets:
                ws_url = target.get("webSocketDebuggerUrl")
                if not ws_url or ws_url in monitored:
                    continue
                t = threading.Thread(target=self._monitor_page,
                                     args=(ws_url,), daemon=True)
                t.start()
                monitored.add(ws_url)
                self._cdp_threads.append(t)
                logger.info("CDP: monitoring page: %s",
                            target.get("title", "?")[:50])

            time.sleep(3)  # check for new pages every 3 seconds

    # ------------------------------------------------------------------
    #  Monitor a single page via its WebSocket debugger URL
    # ------------------------------------------------------------------
    def _monitor_page(self, ws_url: str):
        try:
            ws = create_connection(ws_url, timeout=10)
        except Exception as exc:
            logger.debug("CDP WS fail: %s", exc)
            return

        ws.send(json.dumps({"id": 1, "method": "Network.enable"}))
        ws.send(json.dumps({"id": 2, "method": "Console.enable"}))

        # Inject JS to monitor video src changes and console-log them
        ws.send(json.dumps({
            "id": 3,
            "method": "Runtime.evaluate",
            "params": {
                "expression": """
                // Monitor video elements for src changes
                const _origSrcDescriptor = Object.getOwnPropertyDescriptor(
                    HTMLVideoElement.prototype, 'src');
                if (_origSrcDescriptor && _origSrcDescriptor.configurable) {
                    Object.defineProperty(HTMLVideoElement.prototype, 'src', {
                        get() { return _origSrcDescriptor.get.call(this); },
                        set(val) {
                            if (val && typeof val === 'string' &&
                                (val.includes('m3u8') || val.includes('.mp4'))) {
                                console.log('[CDP-CAPTURE] video src =', val);
                            }
                            return _origSrcDescriptor.set.call(this, val);
                        }
                    });
                }
                // Also check for existing video elements
                document.querySelectorAll('video').forEach(v => {
                    if (v.src && (v.src.includes('m3u8') || v.src.includes('mp4'))) {
                        console.log('[CDP-CAPTURE] existing video src =', v.src);
                    }
                });
                // Check for Aliplayer instances
                if (window.Aliplayer) {
                    console.log('[CDP-CAPTURE] Aliplayer found');
                }
                """
            }
        }))

        ws.settimeout(1.0)

        while self._running:
            try:
                msg = ws.recv()
            except WebSocketTimeoutException:
                continue
            except Exception:
                break

            try:
                data = json.loads(msg)
            except json.JSONDecodeError:
                continue

            method = data.get("method", "")

            # -- Response from our Runtime.evaluate (id=3) --
            if data.get("id") == 3:
                result_value = (data.get("result", {})
                                .get("result", {})
                                .get("value", ""))
                if result_value and "src=" in result_value:
                    # Extract video URLs from the evaluate result
                    for u in re.findall(r'(https?://[^\s]+\.(?:mp4|m3u8)[^\s]*)',
                                        result_value):
                        if u not in self._seen_urls:
                            self._seen_urls.add(u)
                            info = StreamInfo(url=u, source="cdp")
                            self.streams.append(info)
                            logger.info("[STREAM] CDP captured (eval): %s", u)
                            if self.on_stream:
                                self.on_stream(info)

            # -- Network requestWillBeSent --
            if method == "Network.requestWillBeSent":
                req = data.get("params", {}).get("request", {})
                req_url = req.get("url", "")
                if (self._is_hls(req_url) or self._is_video_url(req_url)) and req_url not in self._seen_urls:
                    self._seen_urls.add(req_url)
                    info = StreamInfo(url=req_url, source="cdp")
                    self.streams.append(info)
                    logger.info("[STREAM] CDP captured: %s", req_url)
                    if self.on_stream:
                        self.on_stream(info)

            # -- Network responseReceived --
            elif method == "Network.responseReceived":
                resp = data.get("params", {}).get("response", {})
                resp_url = resp.get("url", "")
                ct = (resp.get("mimeType", "") or
                      resp.get("headers", {}).get("content-type", ""))
                if "application/vnd.apple.mpegurl" in ct or "video/mp4" in ct:
                    if resp_url not in self._seen_urls:
                        self._seen_urls.add(resp_url)
                        info = StreamInfo(url=resp_url, source="cdp")
                        self.streams.append(info)
                        logger.info("[STREAM] CDP captured: %s", resp_url)
                        if self.on_stream:
                            self.on_stream(info)

            # -- Console message (from our injected JS) --
            elif method == "Console.messageAdded":
                msg_text = data.get("params", {}).get("message", {}).get("text", "")
                if "[CDP-CAPTURE]" in msg_text:
                    logger.info("[STREAM] CDP JS: %s", msg_text)
                    url_match = re.search(r'(https?://[^\s]+\.(?:m3u8|mp4)[^\s]*)',
                                          msg_text)
                    if url_match:
                        url = url_match.group(1)
                        if url not in self._seen_urls:
                            self._seen_urls.add(url)
                            info = StreamInfo(url=url, source="cdp")
                            self.streams.append(info)
                            if self.on_stream:
                                self.on_stream(info)

        ws.close()

    # ------------------------------------------------------------------
    #  Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _is_hls(url: str) -> bool:
        return ".m3u8" in url.lower() and not url.startswith("data:")

    @staticmethod
    def _is_video_url(url: str) -> bool:
        """Check if URL is a video stream (m3u8, mp4, etc)."""
        lowered = url.lower()
        if lowered.startswith("data:"):
            return False
        # HLS playlist
        if ".m3u8" in lowered:
            return True
        # Direct MP4 from ClassIn CDN
        if ".mp4" in lowered and "eeo.cn" in lowered:
            return True
        return False

    @staticmethod
    def _find_classin() -> Optional[str]:
        paths = [
            "C:/Program Files/ClassIn/ClassIn.exe",
            "C:/Program Files (x86)/ClassIn/ClassIn.exe",
            os.path.expandvars("%LOCALAPPDATA%/Programs/ClassIn/ClassIn.exe"),
            os.path.expandvars("%APPDATA%/ClassIn/ClassIn.exe"),
            os.path.expandvars("%LOCALAPPDATA%/ClassIn/ClassIn.exe"),
            os.path.expandvars("%USERPROFILE%/scoop/apps/classin/current/ClassIn.exe"),
        ]
        for p in paths:
            if os.path.isfile(p):
                return p
        for d in os.environ.get("PATH", "").split(os.pathsep):
            c = os.path.join(d, "ClassIn.exe")
            if os.path.isfile(c):
                return c
        return None

    @staticmethod
    def _kill_process(name: str):
        try:
            subprocess.run(["taskkill", "/f", "/im", name],
                           capture_output=True, timeout=5)
        except Exception:
            pass


# ===================================================================
#  Combined capture – runs proxy + CDP + Frida simultaneously
# ===================================================================
class CombinedCapturer:
    """
    Runs ProxyCapturer, CDPCapturer, and FridaCapturer together.
    Windows system proxy so all ClassIn traffic flows through us.

    Streams detected by either method are reported via the same callback.
    """

    def __init__(self, on_stream: Optional[Callable] = None,
                 proxy_port: int = 8888, cdp_port: int = 9222,
                 enable_frida: bool = True):
        self.on_stream = on_stream
        self.proxy_port = proxy_port
        self.cdp_port = cdp_port

        self.proxy = ProxyCapturer(port=proxy_port, on_stream=on_stream)
        self.cdp = CDPCapturer(port=cdp_port, on_stream=on_stream)

        # Frida capturer — lazy import to avoid early load
        self.frida = None
        if HAS_FRIDA and enable_frida:
            from frida_capture import FridaCapturer
            self.frida = FridaCapturer(on_stream=on_stream, output_dir="captures")

        self._proxy_thread: Optional[threading.Thread] = None
        self._cdp_thread: Optional[threading.Thread] = None
        self._frida_thread: Optional[threading.Thread] = None
        self._running = False
        self._proxy_ok = False
        self._cdp_ok = False
        self._cdp_status = "idle"  # idle / connecting / active / failed
        self._frida_ok = HAS_FRIDA and enable_frida

    # ------------------------------------------------------------------
    def start(self):
        """Start all capture methods."""
        self._running = True

        # 1. Start proxy (always works, no deps needed)
        self._proxy_thread = threading.Thread(target=self._run_proxy,
                                              daemon=True)
        self._proxy_thread.start()

        # 2. Set Windows system proxy
        time.sleep(0.2)  # let proxy start first
        self._proxy_ok = self.proxy.set_system_proxy()

        # 3. Try CDP if available
        if HAS_WEBSOCKET:
            self._cdp_thread = threading.Thread(target=self._run_cdp,
                                                daemon=True)
            self._cdp_thread.start()

        # 4. Frida capture (hooks FFmpeg DLLs in ClassIn process)
        if self.frida and HAS_FRIDA:
            self._frida_thread = threading.Thread(target=self._run_frida,
                                                  daemon=True)
            self._frida_thread.start()

    def stop(self):
        self._running = False
        self.proxy.stop()
        self.cdp.stop()
        if self.frida:
            self.frida.stop()

    @property
    def is_proxy_active(self) -> bool:
        return self._proxy_ok

    @property
    def is_cdp_active(self) -> bool:
        return HAS_WEBSOCKET and self._cdp_ok

    @property
    def is_frida_active(self) -> bool:
        return HAS_FRIDA and self._frida_ok

    # ------------------------------------------------------------------
    def _run_proxy(self):
        try:
            self.proxy.start()
        except Exception as exc:
            logger.error("Proxy error: %s", exc)

    def _run_cdp(self):
        self._cdp_status = "connecting"
        if not self.cdp.can_connect():
            if not self.cdp.start_classin():
                logger.info("CDP unavailable – relying on proxy capture")
                self._cdp_status = "failed"
                return
        self._cdp_ok = True
        self._cdp_status = "active"
        logger.info("CDP connected – monitoring for HLS streams")
        try:
            self.cdp.start(block=True)
        except Exception as exc:
            logger.error("CDP error: %s", exc)
            self._cdp_status = "failed"

    def _run_frida(self):
        logger.info("Frida capturer starting...")
        self._frida_ok = False
        try:
            if self.frida:
                ok = self.frida.start()
                self._frida_ok = ok
                if ok:
                    logger.info("Frida capturer active")
                else:
                    logger.info("Frida capturer unavailable (ClassIn not found or avformat not loaded)")
        except Exception as exc:
            logger.error("Frida error: %s", exc)
            self._frida_ok = False

    @property
    def request_count(self) -> int:
        """Total number of requests seen by the proxy."""
        return self.proxy.request_count

    @property
    def recent_hosts(self) -> List[str]:
        """Recently connected hostnames from proxy."""
        return self.proxy.recent_hosts[-20:]  # last 20


# ===================================================================
#  Local data scanner — searches ClassIn app data for m3u8 URLs
# ===================================================================
CLASSIN_DATA_DIRS = [
    os.path.expandvars("%APPDATA%/ClassIn"),
    os.path.expandvars("%LOCALAPPDATA%/ClassIn"),
    os.path.expandvars("%USERPROFILE%/AppData/Local/Programs/ClassIn"),
]

def find_classin_data_dirs() -> List[str]:
    """Find ClassIn data directories that actually exist."""
    found = []
    for d in CLASSIN_DATA_DIRS:
        p = Path(d)
        if p.is_dir():
            found.append(str(p))
    return found


def scan_classin_data() -> List[str]:
    """
    Search ClassIn's local data directory for .m3u8 URLs.

    Electron apps (like ClassIn) store video playback info in local
    storage / IndexedDB / session files.  These often contain the
    full m3u8 URL as plain text.

    Returns a list of unique m3u8 URLs found.
    """
    urls: Set[str] = set()
    video_re = re.compile(rb'https?://[^\s"\'<>]+\.(?:m3u8|mp4)[^\s"\'<>]*')

    dirs = find_classin_data_dirs()
    if not dirs:
        logger.warning("No ClassIn data directory found")
        return []

    for data_dir in dirs:
        logger.info("Scanning ClassIn data: %s", data_dir)
        for root, _dirs, files in os.walk(data_dir):
            # skip node_modules and __pycache__
            if "node_modules" in root or "__pycache__" in root:
                continue
            for fname in files:
                path = os.path.join(root, fname)
                try:
                    # Skip large files (>50MB)
                    if os.path.getsize(path) > 50 * 1024 * 1024:
                        continue
                    # Binary or text – search raw bytes
                    with open(path, "rb") as fh:
                        content = fh.read(2 * 1024 * 1024)  # first 2MB
                        for match in video_re.finditer(content):
                            url = match.group(0).decode("utf-8", errors="ignore")
                            # filter out garbage
                            if url.count("/") >= 3 and ("m3u8" in url.lower() or "mp4" in url.lower()):
                                urls.add(url)
                except (OSError, PermissionError):
                    pass

    return list(urls)
