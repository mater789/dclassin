#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClassIn 录播课视频下载工具 - 图形界面版

基于 tkinter 桌面应用，支持：
  - 代理捕获 HTTP/HLS 视频流
  - CDP 捕获 HTML5 视频流
  - Frida 捕获 ijkplayer/FFmpeg 原生视频流
  - 手动粘贴 URL
  - 多线程下载 + 实时进度
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import queue
import time
import os
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List

from hls_downloader import HLSDownloader, HAS_AES
from capture import (CombinedCapturer, StreamInfo as CapStreamInfo,
                     HAS_WEBSOCKET, HAS_WINREG, HAS_FRIDA,
                     scan_classin_data, find_classin_data_dirs)


# ===================================================================
#  Data
# ===================================================================
@dataclass
class StreamInfo:
    url: str
    source: str = "proxy"   # proxy / cdp / manual / frida
    timestamp: str = ""


@dataclass
class ProgressInfo:
    completed: int = 0
    total: int = 0
    speed: float = 0.0
    status: str = "idle"      # idle / downloading / merging / done / error


# ===================================================================
#  Main App
# ===================================================================
class ClassInDownloaderApp:
    """tkinter GUI for detecting & downloading ClassIn HLS streams."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ClassIn 录播课视频下载工具")
        self.root.geometry("920x680")
        self.root.minsize(720, 520)

        # state
        self.capturer: Optional[CombinedCapturer] = None
        self.downloader = HLSDownloader(output_dir="downloads")
        self.streams: List[StreamInfo] = []
        self.stream_queue: "queue.Queue[StreamInfo]" = queue.Queue()
        self.progress_queue: "queue.Queue[ProgressInfo]" = queue.Queue()
        self.download_thread: Optional[threading.Thread] = None
        self.is_capturing = False
        self.is_downloading = False
        self._cancel = False
        self._last_req_count = 0
        self._last_cdp_status = "idle"

        self._build_ui()
        self._poll_queues()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._log("程序已启动 — 点「开始监听」启动捕获，然后在 ClassIn 中播放课程视频")
        if not HAS_WINREG:
            self._log("[提示] 无法设置系统代理，请手动将 Windows 代理设为 127.0.0.1:8888")
        if not HAS_WEBSOCKET:
            self._log("[提示] 未安装 websocket-client，CDP 捕获不可用")
        if not HAS_FRIDA:
            self._log("[提示] 未安装 frida，ijkplayer 视频捕获不可用")
        else:
            self._log("[Frida] ijkplayer/FFmpeg 视频捕获已就绪")

    # ================================================================
    #  UI Builder
    # ================================================================
    def _build_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=0)   # toolbar
        self.root.rowconfigure(1, weight=1)   # main
        self.root.rowconfigure(2, weight=0)   # download bar
        self.root.rowconfigure(3, weight=0)   # progress
        self.root.rowconfigure(4, weight=0)   # log

        # -- Toolbar --------------------------------------------------
        toolbar = ttk.Frame(self.root, padding=4)
        toolbar.grid(row=0, column=0, sticky="ew", padx=5, pady=(5, 0))
        toolbar.columnconfigure(5, weight=1)

        self.capture_btn = ttk.Button(toolbar, text="▶ 开始监听",
                                      command=self._toggle_capture)
        self.capture_btn.grid(row=0, column=0, padx=2)

        self.status_dot = ttk.Label(toolbar, text="○", foreground="gray",
                                    font=("", 12))
        self.status_dot.grid(row=0, column=1, padx=(4, 0))

        self.status_lbl = ttk.Label(toolbar, text="就绪")
        self.status_lbl.grid(row=0, column=2, padx=(2, 6))

        sep = ttk.Separator(toolbar, orient="vertical")
        sep.grid(row=0, column=3, sticky="ns", padx=6)

        ttk.Label(toolbar, text="手动添加 URL:").grid(
            row=0, column=4, sticky="e", padx=(4, 2))
        self.url_entry = ttk.Entry(toolbar)
        self.url_entry.grid(row=0, column=5, sticky="ew", padx=2)
        self.url_entry.bind("<Return>", lambda _: self._add_manual_url())

        ttk.Button(toolbar, text="添加", command=self._add_manual_url).grid(
            row=0, column=6, padx=2)

        ttk.Button(toolbar, text="? 如何获取",
                   command=self._show_help).grid(row=0, column=7, padx=2)

        ttk.Button(toolbar, text="扫描本地数据",
                   command=self._scan_local_data).grid(row=0, column=8, padx=2)

        self.req_lbl = ttk.Label(toolbar, text="", foreground="#666")
        self.req_lbl.grid(row=0, column=9, padx=(6, 2))

        # -- Main: stream list + detail -------------------------------
        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # Left – stream list
        list_frame = ttk.LabelFrame(paned, text="检测到的视频流", padding=2)
        paned.add(list_frame, weight=3)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        columns = ("#", "画质", "视频地址", "来源")
        self.tree = ttk.Treeview(list_frame, columns=columns,
                                 show="headings", selectmode="browse")
        for c in columns:
            self.tree.heading(c, text=c)
        self.tree.column("#", anchor="center", width=36)
        self.tree.column("画质", width=100)
        self.tree.column("视频地址", width=350)
        self.tree.column("来源", anchor="center", width=54)

        vsb = ttk.Scrollbar(list_frame, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<<TreeviewSelect>>", self._on_select_stream)

        # Right – detail panel
        detail_frame = ttk.LabelFrame(paned, text="选中流详情", padding=6)
        paned.add(detail_frame, weight=2)
        self._build_detail(detail_frame)

        # -- Download bar ---------------------------------------------
        dl_frame = ttk.LabelFrame(self.root, text="下载控制", padding=4)
        dl_frame.grid(row=2, column=0, sticky="ew", padx=5)
        dl_frame.columnconfigure(1, weight=1)

        ttk.Label(dl_frame, text="保存到:").grid(row=0, column=0,
                                                 sticky="w", padx=2)
        self.save_var = tk.StringVar()
        save_entry = ttk.Entry(dl_frame, textvariable=self.save_var)
        save_entry.grid(row=0, column=1, sticky="ew", padx=2)

        ttk.Button(dl_frame, text="浏览...",
                   command=self._browse_output).grid(row=0, column=2, padx=2)

        self.dl_btn = ttk.Button(dl_frame, text="▼  下载选中视频",
                                 command=self._start_download)
        self.dl_btn.grid(row=0, column=3, padx=5)
        self.dl_btn.state(["disabled"])

        # -- Progress ------------------------------------------------
        self.prog_frame = ttk.LabelFrame(self.root, text="下载进度", padding=4)
        self.prog_frame.grid(row=3, column=0, sticky="ew", padx=5, pady=(0, 5))
        self.prog_frame.columnconfigure(1, weight=1)

        self.progress_bar = ttk.Progressbar(self.prog_frame, mode="determinate")
        self.progress_bar.grid(row=0, column=0, columnspan=4,
                               sticky="ew", padx=2, pady=2)

        self.pct_lbl = ttk.Label(self.prog_frame, text="0%")
        self.pct_lbl.grid(row=1, column=0, sticky="w", padx=2)

        self.speed_lbl = ttk.Label(self.prog_frame, text="")
        self.speed_lbl.grid(row=1, column=1, sticky="w", padx=2)

        self.detail_lbl = ttk.Label(self.prog_frame, text="就绪")
        self.detail_lbl.grid(row=1, column=2, sticky="w", padx=2)

        self.cancel_btn = ttk.Button(self.prog_frame, text="取消",
                                     command=self._do_cancel)
        self.cancel_btn.grid(row=1, column=3, sticky="e", padx=2)

        self.cancel_btn.state(["disabled"])

        # -- Log ------------------------------------------------------
        log_frame = ttk.LabelFrame(self.root, text="运行日志", padding=2)
        log_frame.grid(row=4, column=0, sticky="ew", padx=5, pady=(0, 5))
        log_frame.columnconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, height=6, state="disabled",
                                wrap="word", font=("Consolas", 9),
                                bg="#1e1e1e", fg="#d4d4d4",
                                insertbackground="white")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical",
                                   command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.grid(row=0, column=0, sticky="ew")
        log_scroll.grid(row=0, column=1, sticky="ns")

    # ---------------------------------------------------------------
    def _build_detail(self, parent):
        parent.columnconfigure(1, weight=1)
        # URL – use a selectable Text widget
        ttk.Label(parent, text="URL:", font=("", 9, "bold")).grid(
            row=0, column=0, sticky="nw", padx=2, pady=2)
        self.detail_url_text = tk.Text(parent, height=3, wrap="word",
                                       font=("Consolas", 9), relief="flat",
                                       borderwidth=0)
        self.detail_url_text.grid(row=0, column=1, sticky="ew", padx=2, pady=2)

        fields = [
            ("分辨率:", "res"),
            ("码率:",   "bw"),
            ("分段数:", "seg"),
        ]
        self.detail_vars = {}
        for i, (label, key) in enumerate(fields, start=1):
            ttk.Label(parent, text=label, font=("", 9, "bold")).grid(
                row=i, column=0, sticky="w", padx=2, pady=2)
            var = tk.StringVar(value="-")
            self.detail_vars[key] = var
            lbl = ttk.Label(parent, textvariable=var, wraplength=280)
            lbl.grid(row=i, column=1, sticky="w", padx=2, pady=2)

    # ================================================================
    #  Queue polling
    # ================================================================
    def _poll_queues(self):
        try:
            while True:
                info = self.stream_queue.get_nowait()
                self._add_stream_to_list(info)
        except queue.Empty:
            pass

        try:
            while True:
                prog = self.progress_queue.get_nowait()
                self._update_progress(prog)
        except queue.Empty:
            pass

        # Update capture status and diagnostics
        if self.is_capturing and self.capturer:
            # Show CDP connection progress
            cdp_status = getattr(self.capturer, '_cdp_status', 'idle')
            if cdp_status == 'connecting':
                self._set_status("正在启动 ClassIn 调试端口...", "orange")

            # Log CDP transitions
            if not hasattr(self, '_last_cdp_status'):
                self._last_cdp_status = 'idle'
            if cdp_status != self._last_cdp_status:
                self._last_cdp_status = cdp_status
                if cdp_status == 'active':
                    self._log("[监听] CDP 调试端口已连接，正在监听视频流...")
                elif cdp_status == 'failed':
                    self._log("[监听] CDP 连接失败 (ClassIn 可能不支持调试端口)")

            # Show which capture methods are active
            parts = []
            if self.capturer.is_proxy_active:
                parts.append("代理")
            if self.capturer.is_cdp_active:
                parts.append("CDP")
            if self.capturer.is_frida_active:
                parts.append("Frida")
            if parts:
                self._set_status(f"监听中 ({'+'.join(parts)})", "green")

            # Proxy diagnostics
            count = self.capturer.request_count
            self.req_lbl.configure(text=f"请求: {count}")
            if count > self._last_req_count:
                hosts = self.capturer.recent_hosts
                if hosts:
                    self._log(f"[诊断] 代理请求 +{count - self._last_req_count}  "
                              f"最近: {', '.join(hosts[-3:])}")
                self._last_req_count = count
        else:
            self.req_lbl.configure(text="")

        self.root.after(200, self._poll_queues)

    # ================================================================
    #  Stream list
    # ================================================================
    def _add_stream_to_list(self, info: StreamInfo):
        fmt = "MP4" if ".mp4" in info.url.lower() else "HLS"
        self.tree.insert("", "end", values=(
            len(self.streams) + 1, fmt, info.url, info.source))
        self.streams.append(info)
        self._log(f"[发现] {info.source}: {info.url[:120]}")

        # Select the newly added row
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[-1])
            self.tree.see(children[-1])

    def _on_select_stream(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            self.dl_btn.state(["disabled"])
            return

        idx = self.tree.index(sel[0])
        info = self.streams[idx]

        self.detail_url_text.configure(state="normal")
        self.detail_url_text.delete("1.0", "end")
        self.detail_url_text.insert("1.0", info.url)

        if info.source == "缓存":
            size_mb = info.file_size / 1024 / 1024
            status = "缓存中..." if not info.complete else "已完成"
            self.detail_vars["res"].set(f"本地缓存 ({status})")
            self.detail_vars["bw"].set(f"{size_mb:.1f} MB")
            self.detail_vars["seg"].set("点击下载即复制文件")
        else:
            self.detail_vars["res"].set("(下载后可知)")
            self.detail_vars["bw"].set("(下载后可知)")
            self.detail_vars["seg"].set("点击下载后显示")

        self.detail_url_text.configure(state="disabled")
        self.dl_btn.state(["!disabled"])

    # ================================================================
    #  Capture – Combined (proxy + CDP)
    # ================================================================
    def _toggle_capture(self):
        if self.is_capturing:
            self._stop_capture()
        else:
            self._start_capture()

    def _start_capture(self):
        self.is_capturing = True
        self.capture_btn.configure(text="■ 停止监听")

        # proxy-based capture works immediately, no extra deps needed
        self._set_status("启动代理捕获...", "orange")
        self._log("[监听] 启动代理捕获 (端口 8888)…")

        def on_stream(s):
            """Called from capture thread when a stream is found."""
            info = StreamInfo(url=s.url, source=s.source, timestamp=s.timestamp)
            if getattr(s, "source", "") == "frida":
                self._log(f"[Frida] {info.url[:120]}")
            self.stream_queue.put(info)

        cap = CombinedCapturer(on_stream=on_stream, proxy_port=8888, cdp_port=9222)
        self.capturer = cap

        def worker():
            try:
                cap.start()
                # _poll_queues will handle status updates
                self.root.after(0, lambda: self._log(
                    "[监听] 代理已就绪 — 正在连接 ClassIn 调试端口…"))
            except Exception as exc:
                self._log(f"[错误] 捕获异常: {exc}")
                self.root.after(0, lambda: self._set_status(f"错误: {exc}", "red"))
                self.is_capturing = False
                self.root.after(0, lambda: self.capture_btn.configure(text="▶ 开始监听"))

        self.capture_thread = threading.Thread(target=worker, daemon=True)
        self.capture_thread.start()

    def _stop_capture(self):
        if self.capturer:
            self.capturer.stop()
        self.is_capturing = False
        self.capture_btn.configure(text="▶ 开始监听")
        self._set_status("已停止", "gray")
        self._log("[监听] 已停止，系统代理已恢复")

    # ---------------------------------------------------------------
    def _show_help(self):
        """Show a dialog explaining how to get the video URL."""
        msg = (
            "获取视频地址的 3 种方式\n"
            "━━━━━━━━━━━━━━━━━━━\n\n"
            "方式①：自动模式（推荐）\n"
            "  点击「开始监听」，工具会自动：\n"
            "  · 关闭已有 ClassIn\n"
            "  · 以调试模式重新启动 ClassIn\n"
            "  · 自动捕获 HTML5 视频流和 ijkplayer 缓存\n"
            "  你只需在 ClassIn 中登录并播放录播课即可\n\n"
            "方式②：手动启动 ClassIn + 工具仅监听\n"
            "  如果你希望自己控制 ClassIn 的启动：\n"
            "  1. 双击 launch_classin_debug.bat\n"
            "     （以调试模式启动 ClassIn，端口 9222）\n"
            "  2. 在 ClassIn 中登录、播放录播课\n"
            "  3. 点击本工具的「开始监听」\n"
            "     （会自动连接已有的 ClassIn，不会重启）\n\n"
            "方式③：ijkplayer 缓存捕获（新！）\n"
            "  工具会自动监控 ClassIn 的视频缓存目录。\n"
            "  对于不支持 HTML5 播放的课程，会从本地缓存\n"
            "  中直接获取视频文件。\n"
            "  · 列表中出现「缓存 xxxMB」条目即表示已捕获\n"
            "  · 点击下载会直接把缓存文件复制到目标位置\n\n"
            "获取到视频地址后，选中 → 选择保存位置 → 下载\n"
        )
        messagebox.showinfo("使用说明", msg)

    # ================================================================
    #  Local data scan
    # ================================================================
    def _scan_local_data(self):
        """Scan ClassIn's local data directory for m3u8 URLs (threaded)."""
        dirs = find_classin_data_dirs()
        if not dirs:
            self._log("[扫描] 未找到 ClassIn 数据目录")
            messagebox.showwarning("扫描失败", "未找到 ClassIn 数据目录，请确认已安装 ClassIn")
            return

        self._log(f"[扫描] 正在搜索 {len(dirs)} 个目录中的视频地址...")
        self._log(f"[扫描] {', '.join(dirs)}")

        def worker():
            try:
                urls = scan_classin_data()
                if urls:
                    self.root.after(0, lambda: self._log(
                        f"[扫描] 找到 {len(urls)} 个视频地址"))
                    for url in urls:
                        info = StreamInfo(
                            url=url,
                            source="扫描",
                            timestamp=datetime.now().strftime("%H:%M:%S"),
                        )
                        self.stream_queue.put(info)
                    self.root.after(0, lambda: messagebox.showinfo(
                        "扫描完成",
                        f"在 ClassIn 本地数据中找到 {len(urls)} 个视频地址。\n"
                        "已添加到列表中，选择后点击下载即可。"))
                else:
                    self.root.after(0, lambda: self._log(
                        "[扫描] 未找到视频地址"))
                    self.root.after(0, lambda: messagebox.showinfo(
                        "扫描结果",
                        "未在 ClassIn 本地数据中找到视频地址。\n\n"
                        "请先在 ClassIn 中播放录播课，等待视频加载后再试。\n"
                        "也可尝试「开始监听」或手动粘贴 URL。"))
            except Exception as exc:
                self.root.after(0, lambda: self._log(
                    f"[扫描] 错误: {exc}"))
                self.root.after(0, lambda: messagebox.showerror(
                    "扫描错误", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    # ================================================================
    #  Manual URL
    # ================================================================
    def _add_manual_url(self):
        url = self.url_entry.get().strip()
        if not url:
            return
        self.url_entry.delete(0, tk.END)
        info = StreamInfo(
            url=url,
            source="手动",
            timestamp=datetime.now().strftime("%H:%M:%S"),
        )
        self.stream_queue.put(info)
        self._log(f"[手动添加] {url}")

    # ================================================================
    #  Download
    # ================================================================
    def _browse_output(self):
        sel = self.tree.selection()
        is_mp4 = False
        if sel:
            idx = self.tree.index(sel[0])
            info = self.streams[idx]
            is_mp4 = ".mp4" in info.url.lower()
        path = filedialog.asksaveasfilename(
            defaultextension=".mp4" if is_mp4 else ".ts",
            filetypes=[("视频文件", "*.ts *.mp4"), ("所有文件", "*.*")],
            title="选择保存位置",
        )
        if path:
            self.save_var.set(path)

    def _start_download(self):
        sel = self.tree.selection()
        if not sel:
            return

        idx = self.tree.index(sel[0])
        info = self.streams[idx]
        output = self.save_var.get().strip() or None

        if self.is_downloading:
            messagebox.showinfo("提示", "已有下载任务在进行中")
            return

        self.is_downloading = True
        self._cancel = False
        self.dl_btn.state(["disabled"])
        self.cancel_btn.state(["!disabled"])
        self._set_status("下载中...", "blue")
        self._log(f"[下载] 开始下载: {info.url}")

        def worker():
            try:
                path = self.downloader.download(
                    info.url,
                    output=output,
                    progress_callback=self._on_progress,
                )
                if self._cancel:
                    if path and path.exists():
                        path.unlink()
                    self.root.after(0, lambda: self._log("[下载] 已取消"))
                else:
                    size_mb = path.stat().st_size / 1024 / 1024
                    msg = f"视频已保存至:\n{path}  ({size_mb:.1f} MB)"
                    self.root.after(0, lambda: self._log(f"[下载] 完成: {path}"))
                    self.root.after(0, lambda: messagebox.showinfo("下载完成", msg))
            except Exception as exc:
                self.root.after(0, lambda: self._log(f"[错误] 下载失败: {exc}"))
                self.root.after(0, lambda: messagebox.showerror("下载失败", str(exc)))
            finally:
                self.is_downloading = False
                self.root.after(0, lambda: self.dl_btn.state(["!disabled"]))
                self.root.after(0, lambda: self.cancel_btn.state(["disabled"]))
                self.root.after(0, lambda: self._set_status("就绪", "gray"))

        self.download_thread = threading.Thread(target=worker, daemon=True)
        self.download_thread.start()

    def _do_cancel(self):
        if self.is_downloading:
            self._cancel = True
            self._log("[下载] 正在取消...")

    # ---------------------------------------------------------------
    def _on_progress(self, completed: int, total: int, speed: float,
                     status: str):
        self.progress_queue.put(ProgressInfo(completed, total, speed, status))

    def _update_progress(self, prog: ProgressInfo):
        if prog.total > 0:
            pct = min(100, int(prog.completed / prog.total * 100))
            self.progress_bar["value"] = pct
            self.pct_lbl.configure(text=f"{pct}%")

            if prog.status in ("downloading", "downloading_mp4") and prog.speed > 0:
                self.speed_lbl.configure(text=fmt_speed(prog.speed))
            else:
                self.speed_lbl.configure(text="")

            if prog.status == "downloading_mp4":
                mb_done = prog.completed / 1024 / 1024
                mb_total = prog.total / 1024 / 1024
                speed_str = fmt_speed(prog.speed) if prog.speed > 0 else ""
                self.speed_lbl.configure(text=speed_str)
                self.detail_lbl.configure(
                    text=f"下载中: {mb_done:.1f} MB")
            elif prog.status == "downloading":
                self.detail_lbl.configure(
                    text=f"下载中: {prog.completed}/{prog.total} 分段")
            elif prog.status == "merging":
                self.detail_lbl.configure(text="正在合并视频分段...")
            elif prog.status == "done":
                self.detail_lbl.configure(text="下载完成 ✓")
            elif prog.status == "error":
                self.detail_lbl.configure(text="下载出错")

    # ================================================================
    #  Status / Log
    # ================================================================
    def _set_status(self, text: str, color: str = "gray"):
        self.status_lbl.configure(text=text)
        dot_colors = {"green": "green", "red": "red", "orange": "orange",
                      "blue": "blue", "gray": "gray"}
        self.status_dot.configure(foreground=dot_colors.get(color, "gray"))

    def _log(self, msg: str):
        self.log_text.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{ts}] {msg}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # ================================================================
    #  Cleanup
    # ================================================================
    def _on_close(self):
        if self.is_downloading:
            if not messagebox.askokcancel("退出", "下载正在进行中，确定要退出吗？"):
                return
            self._cancel = True
        if self.capturer:
            self.capturer.stop()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ===================================================================
#  Helpers
# ===================================================================
def fmt_bps(bps: int) -> str:
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.1f} Mbps"
    if bps >= 1000:
        return f"{bps // 1000} Kbps"
    return f"{bps} bps"


def fmt_speed(bps: float) -> str:
    if bps >= 1024 * 1024:
        return f"{bps / 1024 / 1024:.1f} MB/s"
    if bps >= 1024:
        return f"{bps / 1024:.0f} KB/s"
    return f"{bps:.0f} B/s"


# ===================================================================
#  Entry
# ===================================================================
if __name__ == "__main__":
    app = ClassInDownloaderApp()
    app.run()
