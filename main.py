#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=======================
 ClassIn 录播课视频下载工具
=======================

功能
----
1. 从 m3u8 URL 下载视频（核心功能）
2. 自动捕获 ClassIn 中的视频流地址（可选，通过 CDP 调试协议）
3. 支持 AES-128 解密、多线程下载、自动合并


快速开始
--------
  # 方式一：手动获取 URL 并下载（推荐，最简单）
  python main.py download "https://.../playlist.m3u8" -o 课程视频.mp4

  # 方式二：自动捕获 + 下载
  python main.py auto


获取 m3u8 URL 的常见方法
-------------------------
1. ClassIn 桌面版: Ctrl+Shift+I -> Network -> 过滤 m3u8 -> 复制 URL
2. 网页版: F12 -> 网络 -> 过滤 m3u8 -> 复制 URL
3. Fiddler/Charles: 设置代理后捕获 HTTPS 流量
"""

import sys
import os
import argparse
import logging
import json
import time
import signal
from pathlib import Path
from typing import Optional, List

from hls_downloader import HLSDownloader, logger as hls_logger
from capture import CDPCapturer, HAS_WEBSOCKET

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)


# ===================================================================
# Subcommands
# ===================================================================
def cmd_download(args: argparse.Namespace):
    """Download from an m3u8 URL."""
    dl = HLSDownloader(
        output_dir=args.output_dir,
        max_workers=args.workers,
    )
    result = dl.download(args.url, output=args.output, quality=args.quality)

    size_mb = result.stat().st_size / 1024 / 1024
    print(f"\n完成! 视频已保存: {result}  ({size_mb:.1f} MB)")
    return 0


def cmd_capture(args: argparse.Namespace):
    """Capture m3u8 URLs from ClassIn via CDP."""
    if not HAS_WEBSOCKET:
        print("[ERROR] 需要 websocket-client 库。安装: pip install websocket-client")
        return 1

    cap = CDPCapturer(port=args.port)

    try:
        classin_path = cap.find_classin()
        if not classin_path and not args.no_launch:
            print("[ERROR] 未找到 ClassIn.exe。请使用 --no-launch 连接已有进程")
            return 1

        if args.no_launch:
            print(f"[WAITING] 连接到已有 ClassIn 进程 (端口 {args.port}) …")
            if not cap.attach():
                print("[ERROR] 连接失败，请确保 ClassIn 已用 --remote-debugging-port 启动")
                return 1
        else:
            print(f"[FOUND] 找到 ClassIn: {classin_path}")
            cap.start_classin()
            print("\n[OK] ClassIn 已启动，请登录并播放录播课")

        print("\n[LISTENING] 正在监听视频流… (按 Ctrl+C 停止)\n")

        # collect streams
        streams_before = len(cap.streams)
        cap.start(block=True)

    except KeyboardInterrupt:
        print()
    except Exception as exc:
        print(f"\n[ERROR] 错误: {exc}")
        return 1
    finally:
        cap.stop()

    if cap.streams:
        # deduplicate
        seen = set()
        unique = []
        for s in cap.streams:
            if s.url not in seen:
                seen.add(s.url)
                unique.append(s)

        print(f"\n[FOUND] 共捕获 {len(unique)} 个视频流:\n")
        for i, s in enumerate(unique, 1):
            print(f"  [{i}] {s.url}")
            print(f"      时间: {s.timestamp}")

        # save to file
        save_path = Path("captured_urls.json")
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump([s.__dict__ for s in unique], f,
                      ensure_ascii=False, indent=2)
        print(f"\n[SAVED] URL 已保存至: {save_path}")

        print(f"\n[TIP] 下载命令:")
        print(f'   python main.py download "{unique[0].url}"')
        if args.auto_download:
            print("\n[DOWNLOAD] 自动下载…")
            dl = HLSDownloader(output_dir=args.output_dir)
            for i, s in enumerate(unique, 1):
                try:
                    out = f"classin_video_{i}.ts"
                    print(f"\n[{i}/{len(unique)}] 下载中…")
                    path = dl.download(s.url, output=str(
                        Path(args.output_dir) / out))
                    print(f"  [OK] {path}")
                except Exception as exc:
                    print(f"  [ERROR] 下载失败: {exc}")
    else:
        print("\n[WARN]  未捕获到视频流。可能原因:")
        print("   1. 未播放录播课")
        print("   2. ClassIn 版本不支持调试端口")
        print("   3. 可尝试手动获取 URL: Ctrl+Shift+I -> Network -> 过滤 m3u8")
        print("      然后在 DevTools 的 Console 中执行:")
        print('      copy(document.querySelector("video").src)')

    return 0


def cmd_auto(args: argparse.Namespace):
    """Capture + download (combined workflow)."""
    args.auto_download = True
    return cmd_capture(args)


def cmd_frida(args: argparse.Namespace):
    """Frida-based video capture from ClassIn ijkplayer/FFmpeg."""
    # Handle remux-only mode
    if args.remux:
        from remuxer import Remuxer
        remuxer = Remuxer(args.remux)
        if remuxer.remux():
            print(f"[OK] MP4 saved: {remuxer.output_path}")
            return 0
        else:
            print("[ERROR] Remux failed")
            return 1

    # Interactive capture mode
    from frida_capture import FridaCapturer, FridaStreamInfo

    print("=" * 55)
    print("  Frida 原生视频流捕获")
    print("  支持: ijkplayer / FFmpeg / QtAV 播放的视频")
    print("=" * 55)

    cap = FridaCapturer(output_dir=args.output_dir)

    captured_urls = []
    def on_stream(info: FridaStreamInfo):
        if info.filepath:
            print(f"\n[CAPTURE] 数据包文件: {info.filepath}")
        elif info.url and info.url not in captured_urls:
            captured_urls.append(info.url)
            print(f"\n[URL] {info.url[:150]}")
            # Check if it's a direct-downloadable URL
            if ".mp4" in info.url.lower() or "playback.eeo.cn" in info.url:
                print(f"[TIP]  直链 MP4，可直接下载:")
                print(f"       python main.py download \"{info.url}\" -o video.mp4")

    def on_error(msg: str):
        print(f"[ERROR] {msg}")

    cap.on_stream = on_stream
    cap.on_error = on_error

    print("\n[INFO] 请确保 ClassIn 已启动并正在播放视频")
    print("[INFO] 按 Ctrl+C 停止捕获\n")

    if not cap.start():
        print("[ERROR] 无法附加到 ClassIn 进程。")
        print("  请先启动 ClassIn 并播放视频课程。")
        return 1

    try:
        while cap.is_active:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[STOP] 正在停止...")
    finally:
        cap.stop()

    if cap.packet_count > 0:
        print(f"\n[DONE] 共捕获 {cap.packet_count} 个数据包")
        print(f"[INFO] 使用以下命令封装为 MP4:")
        captures = sorted(Path(args.output_dir).glob("*.dcap"))
        for c in captures:
            print(f"  python main.py frida --remux \"{c}\"")
    else:
        print("\n[WARN] 未捕获到数据包。请确保 ClassIn 正在使用 FFmpeg 播放视频。")

    return 0


def cmd_info(args: argparse.Namespace):
    """Show info about an m3u8 playlist."""
    from hls_downloader import HLSPlaylist
    import requests

    s = requests.Session()
    s.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36"
    )
    print(f"正在获取: {args.url}")
    pl = HLSPlaylist.from_url(args.url, session=s)

    if pl.is_variant:
        print(f"\n多码率视频 ({len(pl.variants)} 个可选画质):")
        for v in sorted(pl.variants, key=lambda x: x["bandwidth"], reverse=True):
            bw = v["bandwidth"]
            res = v["resolution"] or "?"
            print(f"  {res:>12s}  {bw//1000:>6} Kbps  {v['url']}")
    else:
        print(f"\n单码率视频, {len(pl.segments)} 个分段")
        print(f"  时长: {pl.target_duration}s")
    return 0


def cmd_interactive(args: argparse.Namespace):
    """Interactive shell mode."""
    dl = HLSDownloader(output_dir=args.output_dir, max_workers=args.workers)
    print("=" * 50)
    print("  ClassIn 视频下载工具 - 交互模式")
    print("=" * 50)
    print("  命令:")
    print("    download <url>  - 下载视频")
    print("    info <url>      - 查看视频信息")
    print("    list            - 查看已下载文件")
    print("    help            - 帮助")
    print("    exit/quit       - 退出")
    print()

    while True:
        try:
            cmd = input("classin> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not cmd:
            continue
        if cmd in ("exit", "quit", "q"):
            break
        if cmd == "help":
            print("  download <url> [-o output]  - 下载视频")
            print("  info <url>                  - 查看视频信息")
            print("  list                        - 列出已下载文件")
            print("  exit/quit                   - 退出")
            continue
        if cmd == "list":
            files = list(Path(args.output_dir).glob("*.*"))
            if not files:
                print("  (暂无已下载的视频)")
            else:
                for f in files:
                    size = f.stat().st_size / 1024 / 1024
                    print(f"  {f.name}  ({size:.1f} MB)")
            continue

        parts = cmd.split()
        sub = parts[0]
        rest = " ".join(parts[1:])

        if sub == "download":
            url_parts = rest.split()
            url = url_parts[0] if url_parts else ""
            out = url_parts[2] if len(url_parts) > 2 else None
            if not url:
                print("  [ERROR] 用法: download <url> [-o output]")
                continue
            try:
                path = dl.download(url, output=out)
                print(f"  [OK] {path}")
            except Exception as exc:
                print(f"  [ERROR] {exc}")
        elif sub == "info":
            if not rest:
                print("  [ERROR] 用法: info <url>")
                continue
            try:
                cmd_info(argparse.Namespace(url=rest))
            except Exception as exc:
                print(f"  [ERROR] {exc}")
        else:
            print(f"  未知命令: {sub}")

    return 0


# ===================================================================
# Main
# ===================================================================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ClassIn 录播课视频下载工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 下载视频（手动获取 m3u8 URL 后使用）
  python main.py download "https://example.com/path/to/playlist.m3u8"
  python main.py download "https://example.com/path/to/playlist.m3u8" -o 我的课程.mp4

  # 自动捕获视频流地址（ClassIn 桌面版）
  python main.py capture

  # 捕获后自动下载
  python main.py auto

  # 交互模式
  python main.py interactive

获取 m3u8 URL:
  在 ClassIn 播放录播课时按 Ctrl+Shift+I 打开 DevTools,
  切换到 Network 标签, 在过滤框输入 "m3u8" 即可看到视频流地址。
        """,
    )
    parser.add_argument("--output-dir", "-d", default="downloads",
                        help="下载目录 (默认: downloads)")
    parser.add_argument("--workers", "-w", type=int, default=10,
                        help="并行下载线程数 (默认: 10)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="详细日志")

    sub = parser.add_subparsers(dest="command", help="子命令")

    # download
    p_dl = sub.add_parser("download", help="从 m3u8 URL 下载视频")
    p_dl.add_argument("url", help="m3u8 播放列表 URL")
    p_dl.add_argument("-o", "--output", default=None,
                      help="输出文件路径")
    p_dl.add_argument("-q", "--quality", default="best",
                      help="画质: best/worst/带宽值 (默认: best)")

    # capture
    p_cap = sub.add_parser("capture", help="自动捕获 ClassIn 视频流地址")
    p_cap.add_argument("--port", type=int, default=9222,
                       help="CDP 调试端口 (默认: 9222)")
    p_cap.add_argument("--no-launch", action="store_true",
                       help="不自动启动 ClassIn, 连接已有进程")
    p_cap.add_argument("--auto-download", action="store_true",
                       help="捕获到 URL 后自动下载")

    # auto
    p_auto = sub.add_parser("auto", help="自动捕获 + 下载")
    p_auto.add_argument("--port", type=int, default=9222)

    # info
    p_info = sub.add_parser("info", help="查看 m3u8 视频信息")
    p_info.add_argument("url", help="m3u8 URL")

    # interactive
    sub.add_parser("interactive", help="交互模式")
    sub.add_parser("shell", help="交互模式 (同 interactive)")

    # frida
    p_frida = sub.add_parser("frida", help="Frida 原生视频流捕获 (ijkplayer/FFmpeg)")
    p_frida.add_argument("-o", "--output-dir", default="captures",
                         help="输出目录 (默认: captures)")
    p_frida.add_argument("--remux", metavar="DCAP_FILE",
                         help="封装已有的 .dcap 文件为 MP4")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        hls_logger.setLevel(logging.DEBUG)

    if args.command == "download":
        return cmd_download(args)
    elif args.command == "capture":
        return cmd_capture(args)
    elif args.command == "auto":
        return cmd_auto(args)
    elif args.command == "info":
        return cmd_info(args)
    elif args.command == "frida":
        return cmd_frida(args)
    elif args.command in ("interactive", "shell"):
        return cmd_interactive(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
