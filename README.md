# ClassIn 录播课视频下载工具

自动捕获并下载 ClassIn 录播课视频（HLS/m3u8 流媒体）。

## 原理

ClassIn 桌面版基于 Electron 框架构建，录播课使用 **HLS（HTTP Live Streaming）** 协议播放。
本工具通过以下方式工作：

1. **获取视频地址**：通过 Chrome DevTools Protocol (CDP) 自动捕获网络请求中的 `.m3u8` URL
2. **下载视频**：纯 Python 实现的 HLS 下载器，支持多线程并发、AES-128 解密、自动合并
3. **转码**（可选）：如已安装 ffmpeg，自动 remux 为 MP4

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 方法一：手动下载（推荐，最简单）

**获取 m3u8 地址：**

| 平台 | 操作 |
|------|------|
| ClassIn 桌面版 | 播放录播课时按 `Ctrl+Shift+I` → Network 标签 → 过滤框输入 `m3u8` → 复制 URL |
| 网页版 | `F12` → 网络 → 过滤 `m3u8` → 复制 URL |

**下载视频：**

```bash
python main.py download "https://xxxxx/playlist.m3u8"
python main.py download "https://xxxxx/playlist.m3u8" -o 课程名称.mp4
```

### 3. 方法二：自动捕获 + 下载

```bash
# 只捕获地址
python main.py capture

# 捕获后自动下载所有发现的视频
python main.py auto
```

工具会自动启动 ClassIn，你只需登录并播放录播课即可。

### 4. 交互模式

```bash
python main.py interactive
```

进入交互式命令行，支持 `download <url>`、`info <url>`、`list` 等命令。

### 5. 一键脚本（Windows）

- **双击 `launch_capture.bat`** — 自动启动 ClassIn 并捕获视频地址
- **双击 `download_url.bat`** — 输入 m3u8 地址直接下载

## 命令行参考

```bash
# 下载视频
python main.py download <m3u8_url> [-o output.mp4] [-q best]

# 自动捕获
python main.py capture [--port 9222] [--no-launch]

# 捕获后自动下载
python main.py auto

# 查看视频信息
python main.py info <m3u8_url>

# 交互模式
python main.py interactive
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `-o, --output` | 输出文件路径 |
| `-q, --quality` | 画质选择: `best`(默认), `worst`, 或目标带宽值 |
| `-d, --output-dir` | 下载目录 (默认: `downloads`) |
| `-w, --workers` | 并行下载线程数 (默认: 10) |
| `--port` | CDP 调试端口 (默认: 9222) |
| `--no-launch` | 不自动启动 ClassIn，连接已有进程 |
| `-v, --verbose` | 详细日志 |

## 手动获取 m3u8 URL 的详细步骤

### 方法 1：ClassIn 桌面版 DevTools (Ctrl+Shift+I)

1. 打开 ClassIn 并播放录播课
2. 按 `Ctrl+Shift+I` 打开开发者工具
3. 切换到 **Network（网络）** 标签
4. 在过滤输入框中输入 `m3u8`
5. 视频开始播放后，列表中会出现 `.m3u8` 的请求
6. 右键点击 → **Copy → Copy URL**
7. 粘贴到下载命令中

### 方法 2：使用 Fiddler Classic（免费）

1. 下载安装 [Fiddler Classic](https://www.telerik.com/fiddler/fiddler-classic)
2. 开启 HTTPS 解密: Tools → Options → HTTPS → Decrypt HTTPS traffic
3. 播放录播课
4. 在 Fiddler 中过滤 `m3u8`，复制 URL

### 方法 3：使用本工具自动捕获（推荐）

```bash
python main.py capture
```

工具会自动启动 ClassIn 并监听网络请求，发现视频流地址后自动显示。

## 常见问题

### Q: 提示 "未找到 ClassIn"

确保 ClassIn 已安装。如已安装但工具找不到，使用 `--no-launch` 手动连接：

```bash
# 先手动启动 ClassIn（带调试端口）
# 方法：找到 ClassIn 快捷方式，在目标后添加 --remote-debugging-port=9222
# 然后运行：
python main.py capture --no-launch
```

### Q: 下载的视频无法播放

下载的文件为 TS 格式（或 MP4，如已安装 ffmpeg）。推荐使用以下播放器：
- **PotPlayer**（韩国，Windows 最强）
- **VLC**（开源跨平台）
- **MPC-BE**

### Q: 视频有声音没画面 / 画面花屏

尝试用 ffmpeg 重新转码：

```bash
ffmpeg -i input.ts -c:v libx264 -c:a aac -movflags +faststart output.mp4
```

### Q: 需要安装 ffmpeg 吗？

**不需要**。工具默认输出 TS 格式，所有主流播放器均可播放。
如希望输出 MP4，安装 ffmpeg 后会自动使用。

## 项目文件

```
classin-downloader/
├── main.py              # 主程序入口
├── hls_downloader.py    # HLS 视频下载引擎
├── capture.py           # CDP 自动捕获模块
├── requirements.txt     # Python 依赖
├── launch_capture.bat   # Windows 一键捕获脚本
├── download_url.bat     # Windows 一键下载脚本
└── README.md            # 本文件
```

## 免责声明

本工具仅供个人学习研究使用。请尊重版权，仅用于下载自己已购买或有权限访问的课程内容。
