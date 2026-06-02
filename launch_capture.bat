@echo off
chcp 65001 >nul
title ClassIn 视频下载 - 捕获模式
echo ============================================
echo   ClassIn 录播课视频下载 - 自动捕获模式
echo ============================================
echo.
echo 将会自动启动 ClassIn 并捕获视频流地址
echo 请在弹出的 ClassIn 窗口中登录并播放录播课
echo.
echo 按 Ctrl+C 停止捕获
echo.

python main.py capture
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo 发生错误, 请确认已安装依赖:
    echo   pip install -r requirements.txt
    pause
)
