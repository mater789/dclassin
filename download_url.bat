@echo off
chcp 65001 >nul
title ClassIn 视频下载
echo ============================================
echo   ClassIn 录播课视频下载
echo ============================================
echo.
set /p url="请输入 m3u8 视频地址: "
if "%url%"=="" goto :eof
echo.
echo 开始下载...
python main.py download "%url%"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo 下载失败, 请检查地址是否正确
    pause
) else (
    echo.
    echo 下载完成! 文件保存在 downloads 目录
    pause
)
