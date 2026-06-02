@echo off
title ClassIn Debug Mode

set "EXE="
if exist "C:\Program Files\ClassIn\ClassIn.exe" set "EXE=C:\Program Files\ClassIn\ClassIn.exe"
if exist "C:\Program Files (x86)\ClassIn\ClassIn.exe" set "EXE=C:\Program Files (x86)\ClassIn\ClassIn.exe"
if exist "%LOCALAPPDATA%\Programs\ClassIn\ClassIn.exe" set "EXE=%LOCALAPPDATA%\Programs\ClassIn\ClassIn.exe"

if "%EXE%"=="" (
    echo ERROR: ClassIn.exe not found
    pause
    exit /b 1
)

echo Found: %EXE%

taskkill /f /im ClassIn.exe >nul 2>&1

start "" "%EXE%" --remote-debugging-port=9222 --no-first-run

echo ClassIn started with debug port 9222
echo Now run ClassInDownloader.exe and click Start
