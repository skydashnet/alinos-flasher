@echo off
title Build ALINOSNET Huawei Tools (GUI)
echo ============================================================
echo   Compiling ALINOS-FlashTool.exe into build\ folder
echo ============================================================
echo.

if not exist build mkdir build

where gcc >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] GCC / MinGW tidak ditemukan di PATH sistem.
    echo Pastikan MinGW-w64 / TDM-GCC terinstall di Windows.
    pause
    exit /b 1
)

echo Mengompilasi resource ikon...
cd src\gui
windres alinos.rc -O coff -o alinos.res
cd ..\..

echo Mengompilasi ALINOS-FlashTool.exe (Windows GUI)...
gcc -Wall -Wextra -std=c99 -Os -mwindows -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va -s -Isrc\core -Isrc\gui src\gui\alinos_flashtool.c src\gui\alinos.res -o build\ALINOS-FlashTool.exe -lws2_32 -lcomctl32 -lcomdlg32 -lgdi32 -luser32 -lshell32 -liphlpapi -lwininet

del src\gui\alinos.res 2>nul

if %errorlevel% equ 0 (
    echo.
    echo [OK] Kompilasi SUKSES! File binary siap: build\ALINOS-FlashTool.exe
) else (
    echo.
    echo [ERR] Kompilasi gagal!
)
pause
