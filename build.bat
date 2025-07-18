@echo off
REM Always run from the script's directory
cd /d %~dp0

REM Simple build script for Network Traffic Analyzer (Windows)

REM Show current directory and files for debugging
cd
dir /b
echo.

REM Install dependencies (requirements.txt must be in the same folder)
pip install -r requirements.txt

REM Install PyInstaller
pip install pyinstaller

REM Build executable
pyinstaller --onefile --name nta nta.py

REM Copy executable to main directory
if exist dist\nta.exe copy dist\nta.exe nta.exe

REM Clean up build files
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist nta.spec del nta.spec

echo Build complete! Executable: nta.exe
pause
