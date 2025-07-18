@echo off
REM Build script for Network Traffic Analyzer (Windows)

echo Building Network Traffic Analyzer executable for Windows...

REM Check if virtual environment exists
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
)

REM Activate venv and install dependencies
echo Installing dependencies...
if exist requirements.txt (
    .venv\Scripts\pip install -r requirements.txt
) else if exist requirements (
    .venv\Scripts\pip install -r requirements
) else (
    echo Requirements file not found, installing packages directly...
    .venv\Scripts\pip install scapy==2.5.0 colorama>=0.4.0
)
.venv\Scripts\pip install pyinstaller

REM Build executable
echo Creating executable...
.venv\Scripts\pyinstaller --onefile --name nta nta.py

REM Copy executable to main directory
echo Copying executable...
copy dist\nta.exe .\nta.exe

REM Clean up build files
echo Cleaning up...
rmdir /s /q build
rmdir /s /q dist
del *.spec

echo Build complete! Executable: nta.exe
echo Usage: nta.exe (run as Administrator)
pause
