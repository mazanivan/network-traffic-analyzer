@echo off
REM Build script for Network Traffic Analyzer (Windows)

echo Building Network Traffic Analyzer executable for Windows...

REM Check if virtual environment exists
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Activate venv and install dependencies
echo Installing dependencies...
if exist requirements.txt (
    echo Found requirements.txt
    .venv\Scripts\pip install -r requirements.txt
) else if exist requirements (
    echo Found requirements file without extension
    .venv\Scripts\pip install -r requirements
) else (
    echo Requirements file not found, installing packages directly...
    .venv\Scripts\pip install scapy==2.5.0 colorama>=0.4.0
)

if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo Installing PyInstaller...
.venv\Scripts\pip install pyinstaller
if errorlevel 1 (
    echo ERROR: Failed to install PyInstaller
    pause
    exit /b 1
)

REM Build executable
echo Creating executable...
.venv\Scripts\pyinstaller --onefile --name nta nta.py
if errorlevel 1 (
    echo ERROR: Failed to build executable
    pause
    exit /b 1
)

REM Copy executable to main directory
echo Copying executable...
if exist dist\nta.exe (
    copy dist\nta.exe .\nta.exe
    if errorlevel 1 (
        echo ERROR: Failed to copy executable
        pause
        exit /b 1
    )
) else (
    echo ERROR: nta.exe not found in dist folder
    pause
    exit /b 1
)

REM Clean up build files
echo Cleaning up...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist *.spec del *.spec

echo.
echo ===================================
echo Build complete! Executable: nta.exe
echo Usage: nta.exe (run as Administrator)
echo ===================================
pause
