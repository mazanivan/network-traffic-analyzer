@echo off
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
    echo NOT FOUND: requirements
)
echo.

REM Install dependencies directly (no virtual environment)
echo Installing dependencies...
if exist requirements.txt (
    pip install -r requirements.txt
) else if exist requirements (
    pip install -r requirements
) else (
    echo Requirements file not found, installing packages directly...
    pip install scapy==2.5.0 colorama>=0.4.0
)

if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo Installing PyInstaller...
pip install pyinstaller
if errorlevel 1 (
    echo ERROR: Failed to install PyInstaller
    pause
    exit /b 1
)

REM Build executable
echo Creating executable...
pyinstaller --onefile --name nta nta.py
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
