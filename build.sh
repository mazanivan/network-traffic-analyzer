#!/bin/bash
# Build script for Network Traffic Analyzer

echo "Building Network Traffic Analyzer executable..."

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate venv and install dependencies
echo "Installing dependencies..."
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install pyinstaller

# Build executable
echo "Creating executable..."
.venv/bin/pyinstaller --onefile --name nta nta.py

# Copy executable to main directory
echo "Copying executable..."
cp dist/nta ./nta

# Clean up build files
echo "Cleaning up..."
rm -rf build/ dist/ *.spec

echo "Build complete! Executable: ./nta"
echo "Usage: sudo ./nta"
