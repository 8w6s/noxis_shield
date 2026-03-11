#!/bin/bash
# 🥭 Mango Shield DStat Startup Script

# Navigate to the script's directory
cd "$(dirname "$0")"

# ── KEEP ONLY ONE INSTANCE ── 
# Kill any existing monitor.py processes to avoid Conflict (Error 409)
echo "Cleaning up previous bot instances..."
pkill -f monitor.py || true
sleep 1 # Wait for processes to exit

# Activate the virtual environment if it exists
if [ -d "venv" ]; then
    echo "Starting Mango DStat Pro Max with Virtual Environment..."
    ./venv/bin/python3 monitor.py
else
    echo "Starting Mango DStat Pro Max with System Python..."
    python3 monitor.py
fi
