#!/bin/bash
# Start MyAgent UI — serves the built web app and opens browser
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${MYAGENT_UI_PORT:-3000}"

# Build if dist doesn't exist
if [ ! -d "$SCRIPT_DIR/dist" ]; then
    echo "[MyAgent UI] Building..."
    cd "$SCRIPT_DIR"
    npm install --silent
    npx vite build
fi

echo "[MyAgent UI] Starting on http://127.0.0.1:$PORT"

# Serve the built files
cd "$SCRIPT_DIR"
npx vite preview --port "$PORT" --host 127.0.0.1 &
UI_PID=$!

sleep 2
open "http://127.0.0.1:$PORT"

echo "[MyAgent UI] Running (PID $UI_PID)"
echo "[MyAgent UI] Press Ctrl+C to stop"
wait $UI_PID
