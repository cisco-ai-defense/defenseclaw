#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCREENSHOT_DIR="${1:-/tmp/defenseclaw-screenshots-final}"
WINDOW_SCRIPT="$(mktemp -t defenseclaw-window.XXXXXX.swift)"

cleanup() {
  rm -f "$WINDOW_SCRIPT"
}
trap cleanup EXIT

mkdir -p "$SCREENSHOT_DIR"

cat >"$WINDOW_SCRIPT" <<'SWIFT'
import Foundation
import CoreGraphics

let options: CGWindowListOption = [.optionOnScreenOnly, .excludeDesktopElements]
guard let windows = CGWindowListCopyWindowInfo(options, kCGNullWindowID) as? [[String: Any]] else {
    exit(1)
}

let candidates: [(UInt32, Double)] = windows.compactMap { window in
    let owner = window[kCGWindowOwnerName as String] as? String ?? ""
    guard owner == "DefenseClaw" else { return nil }

    let layer = window[kCGWindowLayer as String] as? Int ?? 0
    guard layer == 0 else { return nil }

    guard let bounds = window[kCGWindowBounds as String] as? [String: Any],
          let width = bounds["Width"] as? Double,
          let height = bounds["Height"] as? Double,
          width >= 600,
          height >= 400 else { return nil }

    let id = window[kCGWindowNumber as String] as? UInt32 ?? 0
    return (id, width * height)
}

if let largest = candidates.max(by: { $0.1 < $1.1 }) {
    print(largest.0)
}
SWIFT

capture_section() {
  local section="$1"
  local output="$2"

  "$ROOT_DIR/script/build_and_run.sh" --qa "$section"
  sleep 4

  local window_id
  window_id="$(swift "$WINDOW_SCRIPT" | tail -n 1)"
  if [[ -z "$window_id" ]]; then
    echo "No visible DefenseClaw main window found for section: $section" >&2
    exit 1
  fi

  if ! screencapture -x -l "$window_id" "$output" >/dev/null 2>&1; then
    echo "Window capture failed for section '$section'; falling back to full-screen capture" >&2
    screencapture -x "$output"
  fi
  if [[ ! -s "$output" ]]; then
    echo "Screenshot was empty for section: $section" >&2
    exit 1
  fi
}

sections=(home setup settings scan policy alerts tools logs)
for index in "${!sections[@]}"; do
  section="${sections[$index]}"
  number="$(printf '%02d' "$((index + 1))")"
  capture_section "$section" "$SCREENSHOT_DIR/$number-$section.png"
done

echo "Captured DefenseClaw main-window sections in $SCREENSHOT_DIR:"
for index in "${!sections[@]}"; do
  section="${sections[$index]}"
  number="$(printf '%02d' "$((index + 1))")"
  echo "  - $section: $SCREENSHOT_DIR/$number-$section.png"
done
