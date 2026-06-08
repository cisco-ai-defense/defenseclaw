#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

MODE="${1:-run}"
APP_NAME="DefenseClaw"
PRODUCT_NAME="DefenseClawAppKit"
BUNDLE_ID="com.defenseclaw.desktop"
MIN_SYSTEM_VERSION="14.0"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_DIR="$ROOT_DIR/apps/appkit-app"
DIST_DIR="${DEFENSECLAW_DIST_DIR:-/tmp/defenseclaw-dist}"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_BINARY="$APP_MACOS/$APP_NAME"
INFO_PLIST="$APP_CONTENTS/Info.plist"

pkill -x "$APP_NAME" >/dev/null 2>&1 || true

ensure_sidecar() {
  if ! command -v defenseclaw-gateway >/dev/null 2>&1; then
    echo "warning: defenseclaw-gateway not found; launching app without local sidecar" >&2
    return
  fi

  local host="127.0.0.1"
  local port="18970"
  local config_file="$HOME/.defenseclaw/config.yaml"
  if [[ -r "$config_file" ]]; then
    local in_gateway=0
    local line
    while IFS= read -r line; do
      case "$line" in
        gateway:*) in_gateway=1 ;;
        [![:space:]]*) in_gateway=0 ;;
      esac
      if (( in_gateway )); then
        if [[ "$line" =~ ^[[:space:]]*api_bind: ]]; then
          local value="${line#*:}"
          value="${value%%#*}"
          value="${value//[[:space:]\'\"]/}"
          if [[ -n "$value" ]]; then
            host="$value"
          fi
        elif [[ "$line" =~ ^[[:space:]]*api_port:[[:space:]]*([0-9]+) ]]; then
          port="${BASH_REMATCH[1]}"
        fi
      fi
    done <"$config_file"
  fi

  if curl -fsS --max-time 1 "http://$host:$port/health" >/dev/null 2>&1; then
    return
  fi

  defenseclaw-gateway start
  sleep 2
}

swift build --package-path "$PACKAGE_DIR"
BUILD_BINARY="$(swift build --package-path "$PACKAGE_DIR" --show-bin-path)/$PRODUCT_NAME"

if [[ -d "$APP_BUNDLE" ]]; then
  find "$APP_BUNDLE" -depth -mindepth 1 -delete
  rmdir "$APP_BUNDLE"
fi
mkdir -p "$APP_MACOS" "$APP_RESOURCES"
cp "$BUILD_BINARY" "$APP_BINARY"
chmod +x "$APP_BINARY"

if [[ -d "$ROOT_DIR/policies" ]]; then
  ditto "$ROOT_DIR/policies" "$APP_RESOURCES/policies"
fi

if [[ -d "$ROOT_DIR/bundles" ]]; then
  ditto "$ROOT_DIR/bundles" "$APP_RESOURCES/bundles"
fi

cat >"$INFO_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>$APP_NAME</string>
  <key>CFBundleIdentifier</key>
  <string>$BUNDLE_ID</string>
  <key>CFBundleName</key>
  <string>$APP_NAME</string>
  <key>CFBundleDisplayName</key>
  <string>$APP_NAME</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>0.1.0</string>
  <key>LSMinimumSystemVersion</key>
  <string>$MIN_SYSTEM_VERSION</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
PLIST

open_app() {
  ensure_sidecar
  (cd "$HOME" && /usr/bin/open -n "$APP_BUNDLE")
}

open_app_qa() {
  local section="${1:-home}"
  local detail="${2:-}"
  ensure_sidecar
  if [[ -n "$detail" ]]; then
    (cd "$HOME" && /usr/bin/open -n "$APP_BUNDLE" --args --qa-section "$section" --qa-settings-tab "$detail" --qa-setup-group "$detail")
  else
    (cd "$HOME" && /usr/bin/open -n "$APP_BUNDLE" --args --qa-section "$section")
  fi
}

case "$MODE" in
  run)
    open_app
    ;;
  --debug|debug)
    lldb -- "$APP_BINARY"
    ;;
  --logs|logs)
    open_app
    /usr/bin/log stream --info --style compact --predicate "process == \"$APP_NAME\""
    ;;
  --telemetry|telemetry)
    open_app
    /usr/bin/log stream --info --style compact --predicate "subsystem == \"$BUNDLE_ID\""
    ;;
  --verify|verify)
    open_app
    sleep 2
    pgrep -x "$APP_NAME" >/dev/null
    ;;
  --qa|qa)
    open_app_qa "${2:-home}" "${3:-}"
    sleep 2
    pgrep -x "$APP_NAME" >/dev/null
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify|--qa [section] [detail]]" >&2
    exit 2
    ;;
esac
