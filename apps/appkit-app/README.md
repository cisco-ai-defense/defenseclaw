# DefenseClaw macOS App

Native macOS desktop application for DefenseClaw, built with AppKit + SwiftUI.

## Prerequisites

- macOS 14 (Sonoma) or later
- Xcode 15+ or Xcode Command Line Tools (`xcode-select --install`)
- DefenseClaw sidecar running locally (`defenseclaw-gateway start`)

## Quick Start

### Build and run from source

```bash
cd apps/appkit-app
swift build
swift run DefenseClawAppKit
```

### Build release binary

```bash
cd apps/appkit-app
swift build -c release
```

The binary is at `.build/release/DefenseClawAppKit`.

### Run the release binary directly

```bash
.build/release/DefenseClawAppKit
```

## Creating an .app Bundle

Swift Package Manager builds a bare executable. To create a proper `.app`
bundle that integrates with macOS (Dock icon, menu bar, Finder), wrap it
manually:

```bash
# 1. Build release
cd apps/appkit-app
swift build -c release

# 2. Create .app structure
APP="DefenseClaw.app"
mkdir -p "${APP}/Contents/MacOS"
mkdir -p "${APP}/Contents/Resources"

# 3. Copy binary
cp .build/release/DefenseClawAppKit "${APP}/Contents/MacOS/DefenseClaw"

# 4. Create Info.plist
cat > "${APP}/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>DefenseClaw</string>
    <key>CFBundleDisplayName</key>
    <string>DefenseClaw</string>
    <key>CFBundleIdentifier</key>
    <string>com.defenseclaw.desktop</string>
    <key>CFBundleVersion</key>
    <string>0.1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>CFBundleExecutable</key>
    <string>DefenseClaw</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>LSUIElement</key>
    <false/>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSSupportsAutomaticTermination</key>
    <false/>
</dict>
</plist>
PLIST

# 5. (Optional) Copy app icon if available
# cp path/to/AppIcon.icns "${APP}/Contents/Resources/AppIcon.icns"

echo "Created ${APP}"
```

You can now double-click `DefenseClaw.app` or drag it to `/Applications/`.

## Creating a DMG

### Quick method (hdiutil)

```bash
# Build the .app first (see above), then:

DMG_NAME="DefenseClaw-0.1.0"
DMG_DIR="dmg-staging"

# 1. Create staging directory with .app and Applications symlink
mkdir -p "${DMG_DIR}"
cp -R DefenseClaw.app "${DMG_DIR}/"
ln -s /Applications "${DMG_DIR}/Applications"

# 2. Create DMG
hdiutil create -volname "DefenseClaw" \
    -srcfolder "${DMG_DIR}" \
    -ov -format UDZO \
    "${DMG_NAME}.dmg"

# 3. Clean up
find "${DMG_DIR}" -depth -mindepth 1 -delete
rmdir "${DMG_DIR}"

echo "Created ${DMG_NAME}.dmg"
```

### Polished DMG with background image (create-dmg)

For a drag-to-install DMG with custom layout:

```bash
# Install create-dmg (one-time)
brew install create-dmg

# Build .app first, then:
create-dmg \
    --volname "DefenseClaw" \
    --volicon "path/to/VolumeIcon.icns" \
    --window-pos 200 120 \
    --window-size 600 400 \
    --icon-size 100 \
    --icon "DefenseClaw.app" 150 190 \
    --app-drop-link 450 190 \
    --hide-extension "DefenseClaw.app" \
    "DefenseClaw-0.1.0.dmg" \
    "DefenseClaw.app"
```

## Code Signing (Optional)

For distribution outside the App Store, sign the app and DMG:

```bash
# Sign the .app (replace with your Developer ID)
codesign --force --deep --sign "Developer ID Application: Your Name (TEAMID)" \
    --options runtime \
    DefenseClaw.app

# Verify
codesign --verify --deep --strict DefenseClaw.app

# Notarize (required for Gatekeeper on other machines)
xcrun notarytool submit DefenseClaw-0.1.0.dmg \
    --apple-id "your@email.com" \
    --team-id "TEAMID" \
    --password "app-specific-password" \
    --wait

# Staple the notarization ticket
xcrun stapler staple DefenseClaw-0.1.0.dmg
```

Without signing, users will need to right-click > Open on first launch, or
allow the app in System Settings > Privacy & Security.

## One-Liner: Build + Bundle + DMG

```bash
cd apps/appkit-app && \
swift build -c release && \
mkdir -p DefenseClaw.app/Contents/{MacOS,Resources} && \
cp .build/release/DefenseClawAppKit DefenseClaw.app/Contents/MacOS/DefenseClaw && \
cat > DefenseClaw.app/Contents/Info.plist << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>DefenseClaw</string>
    <key>CFBundleIdentifier</key><string>com.defenseclaw.desktop</string>
    <key>CFBundleVersion</key><string>0.1.0</string>
    <key>CFBundleShortVersionString</key><string>0.1.0</string>
    <key>CFBundleExecutable</key><string>DefenseClaw</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
mkdir -p dmg-staging && \
cp -R DefenseClaw.app dmg-staging/ && \
ln -s /Applications dmg-staging/Applications && \
hdiutil create -volname "DefenseClaw" -srcfolder dmg-staging -ov -format UDZO DefenseClaw-0.1.0.dmg && \
find dmg-staging -depth -mindepth 1 -delete && rmdir dmg-staging && \
echo "Done: DefenseClaw-0.1.0.dmg"
```

## Project Structure

```
apps/appkit-app/
├── Package.swift                     App target (depends on DefenseClawKit)
└── DefenseClawAppKit/
    ├── main.swift                    Entry point (NSApplication + AppDelegate)
    ├── AppDelegate.swift             Config init, policy install, window management
    ├── Helpers/
    │   ├── ChatTextView.swift        Rich text rendering for chat messages
    │   └── MarkdownRenderer.swift    Markdown → AttributedString conversion
    ├── MenuBar/
    │   ├── StatusBarController.swift Menu bar icon + popover management
    │   └── StatusBarPopover.swift    Quick-access popover content
    ├── ViewModels/
    │   ├── AppViewModel.swift        Shared app state (health, alerts, config)
    │   └── SessionViewModel.swift    Agent session state (messages, tools)
    ├── Views/
    │   ├── Alerts/AlertsView.swift   Alert dashboard with severity filtering
    │   ├── Dashboard/DashboardView.swift  System overview + health
    │   ├── Governance/               Sidebar (skills, MCP servers, alerts)
    │   ├── Logs/LogsView.swift       Application and audit log viewer
    │   ├── NewSession/               New agent session sheet
    │   ├── Policy/PolicyView.swift   Policy browser
    │   ├── Scan/ScanView.swift       Security scan trigger + results
    │   ├── Session/                  Chat UI (bubbles, tool cards, approvals)
    │   ├── Settings/SettingsView.swift Full config UI
    │   └── Tools/ToolsCatalogView.swift Tool browser
    └── WindowManagement/
        ├── MainWindowController.swift Multi-window coordinator
        ├── TabStripItem.swift         Tab data model
        └── TabStripView.swift         Browser-style tab strip

apps/shared/                          DefenseClawKit shared Swift package
├── Package.swift                     Library target (Yams dependency)
├── Sources/DefenseClawKit/
│   ├── Models/                       17 model files
│   ├── AgentSession.swift            WebSocket v3 client
│   ├── SidecarClient.swift           REST client (30+ endpoints)
│   ├── ConfigManager.swift           YAML config read/write
│   ├── ProcessRunner.swift           Python CLI wrapper
│   ├── LaunchAgentManager.swift      LaunchAgent lifecycle
│   ├── AppLogger.swift               Structured logging
│   └── DeviceIdentity.swift          Device key management
└── Tests/DefenseClawKitTests/        Unit + integration tests
```

## Running Tests

```bash
# Shared package tests
cd apps/shared
swift test

# App builds without errors
cd apps/appkit-app
swift build
```

## Troubleshooting

**"App can't be opened because it is from an unidentified developer"**
Right-click the app > Open, or allow it in System Settings > Privacy & Security.

**Sidecar connection refused**
Make sure the DefenseClaw gateway is running: `defenseclaw-gateway start`.
The app reads `gateway.api_bind` / `gateway.api_port` from
`~/.defenseclaw/config.yaml` and falls back to `localhost:18970`.

**Build fails with "no such module 'DefenseClawKit'"**
Ensure you're building from `apps/appkit-app/` (not the repo root). The
`Package.swift` references `../shared` as a local dependency.
