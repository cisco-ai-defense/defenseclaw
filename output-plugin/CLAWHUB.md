# Publishing to ClawHub

Steps to build, package, and publish the DefenseClaw plugin to ClawHub.

## 1. Build

```bash
cd output-plugin
npm install
npm run build
```

Verify the `dist/` directory contains compiled output:

```bash
ls dist/
# Should show: index.js, index.d.ts, and all compiled modules
```

## 2. Package

Create a distributable tarball:

```bash
npm pack
```

This produces `defenseclaw-openclaw-plugin-0.1.0.tgz`.

## 3. Publish to ClawHub

### Option A: Tarball upload

```bash
clawhub publish defenseclaw-openclaw-plugin-0.1.0.tgz
```

### Option B: Directory publish

```bash
clawhub publish --directory .
```

ClawHub reads `openclaw.plugin.json` for the listing page metadata (name, description, config schema).

## 4. Verify the Listing

After publishing, confirm the plugin appears in ClawHub:

```bash
clawhub search defenseclaw
```

The listing should show:
- **Name**: DefenseClaw Security (ClawHub)
- **ID**: defenseclaw-plugin
- **Version**: 0.1.0

## 5. User Installation

Users install the plugin with:

```bash
clawhub install @defenseclaw/openclaw-plugin
```

After installation, they configure `sidecarHost` and `sidecarPort` in OpenClaw plugin settings to point at their DefenseClaw gateway.

## 6. Version Updates

To publish an update:

1. Bump version in both `package.json` and `openclaw.plugin.json`
2. Rebuild: `npm run build`
3. Repackage: `npm pack`
4. Publish: `clawhub publish defenseclaw-openclaw-plugin-<version>.tgz`

## Providers JSON

The `src/providers.json` file contains the canonical list of LLM provider domains intercepted by the fetch interceptor. This file is copied from `internal/configs/providers.json` in the DefenseClaw gateway source.

When updating provider domains, copy the latest version:

```bash
cp ../internal/configs/providers.json src/providers.json
```

Then rebuild and republish.
