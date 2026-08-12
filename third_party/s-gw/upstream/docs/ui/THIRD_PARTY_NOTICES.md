# Third-Party Notices

## Rust Execution Core

The compiled `sgw-core` runner uses crates from crates.io. Exact versions are
locked in `Cargo.lock`.

- `base64`, `block-buffer`, `cfg-if`, `cpufeatures`, `crypto-common`, `digest`,
  `itoa`, `libc`, `proc-macro2`, `quote`, `serde`, `serde_core`, `serde_derive`,
  `serde_json`, `sha2`, `syn`, `typenum`, and `version_check`: MIT or Apache-2.0
- `generic-array` and `zmij`: MIT
- `memchr`: Unlicense or MIT
- `unicode-ident`: MIT or Apache-2.0, with Unicode-3.0 data terms

Sources and license files are available through each package entry at
https://crates.io/ and in the corresponding Cargo registry source archive.

## AWS Architecture Icons

The macOS approval helper includes the Amazon EC2 service icon from the official
AWS Architecture Icons package. This asset is used only to identify Amazon EC2.
AWS and Amazon EC2 are trademarks of Amazon.com, Inc. or its affiliates.

- Source: https://aws.amazon.com/architecture/icons/

## Lucide Icons

The local console and native macOS menu helper embed selected Lucide SVG icons.
The helper uses Lucide for generic agent, terminal, server, and local-machine
concepts while retaining service-specific marks where identity matters.

- Source: https://lucide.dev/
- Package: `lucide-react@1.23.0`
- License: ISC

The selected icons are embedded directly in `local-console.html` so the local credential console works offline and does not call a CDN.

## Simple Icons

The credential provider table embeds the GitHub SVG mark from Simple Icons 16.22.0.

- Source: https://simpleicons.org/
- Package: `simple-icons@16.22.0`
- License: CC0-1.0

Simple Icons supplies brand SVGs; trademark rights remain with the respective brand owners. AWS and OpenAI remain text marks in the legacy prototype because the package used there did not include matching current SVG marks under those provider names.

The React console also uses the Claude, Google Gemini, GitHub Copilot, and
Windsurf marks from Simple Icons 16.22.0 to identify known coding agents.

The React Credentials view uses the 1Password mark from Simple Icons 16.24.1
to make the provider immediately recognizable. The mark is bundled locally;
1Password remains a trademark of AgileBits, Inc.

## Installed Application Icons

The React console includes scaled application icons for Codex, Cursor, OpenCode,
and Visual Studio Code so approval and activity views use the product artwork
users already recognize. These icons are used only for product identification.
The products and their artwork remain trademarks of their respective owners and
are not licensed under s-gw's Apache-2.0 license.

- Codex: https://openai.com/codex/
- Cursor: https://cursor.com/
- OpenCode: https://github.com/anomalyco/opencode
- Visual Studio Code: https://github.com/microsoft/vscode

## Agent Project Artwork

The React console uses artwork from the following official project repositories
to identify configured agents. The artwork is used only for product
identification; project names and marks remain with their respective owners.

- OpenClaw: https://github.com/openclaw/openclaw (MIT)
- ZeptoClaw: https://github.com/qhkm/zeptoclaw (Apache-2.0)
- Hermes Agent: https://github.com/NousResearch/hermes-agent (MIT)
- OpenHands: https://github.com/OpenHands/OpenHands (MIT outside `enterprise/`)
- OmniGent: https://github.com/omnigent-ai/omnigent (Apache-2.0)

The Google Antigravity favicon is sourced from the official Antigravity site and
is used only to identify that product. Google and Antigravity are trademarks of
Google LLC.

- Source: https://www.antigravity.google/

## d3-sankey and d3 Modules

The Usage Flow panel uses d3-sankey for the local, offline Agent -> Credential -> Action Sankey chart. The browser bundles are vendored so the console does not call a CDN.

- Source: https://github.com/d3/d3-sankey
- Package: `d3-sankey@0.12.3`
- File: `docs/ui/vendor/d3-sankey/d3-sankey.min.js`
- License: BSD-3-Clause

d3-sankey's browser bundle depends on these d3 modules, also vendored locally:

- `d3-array@2.12.1`, BSD-3-Clause, `docs/ui/vendor/d3-sankey/d3-array.min.js`
- `d3-path@1.0.9`, BSD-3-Clause, `docs/ui/vendor/d3-sankey/d3-path.min.js`
- `d3-shape@1.3.7`, BSD-3-Clause, `docs/ui/vendor/d3-sankey/d3-shape.min.js`

The upstream BSD license files are included beside the bundles in `docs/ui/vendor/d3-sankey/`.

## SankeyMATIC

A legacy SankeyMATIC layout-core copy remains in the repository from an earlier prototype but is not loaded by the current Usage Flow panel.

- Source: https://github.com/nowthis/sankeymatic
- File: `docs/ui/vendor/sankeymatic/sankey.js`
- License: ISC

The upstream ISC license is included at `docs/ui/vendor/sankeymatic/LICENSE.txt`.
