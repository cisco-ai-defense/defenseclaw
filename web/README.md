# DefenseClaw web dashboard

Lit + Vite source for the dashboard embedded into `defenseclaw-gateway`.
Built output goes to `../internal/dashboard/dist/` and is served by
`internal/dashboard/embed.go` from `127.0.0.1:18970/`.

## Aesthetic

The dashboard ports the TUI's terminal aesthetic to the browser. Palette,
casing, spacing, and dot indicators in `src/styles/tokens.css` mirror
`internal/tui/theme.go`. An optional CRT skin (scanlines, vignette, accent
glow) is layered via `<html data-effects="crt">` and can be turned off
without affecting layout. See [`docs/design/style-guide.md`](../docs/design/style-guide.md).

## Develop

```sh
npm install
npm run dev          # http://localhost:18971, proxies API to :18970
```

The dev server proxies `/health`, `/status`, `/alerts`, `/skills`, `/mcps`,
`/tools`, `/v1/*`, `/api/*` to the running gateway, so the dashboard talks to
real data while you edit.

## Build

```sh
make web             # writes ../internal/dashboard/dist/ + rebuilds gateway binary
```

## Layout

```
web/
├── index.html             # shell, sets data-effects="crt"
├── src/
│   ├── main.ts            # registers all custom elements
│   ├── components/
│   │   ├── dc-app.ts      # app shell + hash-based routing
│   │   ├── dc-sidebar.ts  # 7-item nav (OPERATE / EVIDENCE)
│   │   ├── dc-statusbar.ts
│   │   ├── dc-panel.ts    # functional container
│   │   └── dc-overview.ts
│   ├── lib/
│   │   ├── api.ts         # fetch client + schemas
│   │   └── poll.ts        # ReactiveController, 5s/30s tiers
│   └── styles/
│       ├── tokens.css     # palette mirrors lipgloss codes from TUI
│       ├── base.css
│       └── effects-crt.css
└── vite.config.ts
```

## Status

v1 covers Overview only. Other six nav items render placeholders pending the
backing REST endpoints (audit query API, log tail, watcher activity,
inventory unification, policy CRUD).
