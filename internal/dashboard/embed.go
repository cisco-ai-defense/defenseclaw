// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package dashboard embeds the built web UI and serves it as an http.Handler.
//
// The UI is built from ../../web by `make web` and copied into ./dist before
// `go build` so that the binary is self-contained.  Missing dist/ degrades
// gracefully to an "unbuilt" placeholder page.
package dashboard

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns an http.Handler that serves the embedded dashboard.
//
// Behavior:
//   - /assets/<hashed>.(js|css) → served from the embedded FS with
//     `Cache-Control: public, max-age=31536000, immutable` (hash-based busting)
//   - /index.html, /, and SPA deep-link paths → served as index.html with
//     `Cache-Control: no-cache` so updates take effect on next reload
//   - any path that matches a file in the FS is served directly
//   - CSP header restricts scripts/styles/fonts to self + Google Fonts
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return unbuiltHandler(err)
	}

	if _, err := fs.Stat(sub, "index.html"); err != nil {
		// dist/ exists but is empty — build hasn't run yet.
		return unbuiltHandler(err)
	}

	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)

		path := r.URL.Path
		if path == "" || path == "/" {
			serveIndex(w, r, sub)
			return
		}

		clean := strings.TrimPrefix(path, "/")

		// Long cache for hashed asset bundles.
		if strings.HasPrefix(clean, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			fileServer.ServeHTTP(w, r)
			return
		}

		// If it's a real file in the FS, serve it directly (favicon, etc.).
		if _, err := fs.Stat(sub, clean); err == nil {
			w.Header().Set("Cache-Control", "no-cache")
			fileServer.ServeHTTP(w, r)
			return
		}

		// SPA fallback — serve index.html for unknown paths.
		serveIndex(w, r, sub)
	})
}

func serveIndex(w http.ResponseWriter, _ *http.Request, sub fs.FS) {
	data, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "dashboard asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_, _ = w.Write(data)
}

func setSecurityHeaders(w http.ResponseWriter) {
	// Restrict to self plus Google Fonts (for Share Tech Mono / Inter loaded
	// via <link> in index.html). API calls are same-origin.
	csp := strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
		"font-src 'self' https://fonts.gstatic.com data:",
		"img-src 'self' data:",
		"connect-src 'self'",
		"frame-ancestors 'none'",
		"base-uri 'self'",
		"form-action 'self'",
	}, "; ")
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func unbuiltHandler(reason error) http.Handler {
	msg := fmt.Sprintf(`<!doctype html>
<html><head><title>DefenseClaw — dashboard not built</title>
<style>
body{background:#070b12;color:#c7d5e4;font-family:monospace;padding:40px;line-height:1.6;}
h1{color:#049FD9;letter-spacing:.2em;text-transform:uppercase;}
code{background:#0c131c;padding:4px 8px;border:1px solid #1e3346;border-radius:3px;color:#e8f3ff;}
</style></head>
<body>
<h1>// DefenseClaw Dashboard</h1>
<p>The web dashboard assets have not been built into this binary.</p>
<p>Run <code>make web</code> from the project root, then rebuild the gateway:</p>
<pre><code>make web
make gateway
</code></pre>
<p style="color:#566b82;margin-top:24px;">reason: %s</p>
</body></html>`, reason)

	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write([]byte(msg))
	})
}
