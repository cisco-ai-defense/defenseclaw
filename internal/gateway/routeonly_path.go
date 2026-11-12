// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"path"
	"strings"
)

// routeOnlyPrefix is the path prefix of the route-only listener for hook
// connectors (DESIGN 16.1). It is distinct from the retired /c/<connector>
// guardrail-proxy forms that Codex Setup deletes.
const routeOnlyPrefix = "/r/"

// routeOnlyClaim reports whether r belongs to the route-only chain: any
// path that starts with /r or /R followed by a separator, in raw or escaped
// form. A claimed request never reaches the API mux.
func routeOnlyClaim(r *http.Request) bool {
	raw := r.URL.EscapedPath()
	if len(raw) < 2 || raw[0] != 0x2f {
		return false
	}
	if raw[1] != 0x72 && raw[1] != 0x52 {
		return false
	}
	return len(raw) == 2 || raw[2] == 0x2f || strings.HasPrefix(raw[2:], "%2") || strings.HasPrefix(raw[2:], "%5")
}

// routeOnlyParse splits a claimed path into connector and the native path
// the agent used, or returns ok false for anything ambiguous: a capital R,
// a path that path.Clean changes, an escaped dot, slash or backslash in the
// connector segment, or a dot segment anywhere.
func routeOnlyParse(r *http.Request) (connector, native string, ok bool) {
	escaped := r.URL.EscapedPath()
	if !strings.HasPrefix(escaped, routeOnlyPrefix) {
		return "", "", false
	}
	decoded := r.URL.Path
	if path.Clean(decoded) != strings.TrimSuffix(decoded, "/") && path.Clean(decoded) != decoded {
		return "", "", false
	}
	for _, seg := range strings.Split(escaped, "/") {
		if seg == "." || seg == ".." {
			return "", "", false
		}
		lower := strings.ToLower(seg)
		if strings.Contains(lower, "%2e%2e") || lower == "%2e" || strings.HasPrefix(lower, "%2e.") || strings.HasPrefix(lower, ".%2e") {
			return "", "", false
		}
	}
	rest := strings.TrimPrefix(escaped, routeOnlyPrefix)
	connector, native, found := strings.Cut(rest, "/")
	if !found || connector == "" {
		return "", "", false
	}
	for _, c := range connector {
		if (c < 0x61 || c > 0x7a) && (c < 0x30 || c > 0x39) {
			return "", "", false
		}
	}
	return connector, "/" + native, true
}
