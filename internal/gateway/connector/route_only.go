// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// RouteOnlySetup is the route-only rendering of one hook connector, derived
// from config.yaml routing.route_only (DESIGN 7.2, 17.5, 17.7). nil in
// SetupOpts means the connector is not routed: Setup removes what an
// earlier route-only render wrote and restores the agent values.
type RouteOnlySetup struct {
	// BaseURL is the route-only endpoint, http://127.0.0.1:<api>/r/<c>.
	BaseURL string
	// Token is the route credential the agent sends as X-DC-Route-Auth.
	Token string
	// Bedrock: the agent talks to Bedrock (Claude Code on Bedrock).
	Bedrock bool
	// GatewaySigning: the gateway signs Bedrock calls (the agent skips its
	// own AWS auth).
	GatewaySigning bool
	// Custody: the gateway holds the provider credential and forwards none
	// from the agent (managed macOS and Windows, S1 DESIGN 16.2). The agent
	// gets RouteOnlyPlaceholderCredential in place of its own key or login
	// token, so another account that binds the port while the gateway
	// restarts receives nothing it can use.
	Custody bool
}

// RouteOnlyPlaceholderCredential is the fixed, non-secret value a custody
// render gives the agent as its provider credential.
const RouteOnlyPlaceholderCredential = "defenseclaw-gateway-held-credential"

// RouteOnlyConnector is implemented by connectors whose agent exposes a
// model base URL (capability routing base_url).
type RouteOnlyConnector interface {
	// ApplyRouteOnly writes (route != nil) or removes (nil) the route-only
	// keys in the agent configuration, restoring the values it replaced.
	ApplyRouteOnly(opts SetupOpts, route *RouteOnlySetup) error
}

// RouteOnlyHeader is the header that carries the route credential.
const RouteOnlyHeader = "X-DC-Route-Auth"

// routeEnvBackup records what a route-only render replaced: Original holds
// the value each key had before the first render (nil = absent), Applied
// the value DefenseClaw wrote. A key the user changed after the render is
// left alone on restore.
type routeEnvBackup struct {
	Original map[string]*string `json:"original,omitempty"`
	Applied  map[string]string  `json:"applied,omitempty"`
	// Wrapped is the agent provider a render wrapped (Codex), kept so a
	// re-render never takes settings from a provider the user switched to.
	Wrapped map[string]interface{} `json:"wrapped,omitempty"`
}

// isOwnRouteValue reports a value that only a route-only render writes (a
// loopback /r/<connector> URL), used to recover after a lost record.
func isOwnRouteValue(v string) bool {
	return strings.Contains(v, "/r/claudecode") || strings.Contains(v, "/r/codex") || v == RouteOnlyPlaceholderCredential
}

func routeBackupPath(dataDir, connector string) string {
	return filepath.Join(dataDir, connector+"_route_backup.json")
}

func loadRouteBackup(dataDir, connector string) (routeEnvBackup, error) {
	var b routeEnvBackup
	raw, err := os.ReadFile(routeBackupPath(dataDir, connector))
	if errors.Is(err, os.ErrNotExist) {
		return routeEnvBackup{Original: map[string]*string{}, Applied: map[string]string{}}, nil
	}
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, fmt.Errorf("route backup %s: %w", routeBackupPath(dataDir, connector), err)
	}
	if b.Original == nil {
		b.Original = map[string]*string{}
	}
	if b.Applied == nil {
		b.Applied = map[string]string{}
	}
	return b, nil
}

func saveRouteBackup(dataDir, connector string, b routeEnvBackup) error {
	path := routeBackupPath(dataDir, connector)
	if len(b.Applied) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WritePrivate(path, raw)
}

// headerLines splits a "Name: value" newline list.
func headerLines(v string) []string {
	var out []string
	for _, line := range strings.Split(v, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func isRouteHeaderLine(line string) bool {
	name, _, ok := strings.Cut(line, ":")
	return ok && strings.EqualFold(strings.TrimSpace(name), RouteOnlyHeader)
}

// withRouteHeader returns the custom-headers value with our line set.
func withRouteHeader(current, token string) string {
	lines := []string{}
	for _, l := range headerLines(current) {
		if !isRouteHeaderLine(l) {
			lines = append(lines, l)
		}
	}
	lines = append(lines, RouteOnlyHeader+": "+token)
	return strings.Join(lines, "\n")
}

// withoutRouteHeader returns the custom-headers value without our line.
func withoutRouteHeader(current string) string {
	var lines []string
	for _, l := range headerLines(current) {
		if !isRouteHeaderLine(l) {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}

// applyRouteEnv updates env (string values) to desired, recording what it
// replaced in b. headerKey is the key that carries a header list where only
// our line is owned. Keys in b no longer desired are restored.
func applyRouteEnv(env map[string]interface{}, desired map[string]string, headerKey string, b *routeEnvBackup) {
	str := func(k string) (string, bool) {
		v, ok := env[k]
		if !ok {
			return "", false
		}
		s, isStr := v.(string)
		if !isStr {
			raw, _ := json.Marshal(v)
			s = string(raw)
		}
		return s, true
	}
	for k := range b.Applied {
		if _, keep := desired[k]; !keep {
			restoreRouteEnvKey(env, k, headerKey, b)
		}
	}
	for k, want := range desired {
		cur, had := str(k)
		if applied, recorded := b.Applied[k]; recorded && had && cur != applied {
			// The user changed the value after the render: theirs becomes the
			// value a restore puts back.
			orig := cur
			if k == headerKey {
				orig = withoutRouteHeader(cur)
			}
			b.Original[k] = &orig
		}
		if _, recorded := b.Original[k]; !recorded {
			if had && k != headerKey && isOwnRouteValue(cur) {
				// Our own render without its record (crash, reset): the value
				// before it is unknown, so a restore removes the key.
				b.Original[k] = nil
			} else if had {
				orig := cur
				if k == headerKey {
					orig = withoutRouteHeader(cur)
				}
				b.Original[k] = &orig
			} else {
				b.Original[k] = nil
			}
		}
		if k == headerKey {
			want = withRouteHeader(cur, want)
		}
		env[k] = want
		b.Applied[k] = want
	}
}

func restoreRouteEnvKey(env map[string]interface{}, k, headerKey string, b *routeEnvBackup) {
	applied := b.Applied[k]
	orig := b.Original[k]
	delete(b.Applied, k)
	delete(b.Original, k)
	cur, had := env[k].(string)
	if k == headerKey {
		if !had {
			return
		}
		rest := withoutRouteHeader(cur)
		switch {
		case rest == "" && orig == nil:
			delete(env, k)
		default:
			env[k] = rest
		}
		return
	}
	if applied == lostRecordMarker {
		applied = cur
		if !isOwnRouteValue(cur) {
			return
		}
	}
	if !had || cur != applied {
		// The user changed or removed it after the render: theirs stays.
		return
	}
	if orig == nil {
		delete(env, k)
	} else {
		env[k] = *orig
	}
}

// restoreAllRouteEnv restores every recorded key.
func restoreAllRouteEnv(env map[string]interface{}, headerKey string, b *routeEnvBackup) {
	for k := range b.Applied {
		restoreRouteEnvKey(env, k, headerKey, b)
	}
}
