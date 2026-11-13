// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
)

// Route-only drift (S1 DESIGN 18.3): per-user agent files are writable by
// the user they route, so the managed guardian checks the rendering on
// every verify and repairs (re-renders) on drift.

// ErrRouteConfigDrift names a route-only rendering that differs from the
// one config.yaml selects; its text starts with route_config_drift so the
// guardian repair report carries it.
var ErrRouteConfigDrift = errors.New("route_config_drift")

// RouteOnlyDrift reports whether the route-only keys of conn in the agent
// files differ from route (nil: nothing may be rendered). Connectors
// without route-only support never drift.
func RouteOnlyDrift(conn Connector, opts SetupOpts, route *RouteOnlySetup) error {
	var current bool
	var err error
	switch c := conn.(type) {
	case *ClaudeCodeConnector:
		current, err = c.routeOnlyCurrent(opts, route)
	case *CodexConnector:
		current, err = c.routeOnlyCurrent(opts, route)
	default:
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrRouteConfigDrift, conn.Name(), err)
	}
	if !current {
		return fmt.Errorf("%w: %s route-only settings differ from config.yaml", ErrRouteConfigDrift, conn.Name())
	}
	return nil
}

func (c *ClaudeCodeConnector) routeOnlyCurrent(opts SetupOpts, route *RouteOnlySetup) (bool, error) {
	backup, err := loadRouteBackup(opts.DataDir, c.Name())
	if err != nil {
		return false, err
	}
	if route == nil {
		return len(backup.Applied) == 0, nil
	}
	raw, err := os.ReadFile(claudeCodeSettingsPath())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	settings := map[string]interface{}{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return false, nil
		}
	}
	env, _ := settings["env"].(map[string]interface{})
	desired := claudeCodeRouteEnv(route)
	for key, want := range desired {
		cur, _ := env[key].(string)
		if key == claudeCodeRouteHeaders {
			if !slices.Contains(headerLines(cur), RouteOnlyHeader+": "+want) {
				return false, nil
			}
			continue
		}
		if cur != want {
			return false, nil
		}
	}
	for key := range backup.Applied {
		if _, ok := desired[key]; !ok {
			return false, nil
		}
	}
	return true, nil
}

func (c *CodexConnector) routeOnlyCurrent(opts SetupOpts, route *RouteOnlySetup) (bool, error) {
	backup, err := loadRouteBackup(opts.DataDir, c.Name())
	if err != nil {
		return false, err
	}
	if route == nil {
		return len(backup.Applied) == 0, nil
	}
	raw, err := os.ReadFile(codexConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	out, err := renderCodexRoute(raw, route, &backup)
	if err != nil {
		return false, nil
	}
	return bytes.Equal(out, raw), nil
}
