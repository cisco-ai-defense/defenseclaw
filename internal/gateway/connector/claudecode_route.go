// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// Claude Code route-only keys in settings.json env (DESIGN 7.2). They have
// their own record, separate from claudeCodeOtelEnvKeys, so the OTLP
// cleanup never touches them.
const (
	claudeCodeRouteBaseURL        = "ANTHROPIC_BASE_URL"
	claudeCodeRouteBedrockBaseURL = "ANTHROPIC_BEDROCK_BASE_URL"
	claudeCodeRouteSkipBedrock    = "CLAUDE_CODE_SKIP_BEDROCK_AUTH"
	claudeCodeRouteHeaders        = "ANTHROPIC_CUSTOM_HEADERS"
)

func claudeCodeRouteEnv(route *RouteOnlySetup) map[string]string {
	if route == nil {
		return nil
	}
	env := map[string]string{claudeCodeRouteHeaders: route.Token}
	if route.Bedrock {
		env[claudeCodeRouteBedrockBaseURL] = route.BaseURL
		if route.GatewaySigning {
			env[claudeCodeRouteSkipBedrock] = "1"
		}
	} else {
		env[claudeCodeRouteBaseURL] = route.BaseURL
	}
	return env
}

// ApplyRouteOnly implements RouteOnlyConnector.
func (c *ClaudeCodeConnector) ApplyRouteOnly(opts SetupOpts, route *RouteOnlySetup) error {
	settingsPath := claudeCodeSettingsPath()
	// Nothing rendered and nothing to render: touch no file (the lock would
	// create the agent config directory).
	if route == nil {
		if b, err := loadRouteBackup(opts.DataDir, c.Name()); err == nil && len(b.Applied) == 0 {
			raw, rerr := os.ReadFile(settingsPath)
			if rerr != nil || (!bytes.Contains(raw, []byte("/r/claudecode")) && !bytes.Contains(raw, []byte(RouteOnlyHeader))) {
				return nil
			}
		}
	}
	return withFileLock(settingsPath, func() error {
		backup, err := loadRouteBackup(opts.DataDir, c.Name())
		if err != nil {
			return err
		}
		if route == nil && len(backup.Applied) == 0 {
			// No record: restore only if our own render is still there (a
			// lost record after a crash or a data-dir reset).
			raw, rerr := os.ReadFile(settingsPath)
			if rerr != nil || (!bytes.Contains(raw, []byte("/r/claudecode")) && !bytes.Contains(raw, []byte(RouteOnlyHeader))) {
				return nil
			}
			backup = lostClaudeRouteRecord()
		}
		err = atomicTransformFileWithStateDir(settingsPath, opts.DataDir, 0o600, func(data []byte, exists bool) (atomicTransformResult, error) {
			settings := map[string]interface{}{}
			if exists && len(bytes.TrimSpace(data)) > 0 {
				if err := json.Unmarshal(data, &settings); err != nil {
					return atomicTransformResult{}, fmt.Errorf("parse claude settings: %w", err)
				}
			} else if route == nil {
				return atomicTransformResult{Keep: true}, nil
			}
			env, _ := settings["env"].(map[string]interface{})
			if env == nil {
				env = map[string]interface{}{}
			}
			if route == nil {
				adoptLostSkipBedrock(env, &backup)
				restoreAllRouteEnv(env, claudeCodeRouteHeaders, &backup)
			} else {
				applyRouteEnv(env, claudeCodeRouteEnv(route), claudeCodeRouteHeaders, &backup)
			}
			if len(env) == 0 {
				delete(settings, "env")
			} else {
				settings["env"] = env
			}
			out, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				return atomicTransformResult{}, err
			}
			// The record goes first: a crash after it and before the agent
			// file is harmless (restore finds nothing of ours to change).
			if err := saveRouteBackup(opts.DataDir, c.Name(), backup); err != nil {
				return atomicTransformResult{}, fmt.Errorf("route backup: %w", err)
			}
			if exists && bytes.Equal(bytes.TrimSpace(out), bytes.TrimSpace(data)) {
				return atomicTransformResult{Keep: true}, nil
			}
			return atomicTransformResult{Data: out}, nil
		})
		if err != nil {
			return fmt.Errorf("claudecode route-only settings: %w", err)
		}
		return nil
	})
}

var _ RouteOnlyConnector = (*ClaudeCodeConnector)(nil)

// lostClaudeRouteRecord is the record a restore uses when ours is gone but
// the render is still in settings.json: every route key is treated as ours
// with no prior value; restoreRouteEnvKey removes only values that still
// look like our own render.
func lostClaudeRouteRecord() routeEnvBackup {
	b := routeEnvBackup{Original: map[string]*string{}, Applied: map[string]string{}}
	for _, k := range []string{claudeCodeRouteBaseURL, claudeCodeRouteBedrockBaseURL, claudeCodeRouteHeaders} {
		b.Original[k] = nil
		b.Applied[k] = lostRecordMarker
	}
	return b
}

const lostRecordMarker = "\x00lost-record"

// adoptLostSkipBedrock treats CLAUDE_CODE_SKIP_BEDROCK_AUTH=1 as ours on a
// lost-record restore only when our own Bedrock base URL render sits next
// to it: left behind, it would send unsigned calls straight to Bedrock. A
// skip the user set for another gateway stays.
func adoptLostSkipBedrock(env map[string]interface{}, b *routeEnvBackup) {
	if b.Applied[claudeCodeRouteBedrockBaseURL] != lostRecordMarker {
		return
	}
	base, _ := env[claudeCodeRouteBedrockBaseURL].(string)
	skip, _ := env[claudeCodeRouteSkipBedrock].(string)
	if isOwnRouteValue(base) && skip == "1" {
		b.Original[claudeCodeRouteSkipBedrock] = nil
		b.Applied[claudeCodeRouteSkipBedrock] = "1"
	}
}
