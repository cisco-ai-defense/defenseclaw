// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	return withFileLock(settingsPath, func() error {
		backup, err := loadRouteBackup(opts.DataDir, c.Name())
		if err != nil {
			return err
		}
		if route == nil && len(backup.Applied) == 0 {
			return nil
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
			if exists && bytes.Equal(bytes.TrimSpace(out), bytes.TrimSpace(data)) {
				return atomicTransformResult{Keep: true}, nil
			}
			return atomicTransformResult{Data: out}, nil
		})
		if err != nil {
			return fmt.Errorf("claudecode route-only settings: %w", err)
		}
		return saveRouteBackup(opts.DataDir, c.Name(), backup)
	})
}

var _ RouteOnlyConnector = (*ClaudeCodeConnector)(nil)
