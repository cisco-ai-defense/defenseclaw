// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const configReloadDebounce = 500 * time.Millisecond

type ConfigDiff struct {
	Changed         []string
	RestartRequired []string
}

type configApplyFunc func(ctx context.Context, oldCfg, newCfg *config.Config, diff ConfigDiff) error

type ConfigManager struct {
	path   string
	apply  configApplyFunc
	logger *audit.Logger
	health *SidecarHealth

	current atomic.Value // *config.Config
	gen     atomic.Uint64
	mu      sync.Mutex
}

func NewConfigManager(path string, initial *config.Config, logger *audit.Logger, health *SidecarHealth, apply configApplyFunc) *ConfigManager {
	if strings.TrimSpace(path) == "" {
		path = config.ConfigPath()
	}
	m := &ConfigManager{
		path:   filepath.Clean(path),
		apply:  apply,
		logger: logger,
		health: health,
	}
	if initial != nil {
		m.current.Store(cloneConfig(initial))
	}
	return m
}

func (m *ConfigManager) Current() *config.Config {
	if m == nil {
		return nil
	}
	v := m.current.Load()
	if cfg, ok := v.(*config.Config); ok {
		return cloneConfig(cfg)
	}
	return nil
}

func (m *ConfigManager) Run(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if m.health != nil {
		m.health.SetConfig(StateRunning, "", map[string]interface{}{
			"path":       m.path,
			"generation": m.gen.Load(),
		})
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		if m.health != nil {
			m.health.SetConfig(StateError, err.Error(), map[string]interface{}{"path": m.path})
		}
		return fmt.Errorf("config watcher: %w", err)
	}
	defer fsw.Close()

	dir := filepath.Dir(m.path)
	if err := fsw.Add(dir); err != nil {
		if m.health != nil {
			m.health.SetConfig(StateError, err.Error(), map[string]interface{}{"path": m.path})
		}
		return fmt.Errorf("config watcher: watch %s: %w", dir, err)
	}

	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	pending := false
	for {
		select {
		case <-ctx.Done():
			if m.health != nil {
				m.health.SetConfig(StateStopped, "", map[string]interface{}{"path": m.path})
			}
			return ctx.Err()
		case event := <-fsw.Events:
			if !m.matches(event.Name) {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			pending = true
			resetTimer(timer, configReloadDebounce)
		case err := <-fsw.Errors:
			if err != nil && m.health != nil {
				m.health.SetConfig(StateError, err.Error(), map[string]interface{}{"path": m.path})
			}
		case <-timer.C:
			if !pending {
				continue
			}
			pending = false
			if err := m.Reload(ctx, "fsnotify"); err != nil {
				fmt.Fprintf(os.Stderr, "[config] reload failed: %v\n", err)
			}
		}
	}
}

func (m *ConfigManager) Reload(ctx context.Context, reason string) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	oldCfg := m.Current()
	next, err := config.LoadFromFile(m.path)
	if err != nil {
		if m.health != nil {
			m.health.SetConfig(StateError, err.Error(), map[string]interface{}{
				"path":       m.path,
				"generation": m.gen.Load(),
				"reason":     reason,
			})
		}
		return err
	}
	diff := diffConfigs(oldCfg, next)
	if len(diff.Changed) == 0 {
		if m.health != nil {
			m.health.SetConfig(StateRunning, "", map[string]interface{}{
				"path":       m.path,
				"generation": m.gen.Load(),
				"reason":     reason,
				"changed":    []string{},
			})
		}
		return nil
	}
	if m.apply != nil {
		if err := m.apply(ctx, oldCfg, next, diff); err != nil {
			if m.health != nil {
				m.health.SetConfig(StateError, err.Error(), map[string]interface{}{
					"path":             m.path,
					"generation":       m.gen.Load(),
					"reason":           reason,
					"changed":          diff.Changed,
					"restart_required": diff.RestartRequired,
				})
			}
			return err
		}
	}
	gen := m.gen.Add(1)
	m.current.Store(cloneConfig(next))
	if m.logger != nil {
		_ = m.logger.LogActionCtx(ctx, string(audit.ActionConfigUpdate), m.path,
			fmt.Sprintf("generation=%d changed=%s reason=%s", gen, strings.Join(diff.Changed, ","), reason))
	}
	if m.health != nil {
		m.health.SetConfig(StateRunning, "", map[string]interface{}{
			"path":             m.path,
			"generation":       gen,
			"reason":           reason,
			"changed":          diff.Changed,
			"restart_required": diff.RestartRequired,
			"last_success":     time.Now().UTC().Format(time.RFC3339),
		})
	}
	return nil
}

func cloneConfig(in *config.Config) *config.Config {
	if in == nil {
		return nil
	}
	data, err := yaml.Marshal(in)
	if err != nil {
		panic(fmt.Errorf("config manager: clone config: %w", err))
	}
	var out config.Config
	if err := yaml.Unmarshal(data, &out); err != nil {
		panic(fmt.Errorf("config manager: decode cloned config: %w", err))
	}
	out.ConfigFilePath = in.ConfigFilePath
	out.Gateway.NoTLS = in.Gateway.NoTLS
	out.Gateway.SandboxHome = in.Gateway.SandboxHome
	out.Gateway.ClawHome = in.Gateway.ClawHome
	return &out
}

func (m *ConfigManager) matches(path string) bool {
	return filepath.Clean(path) == m.path
}

func resetTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

func diffConfigs(oldCfg, newCfg *config.Config) ConfigDiff {
	if oldCfg == nil || newCfg == nil {
		return ConfigDiff{Changed: []string{"config"}}
	}
	var changed []string
	add := func(path string, oldVal, newVal any) {
		if !reflect.DeepEqual(oldVal, newVal) {
			changed = append(changed, path)
		}
	}
	add("llm", oldCfg.LLM, newCfg.LLM)
	add("claw", oldCfg.Claw, newCfg.Claw)
	add("agent", oldCfg.Agent, newCfg.Agent)
	add("cisco_ai_defense", oldCfg.CiscoAIDefense, newCfg.CiscoAIDefense)
	add("scanners", oldCfg.Scanners, newCfg.Scanners)
	add("watch", oldCfg.Watch, newCfg.Watch)
	add("guardrail", oldCfg.Guardrail, newCfg.Guardrail)
	add("gateway", oldCfg.Gateway, newCfg.Gateway)
	add("openshell", oldCfg.OpenShell, newCfg.OpenShell)
	add("skill_actions", oldCfg.SkillActions, newCfg.SkillActions)
	add("mcp_actions", oldCfg.MCPActions, newCfg.MCPActions)
	add("plugin_actions", oldCfg.PluginActions, newCfg.PluginActions)
	add("asset_policy", oldCfg.AssetPolicy, newCfg.AssetPolicy)
	add("registries", oldCfg.Registries, newCfg.Registries)
	add("otel", oldCfg.OTel, newCfg.OTel)
	add("connector_hooks", oldCfg.ConnectorHooks, newCfg.ConnectorHooks)
	add("audit_sinks", oldCfg.AuditSinks, newCfg.AuditSinks)
	add("webhooks", oldCfg.Webhooks, newCfg.Webhooks)
	add("observability", oldCfg.Observability, newCfg.Observability)
	add("privacy", oldCfg.Privacy, newCfg.Privacy)
	add("ai_discovery", oldCfg.AIDiscovery, newCfg.AIDiscovery)
	add("application_protection", oldCfg.ApplicationProtection, newCfg.ApplicationProtection)
	add("notifications", oldCfg.Notifications, newCfg.Notifications)
	add("environment", oldCfg.Environment, newCfg.Environment)
	add("tenant_id", oldCfg.TenantID, newCfg.TenantID)
	add("workspace_id", oldCfg.WorkspaceID, newCfg.WorkspaceID)
	add("deployment_mode", oldCfg.DeploymentMode, newCfg.DeploymentMode)
	add("discovery_source", oldCfg.DiscoverySource, newCfg.DiscoverySource)
	add("data_dir", oldCfg.DataDir, newCfg.DataDir)
	add("audit_db", oldCfg.AuditDB, newCfg.AuditDB)
	add("judge_bodies_db", oldCfg.JudgeBodiesDB, newCfg.JudgeBodiesDB)

	var restart []string
	if oldCfg.DataDir != newCfg.DataDir {
		restart = append(restart, "data_dir")
	}
	if oldCfg.AuditDB != newCfg.AuditDB {
		restart = append(restart, "audit_db")
	}
	if oldCfg.JudgeBodiesDB != newCfg.JudgeBodiesDB {
		restart = append(restart, "judge_bodies_db")
	}
	if oldCfg.Gateway.DeviceKeyFile != newCfg.Gateway.DeviceKeyFile {
		restart = append(restart, "gateway.device_key_file")
	}
	return ConfigDiff{Changed: changed, RestartRequired: restart}
}
