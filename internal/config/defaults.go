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

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Environment string

const (
	EnvDGXSpark Environment = "dgx-spark"
	EnvMacOS    Environment = "macos"
	EnvLinux    Environment = "linux"
)

const (
	DefaultDataDirName = ".defenseclaw"
	DefaultAuditDBName = "audit.db"
	DefaultConfigName  = "config.yaml"
)

func DefaultDataPath() string {
	if v := os.Getenv("DEFENSECLAW_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, DefaultDataDirName)
}

func ConfigPath() string {
	return filepath.Join(DefaultDataPath(), DefaultConfigName)
}

func DetectEnvironment() Environment {
	if runtime.GOOS == "darwin" {
		return EnvMacOS
	}

	if _, err := os.Stat("/etc/dgx-release"); err == nil {
		return EnvDGXSpark
	}

	out, err := exec.Command("nvidia-smi", "-L").Output()
	if err == nil && strings.Contains(string(out), "DGX") {
		return EnvDGXSpark
	}

	return EnvLinux
}

// DefaultSkillWatchPaths returns skill directories for the default claw mode.
// Prefer SkillDirsForMode when a config is available.
func DefaultSkillWatchPaths() []string {
	return SkillDirsForMode(ClawOpenClaw, "")
}

func DefaultConfig() *Config {
	dataDir := DefaultDataPath()
	clawMode := ClawOpenClaw
	return &Config{
		DataDir:       dataDir,
		AuditDB:       filepath.Join(dataDir, DefaultAuditDBName),
		QuarantineDir: filepath.Join(dataDir, "quarantine"),
		PluginDir:     "",
		PolicyDir:     filepath.Join(dataDir, "policies"),
		Environment:   string(DetectEnvironment()),
		Claw: ClawConfig{
			Mode:       clawMode,
			HomeDir:    "~/.openclaw",
			ConfigFile: "~/.openclaw/openclaw.json",
		},
		InspectLLM: InspectLLMConfig{
			Timeout:    30,
			MaxRetries: 3,
		},
		CiscoAIDefense: CiscoAIDefenseConfig{
			Endpoint:  "https://us.api.inspect.aidefense.security.cisco.com",
			APIKeyEnv: "CISCO_AI_DEFENSE_API_KEY",
			TimeoutMs: 3000,
		},
		Scanners: ScannersConfig{
			SkillScanner: SkillScannerConfig{
				Binary:  "skill-scanner",
				Policy:  "permissive",
				Lenient: true,
			},
			MCPScanner: MCPScannerConfig{
				Binary:    "mcp-scanner",
				Analyzers: "yara",
			},
			PluginScanner: "defenseclaw",
			CodeGuard:     filepath.Join(dataDir, "codeguard-rules"),
		},
		OpenShell: OpenShellConfig{
			Binary:    "openshell",
			PolicyDir: "/etc/openshell/policies",
			Version:   DefaultOpenShellVersion,
		},
		Watch: WatchConfig{
			DebounceMs:          500,
			AutoBlock:           true,
			AllowListBypassScan: true,
			RescanEnabled:       true,
			RescanIntervalMin:   60,
		},
		Firewall: FirewallConfig{
			ConfigFile: filepath.Join(dataDir, "firewall.yaml"),
			RulesFile:  filepath.Join(dataDir, "firewall.pf.conf"),
			AnchorName: "com.defenseclaw",
		},
		Guardrail: GuardrailConfig{
			Mode:                        "observe",
			ScannerMode:                 "both",
			Host:                        "",
			Port:                        4000,
			DetectionStrategy:           "regex_judge",
			DetectionStrategyCompletion: "regex_only",
			Judge: JudgeConfig{
				Injection:     true,
				PII:           true,
				PIIPrompt:     true,
				PIICompletion: true,
				ToolInjection: true,
				Timeout:       30.0,
			},
		},
		// AuditSinks is empty by default — operators opt in to forwarding
		// by adding entries (splunk_hec / otlp_logs / http_jsonl). The
		// local SQLite store always receives every event.
		AuditSinks: nil,
		Gateway: GatewayConfig{
			Host:            "127.0.0.1",
			Port:            18789,
			DeviceKeyFile:   filepath.Join(dataDir, "device.key"),
			AutoApprove:     false,
			ReconnectMs:     800,
			MaxReconnectMs:  15000,
			ApprovalTimeout: 30,
			APIPort:         18970,
			Watcher: GatewayWatcherConfig{
				Enabled: true,
				Skill: GatewayWatcherSkillConfig{
					Enabled:    true,
					TakeAction: true,
					Dirs:       []string{},
				},
				Plugin: GatewayWatcherPluginConfig{
					Enabled:    true,
					TakeAction: true,
					Dirs:       []string{},
				},
			},
		},
		SkillActions:  DefaultSkillActions(),
		MCPActions:    DefaultMCPActions(),
		PluginActions: DefaultPluginActions(),
	}
}
