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

// DefaultMCPWatchPaths returns MCP directories for the default claw mode.
// Prefer MCPDirsForMode when a config is available.
func DefaultMCPWatchPaths() []string {
	return MCPDirsForMode(ClawOpenClaw, "")
}

func DefaultConfig() *Config {
	dataDir := DefaultDataPath()
	clawMode := ClawOpenClaw
	return &Config{
		DataDir:       dataDir,
		AuditDB:       filepath.Join(dataDir, DefaultAuditDBName),
		QuarantineDir: filepath.Join(dataDir, "quarantine"),
		PluginDir:     filepath.Join(dataDir, "plugins"),
		PolicyDir:     filepath.Join(dataDir, "policies"),
		Environment:   string(DetectEnvironment()),
		Claw: ClawConfig{
			Mode:       clawMode,
			HomeDir:    "~/.openclaw",
			ConfigFile: "~/.openclaw/openclaw.json",
		},
		Scanners: ScannersConfig{
			SkillScanner: SkillScannerConfig{
				Binary: "skill-scanner",
			},
			MCPScanner: "mcp-scanner",
			AIBOM:      "cisco-aibom",
			CodeGuard:  filepath.Join(dataDir, "codeguard-rules"),
		},
		OpenShell: OpenShellConfig{
			Binary:    "openshell",
			PolicyDir: "/etc/openshell/policies",
		},
		Watch: WatchConfig{
			DebounceMs: 500,
			AutoBlock:  true,
		},
		Firewall: FirewallConfig{
			ConfigFile: filepath.Join(dataDir, "firewall.yaml"),
			RulesFile:  filepath.Join(dataDir, "firewall.pf.conf"),
			AnchorName: "com.defenseclaw",
		},
		Splunk: SplunkConfig{
			HECEndpoint:   "https://localhost:8088/services/collector/event",
			Index:         "defenseclaw",
			Source:        "defenseclaw",
			SourceType:    "_json",
			VerifyTLS:     false,
			Enabled:       false,
			BatchSize:     50,
			FlushInterval: 5,
		},
		Gateway: GatewayConfig{
			Host:            "127.0.0.1",
			Port:            18789,
			DeviceKeyFile:   filepath.Join(dataDir, "device.key"),
			AutoApprove:     false,
			ReconnectMs:     800,
			MaxReconnectMs:  15000,
			ApprovalTimeout: 30,
		},
		SkillActions: DefaultSkillActions(),
	}
}
