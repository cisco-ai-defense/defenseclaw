package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type Config struct {
	DataDir       string          `mapstructure:"data_dir"       yaml:"data_dir"`
	AuditDB       string          `mapstructure:"audit_db"       yaml:"audit_db"`
	QuarantineDir string          `mapstructure:"quarantine_dir" yaml:"quarantine_dir"`
	PluginDir     string          `mapstructure:"plugin_dir"     yaml:"plugin_dir"`
	PolicyDir     string          `mapstructure:"policy_dir"     yaml:"policy_dir"`
	Environment   string          `mapstructure:"environment"    yaml:"environment"`
	Scanners      ScannersConfig  `mapstructure:"scanners"       yaml:"scanners"`
	OpenShell     OpenShellConfig `mapstructure:"openshell"      yaml:"openshell"`
	Watch         WatchConfig     `mapstructure:"watch"          yaml:"watch"`
}

type WatchConfig struct {
	SkillDirs    []string `mapstructure:"skill_dirs"    yaml:"skill_dirs"`
	MCPDirs      []string `mapstructure:"mcp_dirs"      yaml:"mcp_dirs"`
	DebounceMs   int      `mapstructure:"debounce_ms"   yaml:"debounce_ms"`
	AutoBlock    bool     `mapstructure:"auto_block"     yaml:"auto_block"`
}

type ScannersConfig struct {
	SkillScanner string `mapstructure:"skill_scanner" yaml:"skill_scanner"`
	MCPScanner   string `mapstructure:"mcp_scanner"   yaml:"mcp_scanner"`
	AIBOM        string `mapstructure:"aibom"          yaml:"aibom"`
	CodeGuard    string `mapstructure:"codeguard"      yaml:"codeguard"`
}

type OpenShellConfig struct {
	Binary    string `mapstructure:"binary"     yaml:"binary"`
	PolicyDir string `mapstructure:"policy_dir" yaml:"policy_dir"`
}

func Load() (*Config, error) {
	dataDir := DefaultDataPath()
	configFile := filepath.Join(dataDir, DefaultConfigName)

	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	setDefaults(dataDir)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("config: read %s: %w", configFile, err)
			}
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	return &cfg, nil
}

func (c *Config) Save() error {
	configFile := filepath.Join(c.DataDir, DefaultConfigName)

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}

	return os.WriteFile(configFile, data, 0o600)
}

func setDefaults(dataDir string) {
	viper.SetDefault("data_dir", dataDir)
	viper.SetDefault("audit_db", filepath.Join(dataDir, DefaultAuditDBName))
	viper.SetDefault("quarantine_dir", filepath.Join(dataDir, "quarantine"))
	viper.SetDefault("plugin_dir", filepath.Join(dataDir, "plugins"))
	viper.SetDefault("policy_dir", filepath.Join(dataDir, "policies"))
	viper.SetDefault("environment", string(DetectEnvironment()))
	viper.SetDefault("scanners.skill_scanner", "skill-scanner")
	viper.SetDefault("scanners.mcp_scanner", "mcp-scanner")
	viper.SetDefault("scanners.aibom", "cisco-aibom")
	viper.SetDefault("scanners.codeguard", filepath.Join(dataDir, "codeguard-rules"))
	viper.SetDefault("openshell.binary", "openshell")
	viper.SetDefault("openshell.policy_dir", "/etc/openshell/policies")

	viper.SetDefault("watch.skill_dirs", DefaultSkillWatchPaths())
	viper.SetDefault("watch.mcp_dirs", DefaultMCPWatchPaths())
	viper.SetDefault("watch.debounce_ms", 500)
	viper.SetDefault("watch.auto_block", true)
}
