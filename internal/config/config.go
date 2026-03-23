package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type ClawMode string

const (
	ClawOpenClaw ClawMode = "openclaw"
	// Future: ClawNemoClaw, ClawOpenCode, ClawClaudeCode
)

type ClawConfig struct {
	Mode       ClawMode `mapstructure:"mode"        yaml:"mode"`
	HomeDir    string   `mapstructure:"home_dir"    yaml:"home_dir"`
	ConfigFile string   `mapstructure:"config_file" yaml:"config_file"`
}

type Config struct {
	DataDir       string             `mapstructure:"data_dir"       yaml:"data_dir"`
	AuditDB       string             `mapstructure:"audit_db"       yaml:"audit_db"`
	QuarantineDir string             `mapstructure:"quarantine_dir" yaml:"quarantine_dir"`
	PluginDir     string             `mapstructure:"plugin_dir"     yaml:"plugin_dir"`
	PolicyDir     string             `mapstructure:"policy_dir"     yaml:"policy_dir"`
	Environment   string             `mapstructure:"environment"    yaml:"environment"`
	Claw          ClawConfig         `mapstructure:"claw"           yaml:"claw"`
	Scanners      ScannersConfig     `mapstructure:"scanners"       yaml:"scanners"`
	OpenShell     OpenShellConfig    `mapstructure:"openshell"      yaml:"openshell"`
	Watch         WatchConfig        `mapstructure:"watch"          yaml:"watch"`
	Firewall      FirewallConfig     `mapstructure:"firewall"       yaml:"firewall"`
	Splunk        SplunkConfig       `mapstructure:"splunk"         yaml:"splunk"`
	Gateway       GatewayConfig      `mapstructure:"gateway"        yaml:"gateway"`
	SkillActions  SkillActionsConfig `mapstructure:"skill_actions"  yaml:"skill_actions"`
}

type FirewallConfig struct {
	ConfigFile string `mapstructure:"config_file" yaml:"config_file"`
	RulesFile  string `mapstructure:"rules_file"  yaml:"rules_file"`
	AnchorName string `mapstructure:"anchor_name" yaml:"anchor_name"`
}

type SplunkConfig struct {
	HECEndpoint   string `mapstructure:"hec_endpoint"    yaml:"hec_endpoint"`
	HECToken      string `mapstructure:"hec_token"       yaml:"hec_token"`
	Index         string `mapstructure:"index"            yaml:"index"`
	Source        string `mapstructure:"source"           yaml:"source"`
	SourceType    string `mapstructure:"sourcetype"       yaml:"sourcetype"`
	VerifyTLS     bool   `mapstructure:"verify_tls"       yaml:"verify_tls"`
	Enabled       bool   `mapstructure:"enabled"          yaml:"enabled"`
	BatchSize     int    `mapstructure:"batch_size"       yaml:"batch_size"`
	FlushInterval int    `mapstructure:"flush_interval_s" yaml:"flush_interval_s"`
}

type WatchConfig struct {
	DebounceMs int  `mapstructure:"debounce_ms" yaml:"debounce_ms"`
	AutoBlock  bool `mapstructure:"auto_block"  yaml:"auto_block"`
}

type SkillScannerConfig struct {
	Binary         string `mapstructure:"binary"             yaml:"binary"`
	UseLLM         bool   `mapstructure:"use_llm"            yaml:"use_llm"`
	UseBehavioral  bool   `mapstructure:"use_behavioral"     yaml:"use_behavioral"`
	EnableMeta     bool   `mapstructure:"enable_meta"        yaml:"enable_meta"`
	UseTrigger     bool   `mapstructure:"use_trigger"        yaml:"use_trigger"`
	UseVirusTotal  bool   `mapstructure:"use_virustotal"     yaml:"use_virustotal"`
	UseAIDefense   bool   `mapstructure:"use_aidefense"      yaml:"use_aidefense"`
	LLMProvider    string `mapstructure:"llm_provider"       yaml:"llm_provider"`
	LLMModel       string `mapstructure:"llm_model"          yaml:"llm_model"`
	LLMConsensus   int    `mapstructure:"llm_consensus_runs" yaml:"llm_consensus_runs"`
	Policy         string `mapstructure:"policy"             yaml:"policy"`
	Lenient        bool   `mapstructure:"lenient"            yaml:"lenient"`
	LLMAPIKey      string `mapstructure:"llm_api_key"        yaml:"llm_api_key"`
	VirusTotalKey  string `mapstructure:"virustotal_api_key" yaml:"virustotal_api_key"`
	AIDefenseKey   string `mapstructure:"aidefense_api_key"  yaml:"aidefense_api_key"`
}

type ScannersConfig struct {
	SkillScanner SkillScannerConfig `mapstructure:"skill_scanner" yaml:"skill_scanner"`
	MCPScanner   string             `mapstructure:"mcp_scanner"   yaml:"mcp_scanner"`
	AIBOM        string             `mapstructure:"aibom"          yaml:"aibom"`
	CodeGuard    string             `mapstructure:"codeguard"      yaml:"codeguard"`
}

type OpenShellConfig struct {
	Binary    string `mapstructure:"binary"     yaml:"binary"`
	PolicyDir string `mapstructure:"policy_dir" yaml:"policy_dir"`
}

type GatewayConfig struct {
	Host            string `mapstructure:"host"              yaml:"host"`
	Port            int    `mapstructure:"port"              yaml:"port"`
	Token           string `mapstructure:"token"             yaml:"token"`
	DeviceKeyFile   string `mapstructure:"device_key_file"   yaml:"device_key_file"`
	AutoApprove     bool   `mapstructure:"auto_approve_safe" yaml:"auto_approve_safe"`
	ReconnectMs     int    `mapstructure:"reconnect_ms"      yaml:"reconnect_ms"`
	MaxReconnectMs  int    `mapstructure:"max_reconnect_ms"  yaml:"max_reconnect_ms"`
	ApprovalTimeout int    `mapstructure:"approval_timeout_s" yaml:"approval_timeout_s"`
}

type RuntimeAction string

const (
	RuntimeBlock RuntimeAction = "block"
	RuntimeAllow RuntimeAction = "allow"
)

type FileAction string

const (
	FileActionNone       FileAction = "none"
	FileActionQuarantine FileAction = "quarantine"
)

type SeverityAction struct {
	Runtime RuntimeAction `mapstructure:"runtime" yaml:"runtime"`
	File    FileAction    `mapstructure:"file"    yaml:"file"`
}

type SkillActionsConfig struct {
	Critical SeverityAction `mapstructure:"critical" yaml:"critical"`
	High     SeverityAction `mapstructure:"high"     yaml:"high"`
	Medium   SeverityAction `mapstructure:"medium"   yaml:"medium"`
	Low      SeverityAction `mapstructure:"low"      yaml:"low"`
	Info     SeverityAction `mapstructure:"info"     yaml:"info"`
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
	if err := cfg.SkillActions.Validate(); err != nil {
		return nil, err
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
	viper.SetDefault("claw.mode", string(ClawOpenClaw))
	viper.SetDefault("claw.home_dir", "~/.openclaw")
	viper.SetDefault("claw.config_file", "~/.openclaw/openclaw.json")

	viper.SetDefault("scanners.skill_scanner.binary", "skill-scanner")
	viper.SetDefault("scanners.skill_scanner.use_llm", false)
	viper.SetDefault("scanners.skill_scanner.use_behavioral", false)
	viper.SetDefault("scanners.skill_scanner.enable_meta", false)
	viper.SetDefault("scanners.skill_scanner.use_trigger", false)
	viper.SetDefault("scanners.skill_scanner.use_virustotal", false)
	viper.SetDefault("scanners.skill_scanner.use_aidefense", false)
	viper.SetDefault("scanners.skill_scanner.llm_provider", "")
	viper.SetDefault("scanners.skill_scanner.llm_model", "")
	viper.SetDefault("scanners.skill_scanner.llm_consensus_runs", 0)
	viper.SetDefault("scanners.skill_scanner.policy", "")
	viper.SetDefault("scanners.skill_scanner.lenient", false)
	viper.SetDefault("scanners.skill_scanner.llm_api_key", "")
	viper.SetDefault("scanners.skill_scanner.virustotal_api_key", "")
	viper.SetDefault("scanners.skill_scanner.aidefense_api_key", "")
	viper.SetDefault("scanners.mcp_scanner", "mcp-scanner")
	viper.SetDefault("scanners.aibom", "cisco-aibom")
	viper.SetDefault("scanners.codeguard", filepath.Join(dataDir, "codeguard-rules"))
	viper.SetDefault("openshell.binary", "openshell")
	viper.SetDefault("openshell.policy_dir", "/etc/openshell/policies")

	viper.SetDefault("watch.debounce_ms", 500)
	viper.SetDefault("watch.auto_block", true)

	viper.SetDefault("splunk.hec_endpoint", "https://localhost:8088/services/collector/event")
	viper.SetDefault("splunk.hec_token", "")
	viper.SetDefault("splunk.index", "defenseclaw")
	viper.SetDefault("splunk.source", "defenseclaw")
	viper.SetDefault("splunk.sourcetype", "_json")
	viper.SetDefault("splunk.verify_tls", false)
	viper.SetDefault("splunk.enabled", false)
	viper.SetDefault("splunk.batch_size", 50)
	viper.SetDefault("splunk.flush_interval_s", 5)

	viper.SetDefault("skill_actions.critical.runtime", string(RuntimeBlock))
	viper.SetDefault("skill_actions.critical.file", string(FileActionQuarantine))
	viper.SetDefault("skill_actions.high.runtime", string(RuntimeBlock))
	viper.SetDefault("skill_actions.high.file", string(FileActionQuarantine))
	viper.SetDefault("skill_actions.medium.runtime", string(RuntimeAllow))
	viper.SetDefault("skill_actions.medium.file", string(FileActionNone))
	viper.SetDefault("skill_actions.low.runtime", string(RuntimeAllow))
	viper.SetDefault("skill_actions.low.file", string(FileActionNone))
	viper.SetDefault("skill_actions.info.runtime", string(RuntimeAllow))
	viper.SetDefault("skill_actions.info.file", string(FileActionNone))

	viper.SetDefault("gateway.host", "127.0.0.1")
	viper.SetDefault("gateway.port", 18789)
	viper.SetDefault("gateway.token", "")
	viper.SetDefault("gateway.device_key_file", filepath.Join(dataDir, "device.key"))
	viper.SetDefault("gateway.auto_approve_safe", false)
	viper.SetDefault("gateway.reconnect_ms", 800)
	viper.SetDefault("gateway.max_reconnect_ms", 15000)
	viper.SetDefault("gateway.approval_timeout_s", 30)
}
