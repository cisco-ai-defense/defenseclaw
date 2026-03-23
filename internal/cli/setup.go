package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure DefenseClaw components",
}

// Flags for non-interactive mode.
var (
	setupUseLLM        bool
	setupUseBehavioral bool
	setupEnableMeta    bool
	setupUseTrigger    bool
	setupUseVirusTotal bool
	setupUseAIDefense  bool
	setupLLMProvider   string
	setupLLMModel      string
	setupLLMConsensus  int
	setupPolicy        string
	setupLenient       bool
	setupNonInteractive bool
)

var setupSkillScannerCmd = &cobra.Command{
	Use:   "skill-scanner",
	Short: "Configure skill-scanner analyzers, API keys, and policy",
	Long: `Interactively configure how skill-scanner runs. Enables LLM analysis,
behavioral dataflow analysis, meta-analyzer filtering, and more.

API keys are stored in ~/.defenseclaw/config.yaml and injected as environment
variables when skill-scanner runs — no need to export them manually.

Use --non-interactive with flags for CI/scripted configuration.`,
	RunE: runSetupSkillScanner,
}

func init() {
	f := setupSkillScannerCmd.Flags()
	f.BoolVar(&setupUseLLM, "use-llm", false, "Enable LLM analyzer")
	f.BoolVar(&setupUseBehavioral, "use-behavioral", false, "Enable behavioral analyzer")
	f.BoolVar(&setupEnableMeta, "enable-meta", false, "Enable meta-analyzer")
	f.BoolVar(&setupUseTrigger, "use-trigger", false, "Enable trigger analyzer")
	f.BoolVar(&setupUseVirusTotal, "use-virustotal", false, "Enable VirusTotal scanner")
	f.BoolVar(&setupUseAIDefense, "use-aidefense", false, "Enable AI Defense analyzer")
	f.StringVar(&setupLLMProvider, "llm-provider", "", "LLM provider (anthropic or openai)")
	f.StringVar(&setupLLMModel, "llm-model", "", "LLM model name")
	f.IntVar(&setupLLMConsensus, "llm-consensus-runs", 0, "LLM consensus runs (0 = disabled)")
	f.StringVar(&setupPolicy, "policy", "", "Scan policy preset (strict, balanced, permissive)")
	f.BoolVar(&setupLenient, "lenient", false, "Tolerate malformed skills")
	f.BoolVar(&setupNonInteractive, "non-interactive", false, "Use flags instead of prompts")

	setupCmd.AddCommand(setupSkillScannerCmd)
	rootCmd.AddCommand(setupCmd)
}

func runSetupSkillScanner(_ *cobra.Command, _ []string) error {
	sc := &cfg.Scanners.SkillScanner

	if setupNonInteractive {
		applyFlagsToConfig(sc)
	} else {
		if err := runInteractiveSetup(sc); err != nil {
			return err
		}
	}

	if err := cfg.Save(); err != nil {
		return fmt.Errorf("setup: save config: %w", err)
	}

	printSetupSummary(sc)

	if auditLog != nil {
		_ = auditLog.LogAction("setup-skill-scanner", "config", formatAuditDetail(sc))
	}
	return nil
}

func applyFlagsToConfig(sc *config.SkillScannerConfig) {
	sc.UseLLM = setupUseLLM
	sc.UseBehavioral = setupUseBehavioral
	sc.EnableMeta = setupEnableMeta
	sc.UseTrigger = setupUseTrigger
	sc.UseVirusTotal = setupUseVirusTotal
	sc.UseAIDefense = setupUseAIDefense
	if setupLLMProvider != "" {
		sc.LLMProvider = setupLLMProvider
	}
	if setupLLMModel != "" {
		sc.LLMModel = setupLLMModel
	}
	sc.LLMConsensus = setupLLMConsensus
	if setupPolicy != "" {
		sc.Policy = setupPolicy
	}
	sc.Lenient = setupLenient
}

func runInteractiveSetup(sc *config.SkillScannerConfig) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("  Skill Scanner Configuration")
	fmt.Println("  ────────────────────────────")
	fmt.Printf("  Binary: %s\n\n", sc.Binary)

	sc.UseBehavioral = promptBool(reader, "Enable behavioral analyzer (dataflow analysis)?", sc.UseBehavioral)
	sc.UseLLM = promptBool(reader, "Enable LLM analyzer (semantic analysis)?", sc.UseLLM)

	if sc.UseLLM {
		sc.LLMProvider = promptString(reader, "LLM provider (anthropic/openai)", sc.LLMProvider, "anthropic")
		sc.LLMModel = promptString(reader, "LLM model name", sc.LLMModel, "")
		sc.EnableMeta = promptBool(reader, "Enable meta-analyzer (false positive filtering)?", sc.EnableMeta)
		sc.LLMConsensus = promptInt(reader, "LLM consensus runs (0 = disabled)", sc.LLMConsensus)
		sc.LLMAPIKey = promptSecret(reader, "SKILL_SCANNER_LLM_API_KEY", sc.LLMAPIKey)
	}

	sc.UseTrigger = promptBool(reader, "Enable trigger analyzer (vague description checks)?", sc.UseTrigger)

	sc.UseVirusTotal = promptBool(reader, "Enable VirusTotal binary scanner?", sc.UseVirusTotal)
	if sc.UseVirusTotal {
		sc.VirusTotalKey = promptSecret(reader, "VIRUSTOTAL_API_KEY", sc.VirusTotalKey)
	}

	sc.UseAIDefense = promptBool(reader, "Enable Cisco AI Defense analyzer?", sc.UseAIDefense)
	if sc.UseAIDefense {
		sc.AIDefenseKey = promptSecret(reader, "AI_DEFENSE_API_KEY", sc.AIDefenseKey)
	}

	fmt.Println()
	sc.Policy = promptChoice(reader, "Scan policy preset", []string{"strict", "balanced", "permissive"}, sc.Policy)
	sc.Lenient = promptBool(reader, "Lenient mode (tolerate malformed skills)?", sc.Lenient)

	return nil
}

func printSetupSummary(sc *config.SkillScannerConfig) {
	fmt.Println()
	fmt.Println("  Saved to ~/.defenseclaw/config.yaml")
	fmt.Println()

	type row struct {
		key string
		val string
	}
	rows := []row{
		{"use_behavioral", fmt.Sprintf("%v", sc.UseBehavioral)},
		{"use_llm", fmt.Sprintf("%v", sc.UseLLM)},
	}
	if sc.UseLLM {
		rows = append(rows, row{"llm_provider", sc.LLMProvider})
		if sc.LLMModel != "" {
			rows = append(rows, row{"llm_model", sc.LLMModel})
		}
		rows = append(rows, row{"enable_meta", fmt.Sprintf("%v", sc.EnableMeta)})
		if sc.LLMConsensus > 0 {
			rows = append(rows, row{"llm_consensus_runs", fmt.Sprintf("%d", sc.LLMConsensus)})
		}
		if sc.LLMAPIKey != "" {
			rows = append(rows, row{"llm_api_key", maskKey(sc.LLMAPIKey)})
		}
	}
	if sc.UseTrigger {
		rows = append(rows, row{"use_trigger", "true"})
	}
	if sc.UseVirusTotal {
		rows = append(rows, row{"use_virustotal", "true"})
		if sc.VirusTotalKey != "" {
			rows = append(rows, row{"virustotal_api_key", maskKey(sc.VirusTotalKey)})
		}
	}
	if sc.UseAIDefense {
		rows = append(rows, row{"use_aidefense", "true"})
		if sc.AIDefenseKey != "" {
			rows = append(rows, row{"aidefense_api_key", maskKey(sc.AIDefenseKey)})
		}
	}
	if sc.Policy != "" {
		rows = append(rows, row{"policy", sc.Policy})
	}
	if sc.Lenient {
		rows = append(rows, row{"lenient", "true"})
	}

	for _, r := range rows {
		fmt.Printf("    scanners.skill_scanner.%-20s %s\n", r.key+":", r.val)
	}
	fmt.Println()
}

func formatAuditDetail(sc *config.SkillScannerConfig) string {
	parts := []string{
		fmt.Sprintf("use_llm=%v", sc.UseLLM),
		fmt.Sprintf("use_behavioral=%v", sc.UseBehavioral),
		fmt.Sprintf("enable_meta=%v", sc.EnableMeta),
	}
	if sc.LLMProvider != "" {
		parts = append(parts, fmt.Sprintf("llm_provider=%s", sc.LLMProvider))
	}
	if sc.Policy != "" {
		parts = append(parts, fmt.Sprintf("policy=%s", sc.Policy))
	}
	return strings.Join(parts, " ")
}

// --- prompt helpers ---

func promptBool(r *bufio.Reader, prompt string, current bool) bool {
	defLabel := "y/N"
	if current {
		defLabel = "Y/n"
	}
	fmt.Printf("  %s [%s]: ", prompt, defLabel)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	switch line {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return current
	}
}

func promptString(r *bufio.Reader, prompt, current, fallback string) string {
	def := current
	if def == "" {
		def = fallback
	}
	if def != "" {
		fmt.Printf("  %s [%s]: ", prompt, def)
	} else {
		fmt.Printf("  %s: ", prompt)
	}
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		if current != "" {
			return current
		}
		return fallback
	}
	return line
}

func promptInt(r *bufio.Reader, prompt string, current int) int {
	fmt.Printf("  %s [%d]: ", prompt, current)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return current
	}
	var v int
	if _, err := fmt.Sscanf(line, "%d", &v); err == nil {
		return v
	}
	return current
}

func promptSecret(r *bufio.Reader, envName string, current string) string {
	// Show existing env var if set and no stored value.
	envVal := os.Getenv(envName)

	hint := "(not set)"
	if current != "" {
		hint = maskKey(current)
	} else if envVal != "" {
		hint = fmt.Sprintf("from env: %s", maskKey(envVal))
	}
	fmt.Printf("  %s [%s]: ", envName, hint)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		if current != "" {
			return current
		}
		return envVal
	}
	return line
}

func promptChoice(r *bufio.Reader, prompt string, options []string, current string) string {
	optStr := strings.Join(options, "/")
	if current != "" {
		fmt.Printf("  %s (%s) [%s]: ", prompt, optStr, current)
	} else {
		fmt.Printf("  %s (%s) [none]: ", prompt, optStr)
	}
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return current
	}
	for _, o := range options {
		if line == o {
			return o
		}
	}
	fmt.Printf("    invalid choice %q, keeping %q\n", line, current)
	return current
}

func maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "..." + key[len(key)-4:]
}
