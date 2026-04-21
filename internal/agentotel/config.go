package agentotel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ConfigureOpts holds options for persistent Claude/Codex telemetry config.
type ConfigureOpts struct {
	Tool                  string
	Endpoint              string
	Token                 string
	DeprecatedSplunkToken string
	HeaderName            string
	HeaderPrefix          string
	SplunkHost            string
	TenantID              string
	WorkspaceID           string
	AgentName             string
	Environment           string
	ClaudeTenantID        string
	ClaudeWorkspaceID     string
	ClaudeAgentName       string
	ClaudeEnvironment     string
	CodexTenantID         string
	CodexWorkspaceID      string
	CodexAgentName        string
	CodexEnvironment      string
}

type telemetryTarget struct {
	baseEndpoint             string
	traceEndpoint            string
	metricEndpoint           string
	logEndpoint              string
	logsEnabled              bool
	claudeLogBootstrapNeeded bool
	headerName               string
	headerValue              string
	warnings                 []string
}

const (
	codexManagedBeginMarker = "# BEGIN DEFENSECLAW OTEL CONFIG"
	codexManagedEndMarker   = "# END DEFENSECLAW OTEL CONFIG"
)

// otelEnvKeys is the set of keys the configure command manages in
// ~/.claude/settings.json → env. Unconfigure removes exactly these.
var otelEnvKeys = []string{
	"BETA_TRACING_ENDPOINT",
	"CLAUDE_CODE_ENABLE_TELEMETRY",
	"CLAUDE_CODE_ENHANCED_TELEMETRY_BETA",
	"ENABLE_BETA_TRACING_DETAILED",
	"ENABLE_ENHANCED_TELEMETRY_BETA",
	"OTEL_EXPORTER_OTLP_PROTOCOL",
	"OTEL_EXPORTER_OTLP_ENDPOINT",
	"OTEL_EXPORTER_OTLP_HEADERS",
	"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
	"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
	"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
	"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
	"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
	"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
	"OTEL_METRICS_EXPORTER",
	"OTEL_LOGS_EXPORTER",
	"OTEL_TRACES_EXPORTER",
	"OTEL_METRIC_EXPORT_INTERVAL",
	"OTEL_LOGS_EXPORT_INTERVAL",
	"OTEL_TRACES_EXPORT_INTERVAL",
	"OTEL_RESOURCE_ATTRIBUTES",
}

// Configure writes persistent OTEL configuration for Claude and/or Codex.
func Configure(opts ConfigureOpts) error {
	if err := normalizeConfigureOpts(&opts); err != nil {
		return err
	}
	if err := validateToolSpecificOverrides(opts); err != nil {
		return err
	}

	target, err := resolveTelemetryTarget(opts)
	if err != nil {
		return err
	}

	tool := normalizedTool(opts.Tool)
	switch tool {
	case ToolAll:
		claudeOpts := effectiveToolConfigureOpts(opts, ToolClaude)
		if err := configureClaude(claudeOpts, target); err != nil {
			return err
		}
		codexOpts := effectiveToolConfigureOpts(opts, ToolCodex)
		if err := configureCodex(codexOpts, target); err != nil {
			return err
		}
	case ToolClaude:
		if err := configureClaude(effectiveToolConfigureOpts(opts, ToolClaude), target); err != nil {
			return err
		}
	case ToolCodex:
		if err := configureCodex(effectiveToolConfigureOpts(opts, ToolCodex), target); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported tool %q: expected %q, %q, or %q", opts.Tool, ToolClaude, ToolCodex, ToolAll)
	}

	printConfigureSummary(tool, target)
	return nil
}

// Unconfigure removes OTEL configuration previously written by Configure.
func Unconfigure(tool string) error {
	switch normalizedTool(tool) {
	case ToolAll:
		if err := unconfigureClaude(); err != nil {
			return err
		}
		if err := unconfigureCodex(); err != nil {
			return err
		}
		return nil
	case ToolClaude:
		return unconfigureClaude()
	case ToolCodex:
		return unconfigureCodex()
	default:
		return fmt.Errorf("unsupported tool %q: expected %q, %q, or %q", tool, ToolClaude, ToolCodex, ToolAll)
	}
}

func normalizedTool(tool string) string {
	tool = strings.ToLower(strings.TrimSpace(tool))
	if tool == "" {
		return ToolAll
	}
	return tool
}

func normalizeConfigureOpts(opts *ConfigureOpts) error {
	token := strings.TrimSpace(opts.Token)
	deprecated := strings.TrimSpace(opts.DeprecatedSplunkToken)
	if token != "" && deprecated != "" && token != deprecated {
		return fmt.Errorf("received conflicting values for --token and deprecated --splunk-token")
	}
	if token == "" {
		opts.Token = deprecated
	}
	return nil
}

func validateToolSpecificOverrides(opts ConfigureOpts) error {
	switch normalizedTool(opts.Tool) {
	case ToolClaude:
		if hasToolSpecificOverrides(opts, ToolCodex) {
			return fmt.Errorf("received Codex-specific override flags with --tool %q", ToolClaude)
		}
	case ToolCodex:
		if hasToolSpecificOverrides(opts, ToolClaude) {
			return fmt.Errorf("received Claude-specific override flags with --tool %q", ToolCodex)
		}
	}
	return nil
}

func hasToolSpecificOverrides(opts ConfigureOpts, tool string) bool {
	switch tool {
	case ToolClaude:
		return strings.TrimSpace(opts.ClaudeTenantID) != "" ||
			strings.TrimSpace(opts.ClaudeWorkspaceID) != "" ||
			strings.TrimSpace(opts.ClaudeAgentName) != "" ||
			strings.TrimSpace(opts.ClaudeEnvironment) != ""
	case ToolCodex:
		return strings.TrimSpace(opts.CodexTenantID) != "" ||
			strings.TrimSpace(opts.CodexWorkspaceID) != "" ||
			strings.TrimSpace(opts.CodexAgentName) != "" ||
			strings.TrimSpace(opts.CodexEnvironment) != ""
	default:
		return false
	}
}

func effectiveToolConfigureOpts(opts ConfigureOpts, tool string) ConfigureOpts {
	effective := opts
	effective.Tool = tool
	switch tool {
	case ToolClaude:
		effective.TenantID = firstNonEmpty(opts.ClaudeTenantID, opts.TenantID)
		effective.WorkspaceID = firstNonEmpty(opts.ClaudeWorkspaceID, opts.WorkspaceID)
		effective.AgentName = firstNonEmpty(opts.ClaudeAgentName, opts.AgentName)
		effective.Environment = firstNonEmpty(opts.ClaudeEnvironment, opts.Environment)
	case ToolCodex:
		effective.TenantID = firstNonEmpty(opts.CodexTenantID, opts.TenantID)
		effective.WorkspaceID = firstNonEmpty(opts.CodexWorkspaceID, opts.WorkspaceID)
		effective.AgentName = firstNonEmpty(opts.CodexAgentName, opts.AgentName)
		effective.Environment = firstNonEmpty(opts.CodexEnvironment, opts.Environment)
	}
	return effective
}

func resolveTelemetryTarget(opts ConfigureOpts) (telemetryTarget, error) {
	if strings.TrimSpace(opts.Endpoint) != "" {
		return buildDirectTarget(opts)
	}
	if strings.TrimSpace(opts.SplunkHost) != "" {
		return buildDirectSplunkTarget(opts)
	}
	return telemetryTarget{}, fmt.Errorf("configure requires --endpoint or --splunk-host")
}

func buildDirectTarget(opts ConfigureOpts) (telemetryTarget, error) {
	base, warning, err := normalizeOTLPBaseEndpoint(opts.Endpoint)
	if err != nil {
		return telemetryTarget{}, err
	}
	headerName, headerValue := buildAuthHeader(opts, false)
	target := telemetryTarget{
		baseEndpoint:   base,
		traceEndpoint:  base + "/v1/traces",
		metricEndpoint: base + "/v1/metrics",
		logEndpoint:    base + "/v1/logs",
		logsEnabled:    true,
		headerName:     headerName,
		headerValue:    headerValue,
	}
	if warning != "" {
		target.warnings = append(target.warnings, warning)
	}
	return target, nil
}

func buildDirectSplunkTarget(opts ConfigureOpts) (telemetryTarget, error) {
	ingestHost, warning, err := deriveIngestHost(opts.SplunkHost)
	if err != nil {
		return telemetryTarget{}, err
	}
	headerName, headerValue := buildAuthHeader(opts, true)
	target := telemetryTarget{
		baseEndpoint:             "https://" + ingestHost,
		traceEndpoint:            "https://" + ingestHost + "/v2/trace/otlp",
		metricEndpoint:           "https://" + ingestHost + "/v2/datapoint/otlp",
		logEndpoint:              "https://" + ingestHost + "/v1/logs",
		logsEnabled:              false,
		claudeLogBootstrapNeeded: true,
		headerName:               headerName,
		headerValue:              headerValue,
		warnings: []string{
			"Splunk direct mode configures traces and metrics directly; direct OTLP logs remain unsupported without a collector or relay",
		},
	}
	if warning != "" {
		target.warnings = append(target.warnings, warning)
	}
	return target, nil
}

func normalizeOTLPBaseEndpoint(raw string) (string, string, error) {
	endpoint := strings.TrimSpace(raw)
	endpoint = strings.TrimRight(endpoint, "/")
	if endpoint == "" {
		return "", "", fmt.Errorf("endpoint must not be empty")
	}
	for _, suffix := range []string{"/v1/traces", "/v1/metrics", "/v1/logs"} {
		if strings.HasSuffix(endpoint, suffix) {
			base := strings.TrimSuffix(endpoint, suffix)
			return base, fmt.Sprintf("trimmed %q from endpoint and used base %q for all signals", suffix, base), nil
		}
	}
	return endpoint, "", nil
}

func buildAuthHeader(opts ConfigureOpts, splunkDirect bool) (string, string) {
	token := strings.TrimSpace(firstNonEmpty(
		opts.Token,
		os.Getenv("OTLP_AUTH_TOKEN"),
		os.Getenv("SPLUNK_OBSERVABILITY_TOKEN"),
		os.Getenv("SPLUNK_ACCESS_TOKEN"),
	))
	if token == "" {
		return "", ""
	}

	headerName := strings.TrimSpace(opts.HeaderName)
	headerPrefix := opts.HeaderPrefix
	if headerName == "" {
		if splunkDirect {
			headerName = "X-SF-Token"
		} else {
			headerName = "Authorization"
			if headerPrefix == "" {
				headerPrefix = "Bearer "
			}
		}
	}
	if headerPrefix == "" {
		return headerName, token
	}
	return headerName, headerPrefix + token
}

func printConfigureSummary(tool string, target telemetryTarget) {
	switch tool {
	case ToolAll:
		fmt.Fprintf(os.Stderr, "[configure] updated Claude Code and Codex for direct telemetry export\n")
	case ToolClaude:
		fmt.Fprintf(os.Stderr, "[configure] updated Claude Code for direct telemetry export\n")
	case ToolCodex:
		fmt.Fprintf(os.Stderr, "[configure] updated Codex for direct telemetry export\n")
	}
	fmt.Fprintf(os.Stderr, "[configure] traces  → %s\n", target.traceEndpoint)
	fmt.Fprintf(os.Stderr, "[configure] metrics → %s\n", target.metricEndpoint)
	if target.logsEnabled {
		fmt.Fprintf(os.Stderr, "[configure] logs    → %s\n", target.logEndpoint)
	}

	for _, warning := range target.warnings {
		fmt.Fprintf(os.Stderr, "[configure] warning: %s\n", warning)
	}
}

// ---------------------------------------------------------------------------
// Claude Code — ~/.claude/settings.json
// ---------------------------------------------------------------------------

func claudeSettingsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

func configureClaude(opts ConfigureOpts, target telemetryTarget) error {
	path, err := claudeSettingsPath()
	if err != nil {
		return err
	}
	settings, err := readJSONFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if settings == nil {
		settings = map[string]interface{}{}
	}

	env, _ := settings["env"].(map[string]interface{})
	if env == nil {
		env = map[string]interface{}{}
	}
	if shouldUseClaudeBedrockForConfig(env) {
		env["CLAUDE_CODE_USE_BEDROCK"] = "1"
	}

	env["CLAUDE_CODE_ENABLE_TELEMETRY"] = "1"
	env["CLAUDE_CODE_ENHANCED_TELEMETRY_BETA"] = "1"
	delete(env, "BETA_TRACING_ENDPOINT")
	delete(env, "ENABLE_BETA_TRACING_DETAILED")
	delete(env, "ENABLE_ENHANCED_TELEMETRY_BETA")
	env["OTEL_EXPORTER_OTLP_PROTOCOL"] = "http/protobuf"
	if target.baseEndpoint != "" {
		env["OTEL_EXPORTER_OTLP_ENDPOINT"] = target.baseEndpoint
	} else {
		delete(env, "OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	if target.headerName != "" && target.headerValue != "" {
		env["OTEL_EXPORTER_OTLP_HEADERS"] = fmt.Sprintf("%s=%s", target.headerName, target.headerValue)
	} else {
		delete(env, "OTEL_EXPORTER_OTLP_HEADERS")
	}

	env["OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"] = "http/protobuf"
	env["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] = target.traceEndpoint
	env["OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"] = "http/protobuf"
	env["OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"] = target.metricEndpoint

	if target.logsEnabled || target.claudeLogBootstrapNeeded {
		env["OTEL_EXPORTER_OTLP_LOGS_PROTOCOL"] = "http/protobuf"
		env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] = target.logEndpoint
		env["OTEL_LOGS_EXPORTER"] = "otlp"
		env["OTEL_LOGS_EXPORT_INTERVAL"] = "1000"
	} else {
		delete(env, "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL")
		delete(env, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
		delete(env, "OTEL_LOGS_EXPORTER")
		delete(env, "OTEL_LOGS_EXPORT_INTERVAL")
	}

	env["OTEL_METRICS_EXPORTER"] = "otlp"
	env["OTEL_TRACES_EXPORTER"] = "otlp"
	env["OTEL_METRIC_EXPORT_INTERVAL"] = "1000"
	env["OTEL_TRACES_EXPORT_INTERVAL"] = "1000"
	env["OTEL_RESOURCE_ATTRIBUTES"] = buildConfigResourceAttrs(env, opts)

	settings["env"] = env
	if err := writeJSONFile(path, settings); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "[configure] wrote Claude Code OTEL config to %s\n", path)
	return nil
}

func unconfigureClaude() error {
	path, err := claudeSettingsPath()
	if err != nil {
		return err
	}
	settings, err := readJSONFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[unconfigure] %s does not exist, nothing to do\n", path)
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	env, _ := settings["env"].(map[string]interface{})
	if env == nil {
		fmt.Fprintf(os.Stderr, "[unconfigure] no env section in %s, nothing to do\n", path)
		return nil
	}
	removed := 0
	for _, key := range otelEnvKeys {
		if _, ok := env[key]; ok {
			delete(env, key)
			removed++
		}
	}
	if removed == 0 {
		fmt.Fprintf(os.Stderr, "[unconfigure] no OTEL keys found in %s, nothing to do\n", path)
		return nil
	}
	settings["env"] = env
	if err := writeJSONFile(path, settings); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "[unconfigure] removed %d OTEL keys from %s\n", removed, path)
	return nil
}

// ---------------------------------------------------------------------------
// Codex CLI — ~/.codex/config.toml
// ---------------------------------------------------------------------------

func codexConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".codex", "config.toml"), nil
}

func configureCodex(opts ConfigureOpts, target telemetryTarget) error {
	path, err := codexConfigPath()
	if err != nil {
		return err
	}

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}

	cleaned := stripManagedTOMLBlock(string(existing), codexManagedBeginMarker, codexManagedEndMarker)
	if hasTOMLSection(cleaned, "otel") {
		return fmt.Errorf("found unmanaged [otel] section in %s; merge manually before running configure", path)
	}

	var b strings.Builder
	b.WriteString(strings.TrimRight(cleaned, "\n"))
	if b.Len() > 0 {
		b.WriteString("\n\n")
	}
	b.WriteString(codexManagedBeginMarker + "\n")
	b.WriteString("[otel]\n")
	if target.logsEnabled {
		fmt.Fprintf(&b, "exporter = { \"otlp-http\" = { endpoint = %q, protocol = \"binary\"%s } }\n",
			target.logEndpoint, formatTOMLHeaders(target))
	} else {
		b.WriteString("exporter = \"none\"\n")
	}
	fmt.Fprintf(&b, "metrics_exporter = { \"otlp-http\" = { endpoint = %q, protocol = \"binary\"%s } }\n",
		target.metricEndpoint, formatTOMLHeaders(target))
	fmt.Fprintf(&b, "trace_exporter = { \"otlp-http\" = { endpoint = %q, protocol = \"binary\"%s } }\n",
		target.traceEndpoint, formatTOMLHeaders(target))
	fmt.Fprintf(&b, "environment = %q\n", opts.Environment)
	b.WriteString(codexManagedEndMarker + "\n")

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "[configure] wrote Codex OTEL config to %s\n", path)
	if hasConfigTags(opts) {
		fmt.Fprintf(os.Stderr, "[configure] warning: Codex config.toml has no documented key for arbitrary OTEL resource attributes; tenant/workspace/agent tags are not persisted in direct mode\n")
	}
	if strings.TrimSpace(opts.Environment) != "" {
		fmt.Fprintf(os.Stderr, "[configure] warning: Codex environment tagging is best-effort in direct mode; verify trace dimensions in your backend\n")
	}
	return nil
}

func unconfigureCodex() error {
	path, err := codexConfigPath()
	if err != nil {
		return err
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[unconfigure] %s does not exist, nothing to do\n", path)
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	cleaned := stripManagedTOMLBlock(string(existing), codexManagedBeginMarker, codexManagedEndMarker)
	cleaned = strings.TrimRight(cleaned, "\n")
	if cleaned != "" {
		cleaned += "\n"
	}
	if err := os.WriteFile(path, []byte(cleaned), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "[unconfigure] removed OTEL section from %s\n", path)
	return nil
}

func formatTOMLHeaders(target telemetryTarget) string {
	if target.headerName == "" || target.headerValue == "" {
		return ""
	}
	return fmt.Sprintf(", headers = { %q = %q }", target.headerName, target.headerValue)
}

func hasConfigTags(opts ConfigureOpts) bool {
	return strings.TrimSpace(opts.TenantID) != "" ||
		strings.TrimSpace(opts.WorkspaceID) != "" ||
		strings.TrimSpace(opts.AgentName) != ""
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildConfigResourceAttrs(env map[string]interface{}, opts ConfigureOpts) string {
	existing, _ := env["OTEL_RESOURCE_ATTRIBUTES"].(string)
	extra := map[string]string{
		"tenant_id":              opts.TenantID,
		"workspace_id":           opts.WorkspaceID,
		"agent_name":             opts.AgentName,
		"deployment.environment": opts.Environment,
		"wrapped_cli":            opts.Tool,
	}
	return mergeResourceAttributes(existing, extra)
}

func readJSONFile(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func writeJSONFile(path string, data map[string]interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0o644)
}

func hasTOMLSection(text, section string) bool {
	header := "[" + section + "]"
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == header {
			return true
		}
	}
	return false
}

// stripManagedTOMLBlock removes a marker-delimited block from TOML text.
func stripManagedTOMLBlock(text, beginMarker, endMarker string) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == beginMarker:
			inBlock = true
			continue
		case inBlock && trimmed == endMarker:
			inBlock = false
			continue
		case inBlock:
			continue
		default:
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
