package agentotel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// RunOpts holds options for one-shot Claude/Codex launches with direct OTEL config.
type RunOpts struct {
	ConfigureOpts
	Binary string
}

type runSpec struct {
	binary string
	args   []string
	env    []string
}

// Run launches Claude Code or Codex with OTEL configuration injected for this
// process only. It does not persist changes into the user's real desktop
// settings files.
func Run(ctx context.Context, opts RunOpts, toolArgs []string) error {
	if err := normalizeConfigureOpts(&opts.ConfigureOpts); err != nil {
		return err
	}
	if err := validateToolSpecificOverrides(opts.ConfigureOpts); err != nil {
		return err
	}

	tool := normalizedTool(opts.Tool)
	if tool != ToolClaude && tool != ToolCodex {
		return fmt.Errorf("run requires --tool %q or %q", ToolClaude, ToolCodex)
	}

	effective := effectiveToolConfigureOpts(opts.ConfigureOpts, tool)
	target, err := resolveTelemetryTarget(effective)
	if err != nil {
		return err
	}

	spec, err := buildRunSpec(effective, strings.TrimSpace(opts.Binary), toolArgs, target)
	if err != nil {
		return err
	}
	printRunSummary(spec, target, effective)

	cmd := exec.CommandContext(ctx, spec.binary, spec.args...)
	cmd.Env = spec.env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func buildRunSpec(opts ConfigureOpts, binary string, toolArgs []string, target telemetryTarget) (runSpec, error) {
	if binary == "" {
		binary = opts.Tool
	}

	switch normalizedTool(opts.Tool) {
	case ToolClaude:
		return buildClaudeRunSpec(opts, binary, toolArgs, target)
	case ToolCodex:
		return buildCodexRunSpec(opts, binary, toolArgs, target)
	default:
		return runSpec{}, fmt.Errorf("unsupported tool %q", opts.Tool)
	}
}

func buildClaudeRunSpec(opts ConfigureOpts, binary string, toolArgs []string, target telemetryTarget) (runSpec, error) {
	env := envSliceToMap(os.Environ())
	settingsEnv, err := currentClaudeSettingsEnv()
	if err != nil && !os.IsNotExist(err) {
		return runSpec{}, err
	}
	claudeSettingsEnv := sanitizedClaudeRunSettingsEnv(settingsEnv)
	if shouldUseClaudeBedrockForConfig(settingsEnv) {
		claudeSettingsEnv["CLAUDE_CODE_USE_BEDROCK"] = "1"
	}

	claudeSettingsEnv["CLAUDE_CODE_ENABLE_TELEMETRY"] = "1"
	claudeSettingsEnv["CLAUDE_CODE_ENHANCED_TELEMETRY_BETA"] = "1"
	claudeSettingsEnv["ENABLE_ENHANCED_TELEMETRY_BETA"] = "1"
	claudeSettingsEnv["OTEL_EXPORTER_OTLP_PROTOCOL"] = "http/protobuf"
	if target.baseEndpoint != "" {
		claudeSettingsEnv["OTEL_EXPORTER_OTLP_ENDPOINT"] = target.baseEndpoint
	} else {
		delete(claudeSettingsEnv, "OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	if target.headerName != "" && target.headerValue != "" {
		claudeSettingsEnv["OTEL_EXPORTER_OTLP_HEADERS"] = fmt.Sprintf("%s=%s", target.headerName, target.headerValue)
		claudeSettingsEnv["OTEL_EXPORTER_OTLP_TRACES_HEADERS"] = fmt.Sprintf("%s=%s", target.headerName, target.headerValue)
		claudeSettingsEnv["OTEL_EXPORTER_OTLP_METRICS_HEADERS"] = fmt.Sprintf("%s=%s", target.headerName, target.headerValue)
	} else {
		delete(claudeSettingsEnv, "OTEL_EXPORTER_OTLP_HEADERS")
		delete(claudeSettingsEnv, "OTEL_EXPORTER_OTLP_TRACES_HEADERS")
		delete(claudeSettingsEnv, "OTEL_EXPORTER_OTLP_METRICS_HEADERS")
	}

	claudeSettingsEnv["OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"] = "http/protobuf"
	claudeSettingsEnv["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] = target.traceEndpoint
	claudeSettingsEnv["OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"] = "http/protobuf"
	claudeSettingsEnv["OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"] = target.metricEndpoint
	if target.logsEnabled || target.logBootstrapNeeded {
		claudeSettingsEnv["OTEL_EXPORTER_OTLP_LOGS_PROTOCOL"] = "http/protobuf"
		claudeSettingsEnv["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] = target.logEndpoint
		if target.headerName != "" && target.headerValue != "" {
			claudeSettingsEnv["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] = fmt.Sprintf("%s=%s", target.headerName, target.headerValue)
		} else {
			delete(claudeSettingsEnv, "OTEL_EXPORTER_OTLP_LOGS_HEADERS")
		}
		claudeSettingsEnv["OTEL_LOGS_EXPORTER"] = "otlp"
		claudeSettingsEnv["OTEL_LOGS_EXPORT_INTERVAL"] = "1000"
	} else {
		delete(claudeSettingsEnv, "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL")
		delete(claudeSettingsEnv, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
		delete(claudeSettingsEnv, "OTEL_EXPORTER_OTLP_LOGS_HEADERS")
		delete(claudeSettingsEnv, "OTEL_LOGS_EXPORTER")
		delete(claudeSettingsEnv, "OTEL_LOGS_EXPORT_INTERVAL")
	}
	claudeSettingsEnv["OTEL_METRICS_EXPORTER"] = "otlp"
	claudeSettingsEnv["OTEL_TRACES_EXPORTER"] = "otlp"
	claudeSettingsEnv["OTEL_METRIC_EXPORT_INTERVAL"] = "1000"
	claudeSettingsEnv["OTEL_TRACES_EXPORT_INTERVAL"] = "1000"
	claudeSettingsEnv["OTEL_LOG_TOOL_DETAILS"] = "1"
	claudeSettingsEnv["OTEL_METRICS_INCLUDE_VERSION"] = "true"
	claudeSettingsEnv["OTEL_RESOURCE_ATTRIBUTES"] = buildRuntimeResourceAttrs(stringValue(settingsEnv["OTEL_RESOURCE_ATTRIBUTES"]), opts)
	delete(claudeSettingsEnv, "BETA_TRACING_ENDPOINT")
	delete(claudeSettingsEnv, "ENABLE_BETA_TRACING_DETAILED")
	delete(env, "BETA_TRACING_ENDPOINT")
	delete(env, "ENABLE_BETA_TRACING_DETAILED")
	delete(env, "ENABLE_ENHANCED_TELEMETRY_BETA")

	for _, key := range otelEnvKeys {
		delete(env, key)
	}
	delete(env, "BETA_TRACING_ENDPOINT")
	delete(env, "ENABLE_BETA_TRACING_DETAILED")
	delete(env, "ENABLE_ENHANCED_TELEMETRY_BETA")
	for key, value := range claudeSettingsEnv {
		env[key] = value
	}

	return runSpec{
		binary: binary,
		args:   append([]string(nil), toolArgs...),
		env:    envMapToSlice(env),
	}, nil
}

func buildCodexRunSpec(opts ConfigureOpts, binary string, toolArgs []string, target telemetryTarget) (runSpec, error) {
	env := envSliceToMap(os.Environ())
	for _, key := range otelEnvKeys {
		delete(env, key)
	}
	delete(env, "OTEL_EXPORTER_OTLP_TRACES_HEADERS")
	delete(env, "OTEL_EXPORTER_OTLP_METRICS_HEADERS")
	delete(env, "OTEL_EXPORTER_OTLP_LOGS_HEADERS")
	env["OTEL_RESOURCE_ATTRIBUTES"] = buildRuntimeResourceAttrs(env["OTEL_RESOURCE_ATTRIBUTES"], opts)
	if target.baseEndpoint != "" {
		env["OTEL_EXPORTER_OTLP_ENDPOINT"] = target.baseEndpoint
	} else {
		delete(env, "OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	env["OTEL_EXPORTER_OTLP_PROTOCOL"] = "http/protobuf"
	if target.headerName != "" && target.headerValue != "" {
		env["OTEL_EXPORTER_OTLP_HEADERS"] = fmt.Sprintf("%s=%s", target.headerName, target.headerValue)
	} else {
		delete(env, "OTEL_EXPORTER_OTLP_HEADERS")
	}
	env["OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"] = "http/protobuf"
	env["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] = target.traceEndpoint
	if target.headerName != "" && target.headerValue != "" {
		env["OTEL_EXPORTER_OTLP_TRACES_HEADERS"] = fmt.Sprintf("%s=%s", target.headerName, target.headerValue)
	} else {
		delete(env, "OTEL_EXPORTER_OTLP_TRACES_HEADERS")
	}
	env["OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"] = "http/protobuf"
	env["OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"] = target.metricEndpoint
	if target.headerName != "" && target.headerValue != "" {
		env["OTEL_EXPORTER_OTLP_METRICS_HEADERS"] = fmt.Sprintf("%s=%s", target.headerName, target.headerValue)
	} else {
		delete(env, "OTEL_EXPORTER_OTLP_METRICS_HEADERS")
	}
	env["OTEL_METRICS_EXPORTER"] = "otlp"
	env["OTEL_TRACES_EXPORTER"] = "otlp"
	env["OTEL_METRIC_EXPORT_INTERVAL"] = "1000"
	env["OTEL_TRACES_EXPORT_INTERVAL"] = "1000"
	if target.logsEnabled {
		env["OTEL_EXPORTER_OTLP_LOGS_PROTOCOL"] = "http/protobuf"
		env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] = target.logEndpoint
		if target.headerName != "" && target.headerValue != "" {
			env["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] = fmt.Sprintf("%s=%s", target.headerName, target.headerValue)
		} else {
			delete(env, "OTEL_EXPORTER_OTLP_LOGS_HEADERS")
		}
		env["OTEL_LOGS_EXPORTER"] = "otlp"
		env["OTEL_LOGS_EXPORT_INTERVAL"] = "1000"
	} else {
		delete(env, "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL")
		delete(env, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
		delete(env, "OTEL_EXPORTER_OTLP_LOGS_HEADERS")
		delete(env, "OTEL_LOGS_EXPORTER")
		delete(env, "OTEL_LOGS_EXPORT_INTERVAL")
	}

	overrides := make([]string, 0, 8)
	if strings.TrimSpace(opts.Environment) != "" {
		overrides = append(overrides, "-c", fmt.Sprintf("otel.environment=%q", opts.Environment))
	}
	if target.logsEnabled {
		overrides = append(overrides, "-c", "otel.exporter="+buildCodexExporterValue(target.logEndpoint, target))
	}
	overrides = append(overrides, "-c", "otel.metrics_exporter="+buildCodexExporterValue(target.metricEndpoint, target))
	overrides = append(overrides, "-c", "otel.trace_exporter="+buildCodexExporterValue(target.traceEndpoint, target))

	args := make([]string, 0, len(toolArgs)+len(overrides))
	if len(toolArgs) > 0 && !strings.HasPrefix(toolArgs[0], "-") {
		args = append(args, toolArgs[0])
		args = append(args, overrides...)
		args = append(args, toolArgs[1:]...)
	} else {
		args = append(args, overrides...)
		args = append(args, toolArgs...)
	}

	return runSpec{
		binary: binary,
		args:   args,
		env:    envMapToSlice(env),
	}, nil
}

func sanitizedClaudeRunSettingsEnv(env map[string]interface{}) map[string]string {
	out := make(map[string]string, len(env))
	for key, raw := range env {
		s, ok := raw.(string)
		if !ok {
			continue
		}
		if managedClaudeTelemetryKey(key) {
			continue
		}
		out[key] = s
	}
	return out
}

func managedClaudeTelemetryKey(key string) bool {
	for _, managed := range otelEnvKeys {
		if managed == key {
			return true
		}
	}
	switch key {
	case "BETA_TRACING_ENDPOINT", "ENABLE_BETA_TRACING_DETAILED", "ENABLE_ENHANCED_TELEMETRY_BETA":
		return true
	default:
		return false
	}
}

func stringValue(v interface{}) string {
	s, _ := v.(string)
	return s
}

func currentClaudeSettingsEnv() (map[string]interface{}, error) {
	path, err := claudeSettingsPath()
	if err != nil {
		return nil, err
	}
	settings, err := readJSONFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]interface{}{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	env, _ := settings["env"].(map[string]interface{})
	if env == nil {
		return map[string]interface{}{}, nil
	}
	return env, nil
}

func buildRuntimeResourceAttrs(existing string, opts ConfigureOpts) string {
	extra := map[string]string{
		"tenant_id":              opts.TenantID,
		"workspace_id":           opts.WorkspaceID,
		"agent_name":             opts.AgentName,
		"deployment.environment": opts.Environment,
		"wrapped_cli":            opts.Tool,
	}
	return mergeResourceAttributes(existing, extra)
}

func buildCodexExporterValue(endpoint string, target telemetryTarget) string {
	if target.headerName == "" || target.headerValue == "" {
		return fmt.Sprintf(`{ "otlp-http" = { endpoint = %q, protocol = "binary" } }`, endpoint)
	}
	return fmt.Sprintf(`{ "otlp-http" = { endpoint = %q, protocol = "binary", headers = { %q = %q } } }`,
		endpoint, target.headerName, target.headerValue)
}

func envSliceToMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		out[key] = value
	}
	return out
}

func envMapToSlice(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+env[key])
	}
	return out
}

func printRunSummary(spec runSpec, target telemetryTarget, opts ConfigureOpts) {
	fmt.Fprintf(os.Stderr, "[run] launching %s via %s\n", opts.Tool, spec.binary)
	fmt.Fprintf(os.Stderr, "[run] traces  → %s\n", target.traceEndpoint)
	fmt.Fprintf(os.Stderr, "[run] metrics → %s\n", target.metricEndpoint)
	if target.logsEnabled {
		fmt.Fprintf(os.Stderr, "[run] logs    → %s\n", target.logEndpoint)
	}
	for _, warning := range target.warnings {
		if normalizedTool(opts.Tool) == ToolCodex && !target.logsEnabled && strings.Contains(warning, "OTLP logs") {
			continue
		}
		fmt.Fprintf(os.Stderr, "[run] warning: %s\n", warning)
	}
	if normalizedTool(opts.Tool) == ToolCodex && hasConfigTags(opts) {
		fmt.Fprintf(os.Stderr, "[run] warning: Codex resource tags are best-effort in one-shot mode; verify tenant/workspace/agent dimensions in your backend\n")
	}
}
