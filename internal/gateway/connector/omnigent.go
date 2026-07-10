// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const (
	omnigentPolicyModuleName = "defenseclaw_omnigent_policy"
	omnigentPolicyHandler    = omnigentPolicyModuleName + ".defenseclaw_policy"
	omnigentPolicyConfigKey  = "defenseclaw_guardrail"
)

// Test-only path overrides. Production resolves OmniGent's user config and
// the site-packages directory belonging to its installed CLI environment.
var (
	OmnigentConfigPathOverride       string
	OmnigentSitePackagesPathOverride string
)

// OmnigentConnector integrates through OmniGent's documented custom Python
// policy API. Unlike command-hook agents, OmniGent invokes the bridge callable
// in-process for every policy phase; the callable POSTs a normalized event to
// the unified DefenseClaw hook endpoint and translates the verdict back to
// ALLOW, ASK, or DENY.
type OmnigentConnector struct {
	gatewayToken string
	masterKey    string
	loopbackWarn sync.Once
}

func NewOmnigentConnector() *OmnigentConnector { return &OmnigentConnector{} }

func (c *OmnigentConnector) Name() string { return "omnigent" }
func (c *OmnigentConnector) Description() string {
	return "OmniGent custom policy bridge with ALLOW/ASK/DENY enforcement"
}
func (c *OmnigentConnector) HookAPIPath() string                    { return "/api/v1/omnigent/hook" }
func (c *OmnigentConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (c *OmnigentConnector) SubprocessPolicy() SubprocessPolicy     { return SubprocessNone }

func (c *OmnigentConnector) HookCapabilities(opts SetupOpts) HookCapability {
	return c.Capabilities(opts).Hooks
}

func (c *OmnigentConnector) HookProfile(opts SetupOpts) HookProfile {
	return ApplyHookContract(HookProfile{
		Name:                c.Name(),
		Capabilities:        c.HookCapabilities(opts),
		SupportsTraceparent: true,
		NativeOTLP:          omnigentNativeOTLPSpec(opts),
		MapVerdict:          hookOnlyProfileMapVerdict,
		Respond:             hookOnlyProfileRespond,
	}, opts)
}

func omnigentNativeOTLPSpec(opts SetupOpts) *NativeOTLPSpec {
	headers := map[string]string{
		"x-defenseclaw-source": "omnigent",
		"x-defenseclaw-client": "omnigent-otel/1.0",
	}
	if opts.APIToken != "" {
		headers["x-defenseclaw-token"] = opts.APIToken
	}
	return &NativeOTLPSpec{
		Kind:               NativeOTLPEnvBlock,
		Endpoint:           "http://" + strings.TrimSpace(opts.APIAddr),
		Protocol:           "http/protobuf",
		Headers:            headers,
		PerSignal:          true,
		ServiceName:        "omnigent",
		ResourceAttributes: map[string]string{"service.name": "omnigent", "defenseclaw.connector": "omnigent"},
		ExtraEnv:           map[string]string{"OMNIGENT_OTEL_CAPTURE_CONTENT": "false"},
	}
}

func (c *OmnigentConnector) Capabilities(opts SetupOpts) ConnectorCapabilities {
	configPath := omnigentConfigPath()
	unsupported := unsupportedSurface("")
	return ConnectorCapabilities{
		LLMTrafficMode: LLMTrafficModeHooksOnly,
		Hooks: HookCapability{
			CanBlock:           true,
			CanAskNative:       true,
			AskEvents:          []string{"UserPromptSubmit", "PreToolUse", "BeforeModel"},
			BlockEvents:        []string{"UserPromptSubmit", "PreToolUse", "PostToolUse", "AfterAgentResponse", "BeforeModel", "AfterModel"},
			SupportsFailClosed: true,
			Scope:              "user",
			ConfigPath:         configPath,
		},
		MCP:     unsupportedSurface("OmniGent MCP configuration is managed by OmniGent and is not modified by this connector."),
		Skills:  unsupported,
		Rules:   unsupported,
		Plugins: unsupported,
		Agents:  unsupportedSurface("OmniGent agent bundles are not modified by this connector."),
		CodeGuard: CodeGuardCapability{
			Supported: false, OptInOnly: true, Idempotent: true, ConflictSafe: true,
		},
		Telemetry: TelemetryCapability{
			NativeOTLP:    true,
			NativeSignals: []string{"logs", "metrics", "traces"},
			HookSignals:   []string{"logs", "metrics", "traces"},
			ConfigPaths:   []string{configPath},
			Env: []EnvRequirement{
				{Name: "OTEL_EXPORTER_OTLP_ENDPOINT", Scope: EnvScopeProcess, Required: false, Description: "Point OmniGent native OTLP at the DefenseClaw gateway."},
				{Name: "OTEL_EXPORTER_OTLP_PROTOCOL", Scope: EnvScopeProcess, Required: false, Description: "Set to http/protobuf for DefenseClaw OTLP ingestion."},
				{Name: "OTEL_EXPORTER_OTLP_HEADERS", Scope: EnvScopeProcess, Required: false, Description: "Carry x-defenseclaw-token, x-defenseclaw-source, and x-defenseclaw-client headers for native OTLP authentication and attribution."},
				{Name: "OTEL_LOGS_EXPORTER", Scope: EnvScopeProcess, Required: false, Description: "Set to otlp to enable OmniGent native log export."},
				{Name: "OTEL_METRICS_EXPORTER", Scope: EnvScopeProcess, Required: false, Description: "Set to otlp to enable OmniGent native metric export."},
				{Name: "OTEL_TRACES_EXPORTER", Scope: EnvScopeProcess, Required: false, Description: "Set to otlp to enable native traces when OmniGent is installed with its tracing extra."},
			},
			AuthMode:         "header-token",
			EndpointTemplate: "http://" + strings.TrimSpace(opts.APIAddr),
			SourceModes:      []string{"native", "hook"},
			Notes: []string{
				"Custom policy evaluations synthesize hook logs, metrics, and traces.",
				"OmniGent exports native logs and metrics with its standard OpenTelemetry dependencies; native traces require OmniGent's optional tracing extra.",
				"Native OTLP is inactive until the OmniGent launch process exports the required variables; DefenseClaw does not mutate shell startup files.",
			},
		},
	}
}

func (c *OmnigentConnector) Setup(ctx context.Context, opts SetupOpts) error {
	sitePackages, err := omnigentSitePackages(ctx)
	if err != nil {
		return err
	}
	configPath := omnigentConfigPath()
	modulePath := omnigentPolicyModulePath(opts)
	pthPath := filepath.Join(sitePackages, "defenseclaw_omnigent.pth")

	managedPaths := []struct {
		logical string
		path    string
	}{
		{logical: "config", path: configPath},
		{logical: "module", path: modulePath},
		{logical: "pth", path: pthPath},
	}
	snapshots := make([]omnigentFileSnapshot, 0, len(managedPaths)*2)
	for _, managed := range managedPaths {
		backupPath := managedFileBackupPath(opts.DataDir, c.Name(), managed.logical)
		snapshotPaths := []string{managed.path, backupPath}
		backup, backupErr := loadManagedFileBackupPath(backupPath)
		if backupErr == nil && strings.TrimSpace(backup.Path) != "" && filepath.Clean(backup.Path) != filepath.Clean(managed.path) {
			snapshotPaths = append(snapshotPaths, backup.Path)
		} else if backupErr != nil && !os.IsNotExist(backupErr) {
			return fmt.Errorf("omnigent read %s backup: %w", managed.logical, backupErr)
		}
		for _, path := range snapshotPaths {
			snapshot, snapshotErr := captureOmnigentFileSnapshot(path)
			if snapshotErr != nil {
				return fmt.Errorf("omnigent snapshot setup state: %w", snapshotErr)
			}
			snapshots = append(snapshots, snapshot)
		}
	}
	rollback := func(cause error) error {
		rollbackErrs := []error{cause}
		for i := len(snapshots) - 1; i >= 0; i-- {
			if err := restoreOmnigentFileSnapshot(snapshots[i]); err != nil {
				rollbackErrs = append(rollbackErrs, err)
			}
		}
		return errors.Join(rollbackErrs...)
	}
	for _, managed := range managedPaths {
		logical, path := managed.logical, managed.path
		if err := prepareOmnigentManagedBackup(opts.DataDir, c.Name(), logical, path); err != nil {
			return rollback(fmt.Errorf("omnigent capture %s backup: %w", logical, err))
		}
	}

	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		return rollback(fmt.Errorf("omnigent read policy template: %w", err))
	}
	failMode := normalizeHookFailMode(opts.HookFailMode)
	rendered := renderOmnigentPolicy(string(templateBytes), opts.APIAddr, opts.APIToken, failMode)
	if err := atomicWriteFile(modulePath, []byte(rendered), 0o600); err != nil {
		return rollback(fmt.Errorf("omnigent write policy module: %w", err))
	}
	if err := updateManagedFileBackupPostHash(opts.DataDir, c.Name(), "module", modulePath); err != nil {
		return rollback(fmt.Errorf("omnigent update module backup: %w", err))
	}
	if err := atomicWriteFile(pthPath, []byte(filepath.Dir(modulePath)+"\n"), 0o600); err != nil {
		return rollback(fmt.Errorf("omnigent write import path in OmniGent's Python environment (use an isolated, writable environment): %w", err))
	}
	if err := updateManagedFileBackupPostHash(opts.DataDir, c.Name(), "pth", pthPath); err != nil {
		return rollback(fmt.Errorf("omnigent update import-path backup: %w", err))
	}
	if err := patchOmnigentConfig(configPath); err != nil {
		return rollback(fmt.Errorf("omnigent policy config: %w", err))
	}
	if err := updateManagedFileBackupPostHash(opts.DataDir, c.Name(), "config", configPath); err != nil {
		return rollback(fmt.Errorf("omnigent update config backup: %w", err))
	}
	return nil
}

func prepareOmnigentManagedBackup(dataDir, connectorName, logicalName, targetPath string) error {
	backupPath := managedFileBackupPath(dataDir, connectorName, logicalName)
	backup, err := loadManagedFileBackupPath(backupPath)
	if os.IsNotExist(err) {
		return captureManagedFileBackup(dataDir, connectorName, logicalName, targetPath)
	}
	if err != nil {
		return err
	}
	previousPath := strings.TrimSpace(backup.Path)
	if previousPath == "" {
		return fmt.Errorf("managed backup has an empty target path")
	}
	if filepath.Clean(previousPath) == filepath.Clean(targetPath) {
		return nil
	}

	restored, err := restoreManagedFileBackupIfUnchanged(dataDir, connectorName, logicalName, previousPath)
	if err != nil {
		return fmt.Errorf("restore previous target %s: %w", previousPath, err)
	}
	if !restored {
		if logicalName != "config" {
			return fmt.Errorf("previous managed %s at %s was modified; clean it before switching OmniGent targets", logicalName, previousPath)
		}
		if err := removeOmnigentConfigEntries(previousPath); err != nil {
			return fmt.Errorf("remove policy entries from previous config %s: %w", previousPath, err)
		}
		discardManagedFileBackup(dataDir, connectorName, logicalName)
	}
	return captureManagedFileBackup(dataDir, connectorName, logicalName, targetPath)
}

type omnigentFileSnapshot struct {
	path    string
	data    []byte
	mode    os.FileMode
	existed bool
}

func captureOmnigentFileSnapshot(path string) (omnigentFileSnapshot, error) {
	snapshot := omnigentFileSnapshot{path: path}
	data, info, err := readManagedTarget(path)
	if err != nil {
		return snapshot, err
	}
	if info != nil {
		snapshot.data = data
		snapshot.mode = info.Mode().Perm()
		snapshot.existed = true
	}
	return snapshot, nil
}

func restoreOmnigentFileSnapshot(snapshot omnigentFileSnapshot) error {
	if snapshot.existed {
		mode := snapshot.mode
		if mode == 0 {
			mode = 0o600
		}
		if err := atomicWriteFile(snapshot.path, snapshot.data, mode); err != nil {
			return fmt.Errorf("omnigent rollback %s: %w", snapshot.path, err)
		}
		return nil
	}
	if err := os.Remove(snapshot.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("omnigent rollback remove %s: %w", snapshot.path, err)
	}
	return nil
}

func (c *OmnigentConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	paths := map[string]string{
		"config": managedFileBackupTargetPath(opts.DataDir, c.Name(), "config", omnigentConfigPath()),
		"module": managedFileBackupTargetPath(opts.DataDir, c.Name(), "module", omnigentPolicyModulePath(opts)),
		"pth":    managedFileBackupTargetPath(opts.DataDir, c.Name(), "pth", ""),
	}
	currentConfigPath := omnigentConfigPath()
	currentPthPath := ""
	if sitePackages, err := omnigentSitePackages(ctx); err == nil {
		currentPthPath = filepath.Join(sitePackages, "defenseclaw_omnigent.pth")
	}
	var errs []error
	for _, logical := range []string{"config", "module", "pth"} {
		path := paths[logical]
		if path == "" {
			continue
		}
		restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), logical, path)
		if err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", logical, err))
			continue
		}
		if !restored && logical == "config" {
			if err := removeOmnigentConfigEntries(path); err != nil {
				errs = append(errs, fmt.Errorf("remove config entries: %w", err))
			} else {
				discardManagedFileBackup(opts.DataDir, c.Name(), logical)
			}
		}
	}
	if filepath.Clean(currentConfigPath) != filepath.Clean(paths["config"]) {
		if err := removeOmnigentConfigEntries(currentConfigPath); err != nil {
			errs = append(errs, fmt.Errorf("remove config entries from current target: %w", err))
		}
	}
	if currentPthPath != "" && filepath.Clean(currentPthPath) != filepath.Clean(paths["pth"]) {
		data, info, err := readManagedTarget(currentPthPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("inspect current import path: %w", err))
		} else if info != nil && strings.TrimSpace(string(data)) == filepath.Dir(omnigentPolicyModulePath(opts)) {
			if err := os.Remove(currentPthPath); err != nil && !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("remove current import path: %w", err))
			}
		}
	}
	return errors.Join(errs...)
}

func (c *OmnigentConnector) VerifyClean(opts SetupOpts) error {
	configPath := managedFileBackupTargetPath(opts.DataDir, c.Name(), "config", omnigentConfigPath())
	if data, err := os.ReadFile(configPath); err == nil {
		if strings.Contains(string(data), omnigentPolicyModuleName) || strings.Contains(string(data), omnigentPolicyConfigKey) {
			return fmt.Errorf("omnigent teardown incomplete: config still references DefenseClaw at %s", configPath)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, logical := range []string{"module", "pth"} {
		backup, err := loadManagedFileBackupPath(managedFileBackupPath(opts.DataDir, c.Name(), logical))
		if err == nil {
			if _, statErr := os.Stat(backup.Path); statErr == nil {
				return fmt.Errorf("omnigent teardown incomplete: managed %s remains at %s", logical, backup.Path)
			} else if !os.IsNotExist(statErr) {
				return statErr
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (c *OmnigentConnector) Authenticate(r *http.Request) bool {
	return authenticateHookBridgeRequest(r, c.gatewayToken, c.masterKey, c.Name(),
		"the OmniGent policy bridge runs locally and setup injects Authorization when configured",
		&c.loopbackWarn)
}

func (c *OmnigentConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	return &ConnectorSignals{RawBody: body, RawModel: ParseModelFromBody(body), Stream: ParseStreamFromBody(body), PassthroughMode: !isChatPath(r.URL.Path), ConnectorName: c.Name()}, nil
}

func (c *OmnigentConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken, c.masterKey = gatewayToken, masterKey
}

func (c *OmnigentConnector) AgentPaths(opts SetupOpts) AgentPaths {
	pthPath := managedFileBackupTargetPath(opts.DataDir, c.Name(), "pth", "")
	paths := AgentPaths{
		PatchedFiles: []string{omnigentConfigPath(), omnigentPolicyModulePath(opts)},
		BackupFiles: []string{
			managedFileBackupPath(opts.DataDir, c.Name(), "config"),
			managedFileBackupPath(opts.DataDir, c.Name(), "module"),
			managedFileBackupPath(opts.DataDir, c.Name(), "pth"),
		},
	}
	if pthPath != "" {
		paths.PatchedFiles = append(paths.PatchedFiles, pthPath)
	}
	return paths
}

func (c *OmnigentConnector) HookRuntimeArtifacts(opts SetupOpts) []string {
	return []string{
		omnigentPolicyModulePath(opts),
		managedFileBackupTargetPath(opts.DataDir, c.Name(), "pth", ""),
	}
}

func (c *OmnigentConnector) HookConfigReferenceNeedles(SetupOpts) []string {
	return []string{omnigentPolicyHandler}
}

func (c *OmnigentConnector) RequiredEnv() []EnvRequirement {
	return append([]EnvRequirement{{
		Scope:       EnvScopeNone,
		Description: "Policy enforcement requires no environment variables; optional native OmniGent OTLP uses process environment variables.",
	}}, c.Capabilities(SetupOpts{APIAddr: "127.0.0.1:18970"}).Telemetry.Env...)
}

func (c *OmnigentConnector) SupportsComponentScanning() bool { return true }
func (c *OmnigentConnector) ComponentTargets(string) map[string][]string {
	return map[string][]string{}
}
func (c *OmnigentConnector) HasUsableProviders() (int, error) { return 1, nil }

func omnigentPolicyModulePath(opts SetupOpts) string {
	return filepath.Join(opts.DataDir, "hooks", omnigentPolicyModuleName+".py")
}

func omnigentConfigPath() string {
	if OmnigentConfigPathOverride != "" {
		return OmnigentConfigPathOverride
	}
	if home := strings.TrimSpace(os.Getenv("OMNIGENT_CONFIG_HOME")); home != "" {
		return filepath.Join(home, "config.yaml")
	}
	return homePath(".omnigent", "config.yaml")
}

func omnigentSitePackages(ctx context.Context) (string, error) {
	if OmnigentSitePackagesPathOverride != "" {
		return OmnigentSitePackagesPathOverride, nil
	}
	var executable string
	for _, name := range []string{"omnigent", "omni"} {
		if path, err := exec.LookPath(name); err == nil {
			executable = path
			break
		}
	}
	if executable == "" {
		return "", fmt.Errorf("omnigent connector: neither 'omnigent' nor 'omni' is on PATH")
	}
	pythonPath := ""
	for _, name := range []string{"python", "python3", "python.exe", "python3.exe"} {
		candidate := filepath.Join(filepath.Dir(executable), name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			pythonPath = candidate
			break
		}
	}
	if pythonPath == "" {
		file, openErr := os.Open(executable)
		if openErr == nil {
			line, _ := bufio.NewReader(file).ReadString('\n')
			_ = file.Close()
			if strings.HasPrefix(line, "#!") {
				fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#!")))
				switch {
				case len(fields) == 1:
					pythonPath = fields[0]
				case len(fields) == 2 && filepath.Base(fields[0]) == "env":
					resolved, err := exec.LookPath(fields[1])
					if err != nil {
						return "", fmt.Errorf("omnigent connector: resolve Python from env shebang: %w", err)
					}
					pythonPath = resolved
				case len(fields) > 0:
					return "", fmt.Errorf("omnigent connector: unsupported interpreter arguments in shebang for %s", executable)
				}
			}
		}
	}
	if pythonPath == "" {
		return "", fmt.Errorf("omnigent connector: could not locate the Python interpreter beside %s", executable)
	}
	if err := validateOmnigentInterpreter(pythonPath); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, pythonPath, "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("omnigent connector: resolve Python site-packages with %s: %w (%s)", pythonPath, err, strings.TrimSpace(stderr.String()))
	}
	path := ""
	lines := strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if candidate := strings.TrimSpace(lines[i]); candidate != "" {
			path = candidate
			break
		}
	}
	if path == "" {
		return "", fmt.Errorf("omnigent connector: Python returned an empty site-packages path")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("omnigent connector: Python returned a non-absolute site-packages path %q", path)
	}
	return filepath.Clean(path), nil
}

func validateOmnigentInterpreter(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("omnigent connector: resolve Python interpreter %s: %w", path, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return fmt.Errorf("omnigent connector: resolve Python interpreter path: %w", err)
	}
	defaultPrefixes := []string{
		"/usr/bin", "/usr/local/bin", "/usr/sbin", "/usr/local/sbin", "/bin", "/sbin",
		"/opt/homebrew/bin", "/opt/homebrew/sbin", "/opt/homebrew/Cellar", "/opt/homebrew/Caskroom",
		"/usr/local/Cellar", "/opt/local/bin", "/opt/local/sbin",
	}
	prefixes := append([]string(nil), defaultPrefixes...)
	prefixes = append(prefixes, filepath.SplitList(os.Getenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES"))...)
	trusted := false
	for index, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			continue
		}
		if index >= len(defaultPrefixes) && !filepath.IsAbs(prefix) {
			continue
		}
		absolute, absErr := filepath.Abs(prefix)
		if absErr != nil {
			continue
		}
		if evaluated, evalErr := filepath.EvalSymlinks(absolute); evalErr == nil {
			absolute = evaluated
		}
		if resolved == absolute || strings.HasPrefix(resolved, absolute+string(os.PathSeparator)) {
			trusted = true
			break
		}
	}
	if !trusted {
		return fmt.Errorf("omnigent connector: Python interpreter %s is not in a trusted install prefix; add its directory to DEFENSECLAW_TRUSTED_BIN_PREFIXES", resolved)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("omnigent connector: stat Python interpreter %s: %w", resolved, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("omnigent connector: Python interpreter %s is not a non-group/world-writable regular file", resolved)
	}
	parentInfo, err := os.Stat(filepath.Dir(resolved))
	if err != nil {
		return fmt.Errorf("omnigent connector: stat Python interpreter directory: %w", err)
	}
	if parentInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("omnigent connector: Python interpreter directory %s is group/world-writable", filepath.Dir(resolved))
	}
	return nil
}

func renderOmnigentPolicy(template, apiAddr, token, failMode string) string {
	encode := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	replacer := strings.NewReplacer(
		"{{API_ADDR_B64}}", encode(strings.TrimSpace(apiAddr)),
		"{{API_TOKEN_B64}}", encode(token),
		"{{FAIL_MODE_B64}}", encode(normalizeHookFailMode(failMode)),
	)
	return replacer.Replace(template)
}

func patchOmnigentConfig(path string) error {
	cfg, err := readYAMLObject(path)
	if err != nil {
		return err
	}
	modules, err := yamlStringList(cfg["policy_modules"])
	if err != nil {
		return fmt.Errorf("policy_modules: %w", err)
	}
	if !stringSliceContains(modules, omnigentPolicyModuleName) {
		modules = append(modules, omnigentPolicyModuleName)
	}
	cfg["policy_modules"] = modules

	policies, ok := cfg["policies"].(map[string]interface{})
	if !ok {
		if cfg["policies"] != nil {
			return fmt.Errorf("policies: expected a mapping, got %T", cfg["policies"])
		}
		policies = map[string]interface{}{}
		cfg["policies"] = policies
	}
	if existing, ok := policies[omnigentPolicyConfigKey]; ok {
		entry, _ := existing.(map[string]interface{})
		if entry == nil || fmt.Sprint(entry["handler"]) != omnigentPolicyHandler {
			return fmt.Errorf("policies.%s already exists and is not managed by DefenseClaw", omnigentPolicyConfigKey)
		}
		if policyType := strings.TrimSpace(fmt.Sprint(entry["type"])); policyType != "" && policyType != "function" {
			return fmt.Errorf("policies.%s has incompatible type %q", omnigentPolicyConfigKey, policyType)
		}
		entry["type"] = "function"
		entry["handler"] = omnigentPolicyHandler
		policies[omnigentPolicyConfigKey] = entry
	} else {
		policies[omnigentPolicyConfigKey] = map[string]interface{}{
			"type":    "function",
			"handler": omnigentPolicyHandler,
		}
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

func removeOmnigentConfigEntries(path string) error {
	cfg, err := readYAMLObject(path)
	if err != nil {
		return err
	}
	modules, err := yamlStringList(cfg["policy_modules"])
	if err != nil {
		return err
	}
	filtered := modules[:0]
	for _, module := range modules {
		if module != omnigentPolicyModuleName {
			filtered = append(filtered, module)
		}
	}
	if len(filtered) == 0 {
		delete(cfg, "policy_modules")
	} else {
		cfg["policy_modules"] = filtered
	}
	if policies, ok := cfg["policies"].(map[string]interface{}); ok {
		if entry, ok := policies[omnigentPolicyConfigKey].(map[string]interface{}); ok && fmt.Sprint(entry["handler"]) == omnigentPolicyHandler {
			delete(policies, omnigentPolicyConfigKey)
		}
		if len(policies) == 0 {
			delete(cfg, "policies")
		}
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

func yamlStringList(raw interface{}) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	switch values := raw.(type) {
	case []string:
		return append([]string(nil), values...), nil
	case []interface{}:
		out := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("entry %v is not a string", value)
			}
			out = append(out, text)
		}
		return out, nil
	case string:
		return []string{values}, nil
	default:
		return nil, fmt.Errorf("expected a string or list of strings, got %T", raw)
	}
}

func stringSliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
