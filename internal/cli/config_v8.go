// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
)

const configV8WireVersion = 2

type configV8WireResponse struct {
	WireVersion       int             `json:"wire_version"`
	Kind              string          `json:"kind"`
	ConfigVersion     int             `json:"config_version"`
	Source            string          `json:"source"`
	DataDir           string          `json:"data_dir"`
	GatewayAPIPort    int             `json:"gateway_api_port"`
	PlanDigest        string          `json:"plan_digest"`
	NetworkValidation string          `json:"network_validation"`
	Valid             *bool           `json:"valid,omitempty"`
	Warnings          []string        `json:"warnings,omitempty"`
	Effective         json.RawMessage `json:"effective,omitempty"`
}

type configV8WireFailure struct {
	WireVersion   int    `json:"wire_version"`
	Kind          string `json:"kind"`
	ConfigVersion int    `json:"config_version"`
	Path          string `json:"path"`
	Reason        string `json:"reason"`
	// Message is the refusal in plain words on a standalone managed host,
	// as `config validate` prints it there.
	Message string `json:"message,omitempty"`
}

// config-v8 is a machine-facing bridge for the Python operator CLI. Keeping
// effective-plan compilation here means config show/validate/plan can use the
// same compiler as gateway startup without starting the gateway, opening its
// databases, constructing exporters, or contacting a destination.
var configV8Cmd = &cobra.Command{
	Use:    "config-v8",
	Short:  "Inspect configuration v8 without starting the gateway",
	Hidden: true,
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		return nil
	},
	PersistentPostRun: func(_ *cobra.Command, _ []string) {},
}

var configV8ValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration v8 and emit a machine-readable result",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		loaded, err := checkConfigV8Candidate(configV8ConfigPath, configV8DataDir)
		if err != nil {
			failure := configV8ValidationFailure(err)
			if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(failure); encodeErr != nil {
				return errors.New("configuration validation failed and its safe diagnostic could not be written")
			}
			return fmt.Errorf("configuration validation failed at %s: %s", failure.Path, failure.Reason)
		}
		valid := true
		result := configV8WireResponse{
			WireVersion:       configV8WireVersion,
			Kind:              "validation",
			ConfigVersion:     loaded.runtime.ConfigVersion,
			Source:            loaded.source,
			DataDir:           loaded.compiled.DataDir,
			GatewayAPIPort:    loaded.gatewayAPIPort,
			PlanDigest:        loaded.compiled.Plan.Digest(),
			NetworkValidation: "offline_syntax_and_literal_policy_only",
			Valid:             &valid,
			Warnings:          append(gateway.ConfigHILTWarnings(loaded.runtime), configV8InstalledAdvisories(loaded)...),
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetEscapeHTML(false)
		return encoder.Encode(result)
	},
}

// checkConfigV8Candidate is the writers' validator: the file loads through
// the compiler and the runtime loader, the rule packs and rule IDs it
// references load as the gateway's reload needs, and every jsonl destination
// is a file the gateway may write (GAP-0890). It changes nothing.
func checkConfigV8Candidate(path, dataDir string) (*loadedConfigV8File, error) {
	loaded, err := loadConfigV8FileWithCredentials(path, dataDir, configValidateCredentialsDir(path))
	if err != nil {
		return nil, err
	}
	err = config.CheckCandidateAssets(loaded.runtime)
	if err == nil {
		err = checkJSONLDestinationPaths(loaded.compiled, "")
	}
	if err == nil && !configV8IsInstalledConfig(loaded.source) {
		// The managed lifecycle refuses these literals in a new candidate
		// (ensure --config, Setup, bundle apply); validate must agree, or an
		// administrator is told a file is valid that ensure then refuses
		// (GAP-0138). The installed config keeps loading for the upgrade
		// path; configV8InstalledAdvisories reports it instead.
		err = config.ValidateManagedStandaloneLiteralCandidate(loaded.runtime, loaded.raw)
	}
	if err != nil {
		return nil, &configV8SourceError{version: loaded.runtime.ConfigVersion, err: err}
	}
	return loaded, nil
}

// configV8IsInstalledConfig reports whether source is the config.yaml this
// host runs: the per-user default or the standalone enterprise layout's.
func configV8IsInstalledConfig(source string) bool {
	candidates := []string{config.ConfigPath()}
	if layout, err := managed.StandaloneLayoutFor(runtime.GOOS); err == nil && layout.ConfigPath != "" {
		candidates = append(candidates, layout.ConfigPath)
	}
	resolved := configV8ResolvedPath(source)
	for _, candidate := range candidates {
		if resolved != "" && resolved == configV8ResolvedPath(candidate) {
			return true
		}
	}
	return false
}

func configV8ResolvedPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	if real, err := filepath.EvalSymlinks(absolute); err == nil {
		return real
	}
	return filepath.Clean(absolute)
}

// configV8InstalledAdvisories names the literals an installed managed
// standalone config still carries from 1.0.2, the same advisory enterprise
// status and verify print. It never names a value.
func configV8InstalledAdvisories(loaded *loadedConfigV8File) []string {
	if loaded == nil || !configV8IsInstalledConfig(loaded.source) {
		return nil
	}
	paths := config.ManagedStandaloneUpgradeAdvisories(loaded.runtime, loaded.raw)
	if len(paths) == 0 {
		return nil
	}
	return []string{"managed_literal_credentials: installed config uses literals at " + strings.Join(paths, ", ") +
		"; use {credential: NAME} or {env: NAME} where supported; webhook URLs remain supported"}
}

func configV8ValidationFailure(err error) configV8WireFailure {
	result := configV8WireFailure{
		WireVersion:   configV8WireVersion,
		Kind:          "validation_error",
		ConfigVersion: config.ObservabilityV8ConfigVersion,
		Path:          "$",
		Reason:        "configuration could not be compiled safely",
	}
	var yamlError *config.V8YAMLError
	var schemaError *config.V8SchemaError
	var semanticError *config.V8SemanticError
	var secretError *config.V8SecretReferenceError
	var profileError *config.UnknownGuardrailProfileError
	var settingError *config.SettingError
	var sourceError *configV8SourceError
	if errors.As(err, &sourceError) && sourceError.version >= config.ObservabilityV8ConfigVersion {
		result.ConfigVersion = sourceError.version
	}
	switch {
	case errors.As(err, &settingError):
		// A runtime-loader refusal of a profile, its sandbox section or the
		// openshell section: name the setting and the rule, so the fix is to
		// that field (GAP-0337, GAP-0323).
		result.Path = configV8DiagnosticPath("$." + settingError.Path)
		result.Reason = configV8DiagnosticReason("config_semantic_invalid",
			configV8SettingRule(settingError.Detail()), "", "")
	case errors.As(err, &profileError):
		// The runtime loader's check, after the schema pass: name the setting
		// and the profile, so the fix is to the assignment (GAP-0288).
		result.Path = "$." + profileError.Field
		result.Reason = configV8DiagnosticReason("config_semantic_invalid",
			fmt.Sprintf("unknown profile %q", configV8ShortName(profileError.Profile)), "",
			configV8DefinedProfiles(profileError.Defined))
	case errors.As(err, &secretError):
		result.Path = "$." + secretError.Path
		result.Reason = "[secret_reference_unresolved] required environment-backed secret is unavailable"
		if secretError.Credential {
			result.Reason = fmt.Sprintf(
				"[secret_reference_unresolved] protected credential %q is not stored or not trusted; "+
					"credential references resolve only in a standalone enterprise deployment, after `enterprise secret set --name %s`",
				secretError.Reference, secretError.Reference,
			)
		}
	case errors.As(err, &yamlError):
		if sourceError == nil && yamlError.ConfigVersion >= config.ObservabilityV8ConfigVersion {
			result.ConfigVersion = yamlError.ConfigVersion
		}
		result.Path = configV8DiagnosticPath(yamlError.Path)
		result.Reason = configV8DiagnosticReason(string(yamlError.Code), yamlError.Summary, "", yamlError.Action)
	case errors.As(err, &schemaError):
		if schemaError.Version >= config.ConfigVersionV9 {
			result.ConfigVersion = schemaError.Version
		}
		result.Path = configV8DiagnosticPath(schemaError.Path)
		detail := schemaError.Expected
		if schemaError.Suggestion != "" {
			if detail != "" {
				detail += "; "
			}
			detail += "suggested field " + schemaError.Suggestion
		}
		result.Reason = configV8DiagnosticReason("config_schema_invalid", schemaError.Summary, detail, schemaError.Action)
	case errors.As(err, &semanticError):
		result.Path = configV8DiagnosticPath(semanticError.Path)
		result.Reason = configV8DiagnosticReason(
			"config_semantic_invalid",
			semanticError.Summary,
			semanticError.Expected,
			semanticError.Action,
		)
	}
	return result
}

// configV8SourceError carries the config_version the source file declares to
// the diagnostic of a refusal that happens after the file was parsed.
type configV8SourceError struct {
	version int
	err     error
}

func (e *configV8SourceError) Error() string { return e.err.Error() }
func (e *configV8SourceError) Unwrap() error { return e.err }

// configV8SourceVersion is the config_version a parsed document declares, or
// the compiler's own when it declares none that reads as an integer.
func configV8SourceVersion(document *config.V8YAMLDocument) int {
	if document == nil {
		return config.ObservabilityV8ConfigVersion
	}
	switch value := document.Plain["config_version"].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case uint64:
		return int(value)
	case float64:
		return int(value)
	}
	return config.ObservabilityV8ConfigVersion
}

// configV8SettingRule is the loader's rule text for a setting as a diagnostic
// shows it: configured names stay, a long quoted value is shortened, and a
// text with a URL or user info is withheld.
func configV8SettingRule(rule string) string {
	rule = configV8DiagnosticText(rule)
	if rule == "" || strings.Contains(rule, "://") || strings.Contains(rule, "@") {
		return "a setting here violates a semantic constraint (the rule text is withheld because it quotes a URL)"
	}
	parts := strings.Split(rule, `"`)
	for i := 1; i < len(parts); i += 2 {
		parts[i] = configV8ShortName(parts[i])
	}
	shown := strings.Join(parts, `"`)
	if len(shown) > 700 {
		shown = shown[:697] + "..."
	}
	return shown
}

// configV8ShortName is a configured name as a diagnostic shows it.
func configV8ShortName(name string) string {
	if len(name) > 64 {
		return name[:61] + "..."
	}
	return name
}

func configV8DefinedProfiles(names []string) string {
	if len(names) == 0 {
		return "guardrail.profiles defines none: add the profile there, or remove this setting"
	}
	shown := make([]string, 0, len(names))
	for _, name := range names {
		if len(shown) == 8 {
			shown = append(shown, "...")
			break
		}
		shown = append(shown, configV8ShortName(name))
	}
	return "guardrail.profiles defines " + strings.Join(shown, ", ") + ": use one of them, or define this one there"
}

func configV8DiagnosticPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !strings.HasPrefix(value, "$") || len(value) > 512 {
		return "$"
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return "$"
		}
	}
	return value
}

func configV8DiagnosticReason(code, summary, detail, action string) string {
	parts := make([]string, 0, 3)
	if value := configV8DiagnosticText(summary); value != "" {
		parts = append(parts, value)
	}
	if value := configV8DiagnosticText(detail); value != "" {
		parts = append(parts, "expected "+value)
	}
	if value := configV8DiagnosticText(action); value != "" {
		parts = append(parts, value)
	}
	code = configV8DiagnosticText(code)
	if code == "" {
		code = "configuration_invalid"
	}
	if len(parts) == 0 {
		parts = append(parts, "configuration could not be compiled safely")
	}
	reason := "[" + code + "] " + strings.Join(parts, "; ")
	if len(reason) > 1_000 {
		reason = reason[:1_000]
	}
	return reason
}

func configV8DiagnosticText(value string) string {
	value = strings.TrimSpace(value)
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return ""
		}
	}
	return value
}

var configV8EffectiveCmd = &cobra.Command{
	Use:   "effective",
	Short: "Emit the secret-masked effective observability plan as JSON",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		loaded, err := loadConfigV8File(configV8ConfigPath, configV8DataDir)
		if err != nil {
			return err
		}
		response := configV8WireResponse{
			WireVersion:       configV8WireVersion,
			Kind:              "effective",
			ConfigVersion:     loaded.runtime.ConfigVersion,
			Source:            loaded.source,
			DataDir:           loaded.compiled.DataDir,
			GatewayAPIPort:    loaded.gatewayAPIPort,
			PlanDigest:        loaded.compiled.Plan.Digest(),
			NetworkValidation: "offline_syntax_and_literal_policy_only",
			Effective:         loaded.compiled.Plan.EffectiveJSON(),
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetEscapeHTML(false)
		return encoder.Encode(response)
	},
}

var configV8SchemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Emit the embedded canonical configuration v8 JSON Schema",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if _, err := cmd.OutOrStdout().Write(publicschemas.DefenseClawConfigV8Schema()); err != nil {
			return fmt.Errorf("write configuration schema: %w", err)
		}
		_, err := io.WriteString(cmd.OutOrStdout(), "\n")
		return err
	},
}

var configV8ReferenceCmd = &cobra.Command{
	Use:   "reference",
	Short: "Emit a generated configuration v8 reference artifact",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if configV8ReferenceSection != "observability" {
			return fmt.Errorf("unsupported v8 reference section %q; expected observability", configV8ReferenceSection)
		}
		var data []byte
		switch configV8ReferenceFormat {
		case "yaml":
			data = publicschemas.DefenseClawConfigV8ObservabilityReferenceYAML()
		case "markdown":
			data = publicschemas.DefenseClawConfigV8ObservabilityReferenceMarkdown()
		default:
			return fmt.Errorf("unsupported v8 reference format %q; expected yaml or markdown", configV8ReferenceFormat)
		}
		if _, err := cmd.OutOrStdout().Write(data); err != nil {
			return fmt.Errorf("write configuration reference: %w", err)
		}
		if len(data) == 0 || data[len(data)-1] != '\n' {
			_, err := io.WriteString(cmd.OutOrStdout(), "\n")
			return err
		}
		return nil
	},
}

var (
	configV8ConfigPath       string
	configV8DataDir          string
	configV8ReferenceSection string
	configV8ReferenceFormat  string
)

func init() {
	configV8Cmd.PersistentFlags().StringVar(
		&configV8ConfigPath,
		"config",
		"",
		"configuration file (default: DEFENSECLAW_CONFIG or <data-dir>/config.yaml)",
	)
	configV8Cmd.PersistentFlags().StringVar(
		&configV8DataDir,
		"data-dir",
		"",
		"default data directory when data_dir is omitted from the source",
	)
	configV8ReferenceCmd.Flags().StringVar(
		&configV8ReferenceSection,
		"section",
		"observability",
		"reference section to render",
	)
	configV8ReferenceCmd.Flags().StringVar(
		&configV8ReferenceFormat,
		"format",
		"yaml",
		"reference format: yaml or markdown",
	)
	configV8Cmd.AddCommand(configV8ValidateCmd, configV8EffectiveCmd, configV8SchemaCmd, configV8ReferenceCmd)
	rootCmd.AddCommand(configV8Cmd)
}

func compileConfigV8File(path, defaultDataDir string) (*config.ObservabilityV8CompiledConfig, string, int, error) {
	loaded, err := loadConfigV8File(path, defaultDataDir)
	if err != nil {
		return nil, "", 0, err
	}
	return loaded.compiled, loaded.source, loaded.gatewayAPIPort, nil
}

type loadedConfigV8File struct {
	compiled       *config.ObservabilityV8CompiledConfig
	document       *config.V8YAMLDocument
	runtime        *config.Config
	source         string
	raw            []byte
	gatewayAPIPort int
}

func loadConfigV8File(path, defaultDataDir string) (*loadedConfigV8File, error) {
	return loadConfigV8FileWithCredentials(path, defaultDataDir, "")
}

// loadConfigV8FileWithCredentials is loadConfigV8File resolving protected
// credential references from credentialsDir; empty derives it from a
// standalone source's own path.
func loadConfigV8FileWithCredentials(path, defaultDataDir, credentialsDir string) (*loadedConfigV8File, error) {
	return loadConfigV8Source(path, defaultDataDir, credentialsDir, false)
}

// loadConfigV8Source loads and strict-parses the file. With migrate, a
// config_version 8 file is first converted in memory to a config_version 9
// document, and that document is what is parsed
// and compiled (loaded.raw is it too): the keys the migration moves
// (skill_actions and the like) are not in the current schema, so the strict
// parse of the raw file would refuse the very file the migration exists to
// fix. A failed migration refuses the file.
//
// migrate also marks the load of a process that runs the file (the gateway
// and the watchdog): loaded.runtime is then the strict runtime decode
// (managed trust, provenance) the caller runs, instead of an inspection decode
// the caller would decode again. Each decode is a full pass over every
// guardrail profile (GAP-0276).
func loadConfigV8Source(path, defaultDataDir, credentialsDir string, migrate bool) (loaded *loadedConfigV8File, err error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = config.ConfigPath()
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve v8 config path: %w", err)
	}
	raw, err := readConfigV8Source(absPath)
	if err != nil {
		return nil, err
	}
	legacyV8 := migrate && config.NeedsMigrationV9(raw)
	if migrate {
		if raw, err = config.MigrateV8InMemory(absPath, raw, guardrail.RulePackDigest); err != nil {
			return nil, config.InMemoryMigrationError(absPath, err)
		}
	}

	// Resolve the data directory from the already strict YAML projection before
	// compiling so token references persisted in that installation's .env are
	// available to the canonical secret resolver. ParseCompileObservabilityV8
	// performs the authoritative parse/schema/semantic pass below.
	document, err := config.ParseV8YAML(absPath, raw)
	if err != nil {
		return nil, err
	}
	// Every later refusal carries the version the file declares, not the
	// compiler's: a source-9 file failed as config_version 8 (GAP-0337).
	sourceVersion := configV8SourceVersion(document)
	if legacyV8 {
		sourceVersion = config.ObservabilityV8ConfigVersion
	}
	defer func() {
		if err != nil {
			err = &configV8SourceError{version: sourceVersion, err: err}
		}
	}()
	resolvedDataDir := strings.TrimSpace(defaultDataDir)
	if sourceDataDir, ok := document.Plain["data_dir"].(string); ok && strings.TrimSpace(sourceDataDir) != "" {
		resolvedDataDir = strings.TrimSpace(sourceDataDir)
	}
	if resolvedDataDir == "" {
		resolvedDataDir = config.DefaultDataPath()
	}
	loadDotEnvIntoOS(filepath.Join(resolvedDataDir, ".env"))

	// The schema pass comes first: its errors name the field and what it
	// takes. The managed-destination decode below runs the runtime loader,
	// whose errors reach the wire only as "configuration could not be
	// compiled safely" at "$" (an openshell.llm or
	// openshell.workdir.undo_ignored.max_mb the schema refuses was reported
	// that way).
	compiled, err := config.ParseCompileObservabilityV8(
		absPath,
		raw,
		config.ObservabilityV8CompileOptions{DefaultDataDir: resolvedDataDir, CredentialsDir: credentialsDir},
	)
	if err != nil {
		return nil, err
	}
	loadRuntime := config.LoadRuntimeV8InspectionCandidateFromBytes
	if migrate {
		loadRuntime = config.LoadRuntimeV8FromBytes
	}
	runtimeCandidate, err := loadRuntime(absPath, raw)
	if err != nil {
		return nil, err
	}
	runtimeCandidate.RuntimeV8RulePackRebase = legacyV8 && !runtimeCandidate.SecureClientIntegration()
	compiled.Plan, err = config.WithObservabilityV8ManagedAIDDestination(
		compiled.Plan, config.ObservabilityV8ManagedAIDOptionsFromConfig(runtimeCandidate, raw))
	if err != nil {
		return nil, err
	}
	if err := validateRuntimeV8ConnectorRoster(document, runtimeCandidate); err != nil {
		return nil, err
	}
	gatewayAPIPort := config.DefaultGatewayAPIPort
	if gateway, ok := document.Plain["gateway"].(map[string]any); ok {
		if rawPort, exists := gateway["api_port"]; exists {
			configured, typed := rawPort.(int)
			if !typed || configured < 1 || configured > 65535 {
				return nil, fmt.Errorf("compiled v8 gateway.api_port is invalid")
			}
			gatewayAPIPort = configured
		}
	}
	return &loadedConfigV8File{
		compiled:       compiled,
		document:       document,
		runtime:        runtimeCandidate,
		source:         absPath,
		raw:            append([]byte(nil), raw...),
		gatewayAPIPort: gatewayAPIPort,
	}, nil
}

func validateRuntimeV8ConnectorRoster(document *config.V8YAMLDocument, candidate *config.Config) error {
	if document == nil || candidate == nil {
		return &config.V8SemanticError{
			Path:     "$.guardrail.connectors",
			Summary:  "target runtime returned no connector candidate",
			Expected: "the configured connector roster to survive target-runtime decoding",
			Action:   "use the packaged target runtime to validate the complete candidate",
		}
	}
	guardrail, ok := document.Plain["guardrail"].(map[string]any)
	if !ok {
		return nil
	}
	configured, ok := guardrail["connectors"].(map[string]any)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(configured))
	for name := range configured {
		// until 1.1: the runtime loader drops a connector 1.0.4 removed
		// (OpenHands, OmniGent) so the gateway can start and tear it down;
		// expecting it to survive refused every published config that set it
		// up before cleanup could run (GAP-0290).
		if config.IsRetiredConnector(name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	// The runtime loader moves a retired connector key to its replacement
	// (legacyconnector), so compare against the roster it is expected to
	// produce rather than the raw source keys.
	_, rename, dropped := legacyconnector.MigrateConnectorKeys("", names)
	droppedKeys := make(map[string]struct{}, len(dropped))
	for _, name := range dropped {
		droppedKeys[name] = struct{}{}
	}
	expected := 0
	for _, name := range names {
		if _, gone := droppedKeys[name]; gone {
			continue
		}
		expected++
		runtimeName := name
		if replacement, renamed := rename[name]; renamed {
			runtimeName = replacement
		}
		if _, retained := candidate.Guardrail.Connectors[runtimeName]; retained {
			continue
		}
		return &config.V8SemanticError{
			Source:   document.Source,
			Path:     "$.guardrail.connectors." + name,
			Summary:  "target runtime did not retain the configured connector",
			Expected: "the staged runtime connector roster to match the candidate source",
			Action:   "refuse activation and keep the live configuration unchanged",
		}
	}
	if len(candidate.Guardrail.Connectors) != expected {
		return &config.V8SemanticError{
			Source:   document.Source,
			Path:     "$.guardrail.connectors",
			Summary:  "target runtime changed the configured connector roster",
			Expected: "the staged runtime connector roster to match the candidate source",
			Action:   "refuse activation and keep the live configuration unchanged",
		}
	}
	return nil
}

func readConfigV8Source(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	defer file.Close()
	limit := int64(config.ObservabilityV8MaxSourceBytes) + 1
	raw, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if len(raw) > config.ObservabilityV8MaxSourceBytes {
		// Feed a bounded over-limit value to the canonical parser so callers get
		// its stable code/action without allocating an attacker-sized file.
		_, parseErr := config.ParseV8YAML(path, bytes.Repeat([]byte{'x'}, config.ObservabilityV8MaxSourceBytes+1))
		return nil, parseErr
	}
	return raw, nil
}
