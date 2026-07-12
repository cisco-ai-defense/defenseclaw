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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
	Effective         json.RawMessage `json:"effective,omitempty"`
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
		compiled, source, gatewayAPIPort, err := compileConfigV8File(configV8ConfigPath, configV8DataDir)
		if err != nil {
			return err
		}
		valid := true
		result := configV8WireResponse{
			WireVersion:       configV8WireVersion,
			Kind:              "validation",
			ConfigVersion:     8,
			Source:            source,
			DataDir:           compiled.DataDir,
			GatewayAPIPort:    gatewayAPIPort,
			PlanDigest:        compiled.Plan.Digest(),
			NetworkValidation: "offline_syntax_and_literal_policy_only",
			Valid:             &valid,
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetEscapeHTML(false)
		return encoder.Encode(result)
	},
}

var configV8EffectiveCmd = &cobra.Command{
	Use:   "effective",
	Short: "Emit the secret-masked effective observability plan as JSON",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		compiled, source, gatewayAPIPort, err := compileConfigV8File(configV8ConfigPath, configV8DataDir)
		if err != nil {
			return err
		}
		response := configV8WireResponse{
			WireVersion:       configV8WireVersion,
			Kind:              "effective",
			ConfigVersion:     8,
			Source:            source,
			DataDir:           compiled.DataDir,
			GatewayAPIPort:    gatewayAPIPort,
			PlanDigest:        compiled.Plan.Digest(),
			NetworkValidation: "offline_syntax_and_literal_policy_only",
			Effective:         compiled.Plan.EffectiveJSON(),
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
	source         string
	raw            []byte
	gatewayAPIPort int
}

func loadConfigV8File(path, defaultDataDir string) (*loadedConfigV8File, error) {
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

	// Resolve the data directory from the already strict YAML projection before
	// compiling so token references persisted in that installation's .env are
	// available to the canonical secret resolver. ParseCompileObservabilityV8
	// performs the authoritative parse/schema/semantic pass below.
	document, err := config.ParseV8YAML(absPath, raw)
	if err != nil {
		return nil, err
	}
	resolvedDataDir := strings.TrimSpace(defaultDataDir)
	if sourceDataDir, ok := document.Plain["data_dir"].(string); ok && strings.TrimSpace(sourceDataDir) != "" {
		resolvedDataDir = strings.TrimSpace(sourceDataDir)
	}
	if resolvedDataDir == "" {
		resolvedDataDir = config.DefaultDataPath()
	}
	loadDotEnvIntoOS(filepath.Join(resolvedDataDir, ".env"))
	managedOptions, err := config.ResolveObservabilityV8ManagedAIDOptionsForInspection(absPath, raw)
	if err != nil {
		return nil, err
	}

	compiled, err := config.ParseCompileObservabilityV8(
		absPath,
		raw,
		config.ObservabilityV8CompileOptions{DefaultDataDir: resolvedDataDir},
	)
	if err != nil {
		return nil, err
	}
	compiled.Plan, err = config.WithObservabilityV8ManagedAIDDestination(compiled.Plan, managedOptions)
	if err != nil {
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
		source:         absPath,
		raw:            append([]byte(nil), raw...),
		gatewayAPIPort: gatewayAPIPort,
	}, nil
}

func readConfigV8Source(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read v8 config %s: %w", path, err)
	}
	defer file.Close()
	limit := int64(config.ObservabilityV8MaxSourceBytes) + 1
	raw, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return nil, fmt.Errorf("read v8 config %s: %w", path, err)
	}
	if len(raw) > config.ObservabilityV8MaxSourceBytes {
		// Feed a bounded over-limit value to the canonical parser so callers get
		// its stable code/action without allocating an attacker-sized file.
		_, parseErr := config.ParseV8YAML(path, bytes.Repeat([]byte{'x'}, config.ObservabilityV8MaxSourceBytes+1))
		return nil, parseErr
	}
	return raw, nil
}
