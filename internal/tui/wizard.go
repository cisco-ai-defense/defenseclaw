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

package tui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"charm.land/huh/v2"
)

// WizardResult holds the values collected by the first-run wizard.
type WizardResult struct {
	DataDir          string
	EnableGuardrail  bool
	EnableSandbox    bool
	GuardrailMode    string
	ScannerMode      string
	LLMProvider      string
	LLMModel         string
	GatewayHost      string
	GatewayPort      string
	EnableSplunk     bool
	SplunkHECURL     string
}

// ShouldRunWizard returns true if config.yaml doesn't exist yet.
func ShouldRunWizard() bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	configPath := filepath.Join(homeDir, ".defenseclaw", "config.yaml")
	_, err = os.Stat(configPath)
	return os.IsNotExist(err)
}

// RunWizard executes the multi-step first-run setup wizard.
// It returns the wizard result and any error.
func RunWizard(theme *Theme) (*WizardResult, error) {
	result := &WizardResult{
		DataDir:      defaultDataDir(),
		GatewayHost:  "localhost",
		GatewayPort:  "9090",
		GuardrailMode: "observe",
		ScannerMode:  "local",
		LLMProvider:  "openai",
		LLMModel:     "gpt-4o",
	}

	sandboxAvailable := runtime.GOOS == "linux"

	// Step 1: Initialize
	step1 := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Welcome to DefenseClaw").
				Description("Step 1 of 5: Initialize\n\nLet's set up DefenseClaw to secure your OpenClaw installation."),
			huh.NewInput().
				Title("Data directory").
				Description("Where DefenseClaw stores config, audit DB, and logs.").
				Value(&result.DataDir),
			huh.NewConfirm().
				Title("Enable LLM guardrail?").
				Description("Intercepts LLM traffic for security scanning. Recommended for production.").
				Value(&result.EnableGuardrail),
		),
	)

	if sandboxAvailable {
		step1 = huh.NewForm(
			huh.NewGroup(
				huh.NewNote().
					Title("Welcome to DefenseClaw").
					Description("Step 1 of 5: Initialize\n\nLet's set up DefenseClaw to secure your OpenClaw installation."),
				huh.NewInput().
					Title("Data directory").
					Description("Where DefenseClaw stores config, audit DB, and logs.").
					Value(&result.DataDir),
				huh.NewConfirm().
					Title("Enable LLM guardrail?").
					Description("Intercepts LLM traffic for security scanning. Recommended for production.").
					Value(&result.EnableGuardrail),
				huh.NewConfirm().
					Title("Enable sandbox?").
					Description("Runs agent code in an isolated OpenShell sandbox. Linux only.").
					Value(&result.EnableSandbox),
			),
		)
	}

	if err := step1.Run(); err != nil {
		return nil, fmt.Errorf("wizard: step 1: %w", err)
	}

	// Step 2: Scanners
	step2 := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Step 2 of 5: Scanners").
				Description("Configure how DefenseClaw scans skills, MCPs, and code."),
			huh.NewSelect[string]().
				Title("LLM provider").
				Description("Which LLM provider to use for AI-powered scanning.").
				Options(
					huh.NewOption("OpenAI", "openai"),
					huh.NewOption("Anthropic", "anthropic"),
					huh.NewOption("Azure OpenAI", "azure"),
					huh.NewOption("Local (Ollama)", "ollama"),
				).
				Value(&result.LLMProvider),
			huh.NewInput().
				Title("Model name").
				Description("The model used for scanning (e.g., gpt-4o, claude-sonnet-4-20250514, llama3).").
				Value(&result.LLMModel),
			huh.NewSelect[string]().
				Title("Scanner mode").
				Description("\"local\" scans on-device. \"remote\" uses Cisco AI Defense cloud. \"both\" is recommended.").
				Options(
					huh.NewOption("Local only (works offline)", "local"),
					huh.NewOption("Remote only (Cisco AI Defense)", "remote"),
					huh.NewOption("Both (local + remote, recommended)", "both"),
				).
				Value(&result.ScannerMode),
		),
	)

	if err := step2.Run(); err != nil {
		return nil, fmt.Errorf("wizard: step 2: %w", err)
	}

	// Step 3: Guardrail (conditional)
	if result.EnableGuardrail {
		step3 := huh.NewForm(
			huh.NewGroup(
				huh.NewNote().
					Title("Step 3 of 5: LLM Guardrail").
					Description("Configure the guardrail proxy that intercepts LLM traffic."),
				huh.NewSelect[string]().
					Title("Guardrail mode").
					Description("\"observe\" logs without blocking — good for initial deployment. \"action\" actively blocks.").
					Options(
						huh.NewOption("Observe (log only)", "observe"),
						huh.NewOption("Action (block violations)", "action"),
					).
					Value(&result.GuardrailMode),
			),
		)

		if err := step3.Run(); err != nil {
			return nil, fmt.Errorf("wizard: step 3: %w", err)
		}
	}

	// Step 4: Gateway
	step4 := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Step 4 of 5: Gateway").
				Description("Configure the DefenseClaw gateway sidecar."),
			huh.NewInput().
				Title("Gateway host").
				Description("Hostname for the gateway REST API.").
				Value(&result.GatewayHost),
			huh.NewInput().
				Title("Gateway API port").
				Description("Port for the gateway REST API (default: 9090).").
				Value(&result.GatewayPort),
		),
	)

	if err := step4.Run(); err != nil {
		return nil, fmt.Errorf("wizard: step 4: %w", err)
	}

	// Step 5: Observability
	step5 := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Step 5 of 5: Observability").
				Description("Configure logging and monitoring."),
			huh.NewConfirm().
				Title("Enable Splunk integration?").
				Description("Forward audit events to Splunk via HEC.").
				Value(&result.EnableSplunk),
		),
	)

	if err := step5.Run(); err != nil {
		return nil, fmt.Errorf("wizard: step 5: %w", err)
	}

	if result.EnableSplunk {
		splunkForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Splunk HEC URL").
					Description("e.g., https://localhost:8088").
					Value(&result.SplunkHECURL),
			),
		)

		if err := splunkForm.Run(); err != nil {
			return nil, fmt.Errorf("wizard: splunk: %w", err)
		}
	}

	return result, nil
}

// ApplyWizardResult executes CLI commands to apply the wizard settings.
func ApplyWizardResult(result *WizardResult, executor *CommandExecutor) []string {
	var executed []string

	runCmd := func(name string, args ...string) {
		cmd := exec.Command(name, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
		executed = append(executed, name+" "+strings.Join(args, " "))
	}

	runCmd("defenseclaw", "init", "--data-dir", result.DataDir, "--non-interactive")

	if result.EnableGuardrail {
		runCmd("defenseclaw", "setup", "guardrail",
			"--mode", result.GuardrailMode,
			"--scanner-mode", result.ScannerMode,
			"--non-interactive")
	}

	if result.EnableSplunk && result.SplunkHECURL != "" {
		runCmd("defenseclaw", "setup", "splunk",
			"--hec-url", result.SplunkHECURL,
			"--non-interactive")
	}

	return executed
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "~/.defenseclaw"
	}
	return filepath.Join(home, ".defenseclaw")
}
