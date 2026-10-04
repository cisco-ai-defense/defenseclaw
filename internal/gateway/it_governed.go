// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// ITGovernedProvisioner auto-configures the Hermes agent with a hardened
// Docker sandbox, DefenseClaw hooks, and sandbox-escape guardrail rules
// when deployment_mode=it_governed.
type ITGovernedProvisioner struct {
	cfg     *config.Config
	dataDir string
}

func NewITGovernedProvisioner(cfg *config.Config) *ITGovernedProvisioner {
	return &ITGovernedProvisioner{cfg: cfg, dataDir: cfg.DataDir}
}

// Provision runs the full IT Governed setup. It is idempotent — safe to
// call on every gateway start.
func (p *ITGovernedProvisioner) Provision() error {
	if !p.cfg.IsITGoverned() {
		return nil
	}

	if !isHermesInstalled() {
		fmt.Fprintf(os.Stderr, "[it-governed] Hermes not installed — installing...\n")
		if err := installHermes(); err != nil {
			return fmt.Errorf("it_governed: install hermes: %w", err)
		}
	}

	hermesHome := hermesHomePath()
	if hermesHome == "" {
		return fmt.Errorf("it_governed: cannot locate Hermes home directory after install")
	}

	fmt.Fprintf(os.Stderr, "[it-governed] provisioning hardened Hermes sandbox\n")

	if err := p.writeHermesSandboxConfig(hermesHome); err != nil {
		return fmt.Errorf("it_governed: write hermes config: %w", err)
	}

	// Hooks are written by the gateway's connector setup (guardrail --connector hermes).
	// The provisioner only sets hooks_auto_accept and the hardened terminal config.

	if err := p.writeSandboxEscapeRules(); err != nil {
		return fmt.Errorf("it_governed: write sandbox-escape rules: %w", err)
	}

	if err := p.ensureHermesProvider(hermesHome); err != nil {
		return fmt.Errorf("it_governed: configure provider: %w", err)
	}

	// Config locking is deferred until after the gateway's connector setup
	// writes hooks into ~/.hermes/config.yaml. Lock manually after gateway
	// start with: sudo bash ~/.defenseclaw/lock-sandbox.sh

	fmt.Fprintf(os.Stderr, "[it-governed] Hermes sandbox provisioned successfully\n")
	return nil
}

func (p *ITGovernedProvisioner) writeHermesSandboxConfig(hermesHome string) error {
	configPath := filepath.Join(hermesHome, "config.yaml")

	// Read existing config, patch terminal section
	existing, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// Build the hardened terminal config block
	terminalBlock := `terminal:
  backend: docker
  docker_image: nikolaik/python-nodejs:python3.11-nodejs20
  container_cpu: 2
  container_disk: 10240
  container_memory: 4096
  container_persistent: false
  cwd: /workspace
  docker_mount_cwd_to_workspace: false
  docker_network: false
  docker_volumes: []
  docker_forward_env: []
  docker_env: {}
  docker_run_as_host_user: false
  docker_extra_args:
    - "--cap-drop=ALL"
    - "--security-opt=no-new-privileges"
    - "--pids-limit=256"
  docker_shm_size: 256m
  docker_persist_across_processes: false
  docker_orphan_reaper: true
  docker_snap_compat: false
  home_mode: tmpfs
  lifetime_seconds: 300
  timeout: 120
`
	content := string(existing)

	// Replace or append terminal section
	if strings.Contains(content, "terminal:") {
		// Find and replace the terminal: block
		lines := strings.Split(content, "\n")
		var out []string
		inTerminal := false
		replaced := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			indent := len(line) - len(strings.TrimLeft(line, " "))
			if trimmed == "terminal:" && indent == 0 {
				inTerminal = true
				if !replaced {
					out = append(out, terminalBlock)
					replaced = true
				}
				continue
			}
			if inTerminal {
				if indent == 0 && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
					inTerminal = false
					out = append(out, line)
				}
				continue
			}
			out = append(out, line)
		}
		content = strings.Join(out, "\n")
	} else {
		content += "\n" + terminalBlock
	}

	return safefile.Write(configPath, []byte(content))
}

func (p *ITGovernedProvisioner) writeHermesHooks(hermesHome string) error {
	hookScript := filepath.Join(p.dataDir, "hooks", "hermes-hook.sh")
	if _, err := os.Stat(hookScript); os.IsNotExist(err) {
		return fmt.Errorf("hermes hook script not found at %s — run 'defenseclaw setup guardrail --connector hermes' first", hookScript)
	}

	configPath := filepath.Join(hermesHome, "config.yaml")
	existing, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	content := string(existing)

	// Only add hooks if not already present
	if !strings.Contains(content, "hermes-hook.sh") {
		hooksBlock := fmt.Sprintf(`hooks:
  PreToolUse:
    - command: "%s --event PreToolUse --hook-contract hermes-hooks-v1"
      timeout: 10
  PostToolUse:
    - command: "%s --event PostToolUse --hook-contract hermes-hooks-v1"
      timeout: 10
  UserPromptSubmit:
    - command: "%s --event UserPromptSubmit --hook-contract hermes-hooks-v1"
      timeout: 10
  SessionStart:
    - command: "%s --event SessionStart --hook-contract hermes-hooks-v1"
      timeout: 10
  Stop:
    - command: "%s --event Stop --hook-contract hermes-hooks-v1"
      timeout: 10
hooks_auto_accept: true
`, hookScript, hookScript, hookScript, hookScript, hookScript)

		// Replace or append hooks section
		if strings.Contains(content, "hooks:") {
			lines := strings.Split(content, "\n")
			var out []string
			inHooks := false
			replaced := false
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				indent := len(line) - len(strings.TrimLeft(line, " "))
				if (trimmed == "hooks:" || trimmed == "hooks: {}") && indent == 0 {
					inHooks = true
					if !replaced {
						out = append(out, hooksBlock)
						replaced = true
					}
					continue
				}
				if trimmed == "hooks_auto_accept: true" || trimmed == "hooks_auto_accept: false" {
					continue
				}
				if inHooks {
					if indent == 0 && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
						inHooks = false
						out = append(out, line)
					}
					continue
				}
				out = append(out, line)
			}
			content = strings.Join(out, "\n")
		} else {
			content += "\n" + hooksBlock
		}

		return safefile.Write(configPath, []byte(content))
	}

	return nil
}

func (p *ITGovernedProvisioner) writeSandboxEscapeRules() error {
	rulesDir := filepath.Join(p.dataDir, "policies", "guardrail", "default", "rules")
	os.MkdirAll(rulesDir, 0o700)

	rulesPath := filepath.Join(rulesDir, "sandbox-escape.yaml")
	if _, err := os.Stat(rulesPath); err == nil {
		return nil // already exists
	}

	rules := `version: 1
category: sandbox-escape
rules:
  - id: SANDBOX-CONFIG-TAMPER
    pattern: '(?i)(?:\.hermes/config\.yaml|hermes\s+config\s+(?:set|edit|unset)|TERMINAL_ENV\s*=|TERMINAL_DOCKER_MOUNT|TERMINAL_DOCKER_NETWORK|docker_mount_cwd|docker_network|docker_volumes|backend\s*:\s*local)'
    title: "Hermes sandbox config tampering"
    severity: CRITICAL
    confidence: 0.95
    tags: [sandbox-escape, config-tamper]
  - id: SANDBOX-DOCKER-ESCAPE
    pattern: '(?i)(?:docker\s+(?:run|exec|cp|mount|volume)|--privileged|--cap-add|--security-opt|--pid\s*=\s*host|--network\s*=\s*host|--mount\s+type=bind|nsenter\b|chroot\b|unshare\b)'
    title: "Docker container escape attempt"
    severity: CRITICAL
    confidence: 0.92
    tags: [sandbox-escape, container-escape]
  - id: SANDBOX-ENV-OVERRIDE
    pattern: '(?i)(?:export\s+TERMINAL_(?:ENV|DOCKER_MOUNT|DOCKER_NETWORK|DOCKER_VOLUMES)|HERMES_HOME\s*=|DEFENSECLAW_HOME\s*=|\.hermes/\.env)'
    title: "Sandbox environment variable override"
    severity: CRITICAL
    confidence: 0.93
    tags: [sandbox-escape, env-tamper]
  - id: SANDBOX-DEFENSECLAW-TAMPER
    pattern: '(?i)(?:\.defenseclaw/config\.yaml|\.defenseclaw/hooks/|\.defenseclaw/policies/|defenseclaw\s+setup\s+guardrail\s+--disable)'
    title: "DefenseClaw guardrail config tampering"
    severity: CRITICAL
    confidence: 0.95
    tags: [sandbox-escape, guardrail-tamper]
  - id: SANDBOX-CHFLAGS-REMOVE
    pattern: '(?i)(?:chflags\s+(?:nouchg|noschg)|xattr\s+-d\s+com\.apple)'
    title: "File immutability flag removal"
    severity: CRITICAL
    confidence: 0.95
    tags: [sandbox-escape, privilege]
`
	return safefile.Write(rulesPath, []byte(rules))
}

func (p *ITGovernedProvisioner) ensureHermesProvider(hermesHome string) error {
	configPath := filepath.Join(hermesHome, "config.yaml")
	existing, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	content := string(existing)
	if strings.Contains(content, "defenseclaw") && strings.Contains(content, "127.0.0.1:4001") {
		return nil // already configured
	}

	gatewayToken := os.Getenv("DEFENSECLAW_GATEWAY_TOKEN")
	if gatewayToken == "" {
		return fmt.Errorf("DEFENSECLAW_GATEWAY_TOKEN not set — cannot configure Hermes provider")
	}

	providerBlock := fmt.Sprintf(`providers:
  defenseclaw:
    name: defenseclaw
    base_url: "http://127.0.0.1:4001/v1"
    api_key: "%s"
    api_mode: responses
model:
  default: default
  provider: defenseclaw
  api_mode: responses
`, gatewayToken)

	// Replace or append model + providers sections
	if strings.Contains(content, "model:") {
		lines := strings.Split(content, "\n")
		var out []string
		inModel := false
		inProviders := false
		addedProvider := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			indent := len(line) - len(strings.TrimLeft(line, " "))
			if trimmed == "model:" && indent == 0 {
				inModel = true
				if !addedProvider {
					out = append(out, providerBlock)
					addedProvider = true
				}
				continue
			}
			if trimmed == "providers:" && indent == 0 {
				inProviders = true
				continue
			}
			if inModel || inProviders {
				if indent == 0 && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
					inModel = false
					inProviders = false
					out = append(out, line)
				}
				continue
			}
			out = append(out, line)
		}
		content = strings.Join(out, "\n")
	} else {
		content += "\n" + providerBlock
	}

	return safefile.Write(configPath, []byte(content))
}

func (p *ITGovernedProvisioner) lockConfigs(hermesHome string) error {
	targets := []string{
		filepath.Join(hermesHome, "config.yaml"),
		filepath.Join(p.dataDir, "config.yaml"),
		filepath.Join(p.dataDir, "policies", "guardrail", "default", "rules", "sandbox-escape.yaml"),
		filepath.Join(p.dataDir, "hooks", "hermes-hook.sh"),
	}

	for _, path := range targets {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := exec.Command("chflags", "uchg", path).Run(); err != nil {
			return fmt.Errorf("chflags uchg %s: %w", path, err)
		}
	}
	return nil
}

func hermesHomePath() string {
	if v := os.Getenv("HERMES_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	p := filepath.Join(home, ".hermes")
	if info, err := os.Stat(p); err == nil && info.IsDir() {
		return p
	}
	// Create it for fresh installs
	if os.MkdirAll(p, 0o700) == nil {
		return p
	}
	return ""
}

func isHermesInstalled() bool {
	_, err := exec.LookPath("hermes")
	return err == nil
}

func resolveHermesBinary() string {
	if p, err := exec.LookPath("hermes"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	for _, path := range []string{
		filepath.Join(home, ".local", "bin", "hermes"),
		"/usr/local/bin/hermes",
		"/opt/homebrew/bin/hermes",
	} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

const hermesServePort = 9119
const hermesSessionToken = "myagent-defenseclaw-session-2026"

// HermesServeManager manages a hermes serve child process.
type HermesServeManager struct {
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	stopped bool
}

func startManagedHermesServe(ctx context.Context, binaryPath string, dataDir string) *HermesServeManager {
	childCtx, cancel := context.WithCancel(ctx)

	cmd := exec.CommandContext(childCtx, binaryPath, "serve",
		"--port", fmt.Sprintf("%d", hermesServePort),
		"--host", "127.0.0.1",
	)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HERMES_DASHBOARD_SESSION_TOKEN=%s", hermesSessionToken),
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[it-governed] hermes serve failed to start: %v\n", err)
		cancel()
		return nil
	}

	fmt.Fprintf(os.Stderr, "[it-governed] hermes serve started on port %d (pid %d)\n", hermesServePort, cmd.Process.Pid)

	mgr := &HermesServeManager{cmd: cmd, cancel: cancel}

	go func() {
		err := cmd.Wait()
		if !mgr.stopped {
			fmt.Fprintf(os.Stderr, "[it-governed] hermes serve exited unexpectedly: %v\n", err)
		}
	}()

	return mgr
}

func (m *HermesServeManager) Stop() {
	m.stopped = true
	if m.cancel != nil {
		m.cancel()
	}
	if m.cmd != nil && m.cmd.Process != nil {
		m.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { m.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			m.cmd.Process.Kill()
		}
	}
	fmt.Fprintf(os.Stderr, "[it-governed] hermes serve stopped\n")
}

const hermesRepoURL = "https://github.com/NousResearch/hermes-agent.git"

func installHermes() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	hermesHome := filepath.Join(home, ".hermes")
	agentDir := filepath.Join(hermesHome, "hermes-agent")
	binDir := filepath.Join(home, ".local", "bin")

	os.MkdirAll(hermesHome, 0o700)
	os.MkdirAll(binDir, 0o755)

	// Clone the hermes-agent repo if not present
	if _, err := os.Stat(filepath.Join(agentDir, "cli.py")); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "[it-governed] cloning hermes-agent from %s\n", hermesRepoURL)
		cmd := exec.Command("git", "clone", "--depth=1", hermesRepoURL, agentDir)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git clone hermes-agent: %w", err)
		}
	}

	// Set up Python venv and install dependencies
	venvDir := filepath.Join(agentDir, "venv")
	if _, err := os.Stat(venvDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "[it-governed] creating Python venv for Hermes\n")
		python := findPython()
		if python == "" {
			return fmt.Errorf("python3 not found — required for Hermes")
		}
		cmd := exec.Command(python, "-m", "venv", venvDir)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("create venv: %w", err)
		}

		// Install requirements
		pip := filepath.Join(venvDir, "bin", "pip")
		reqFile := filepath.Join(agentDir, "requirements.txt")
		if _, err := os.Stat(reqFile); err == nil {
			fmt.Fprintf(os.Stderr, "[it-governed] installing Hermes dependencies\n")
			cmd = exec.Command(pip, "install", "-r", reqFile)
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("pip install requirements: %w", err)
			}
		}
	}

	// Create launcher script at ~/.local/bin/hermes
	launcher := filepath.Join(binDir, "hermes")
	launcherContent := fmt.Sprintf(`#!/bin/bash
exec "%s/bin/python" "%s/cli.py" "$@"
`, venvDir, agentDir)
	if err := os.WriteFile(launcher, []byte(launcherContent), 0o755); err != nil {
		return fmt.Errorf("write hermes launcher: %w", err)
	}

	// Create default config.yaml if missing
	configPath := filepath.Join(hermesHome, "config.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		defaultConfig := "_config_version: 44\nagent:\n    max_turns: 150\n    reasoning_effort: high\n    verbose: false\n"
		if err := os.WriteFile(configPath, []byte(defaultConfig), 0o600); err != nil {
			return fmt.Errorf("write default config: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "[it-governed] Hermes installed at %s\n", launcher)
	return nil
}

func findPython() string {
	for _, name := range []string{"python3.12", "python3.11", "python3"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}
