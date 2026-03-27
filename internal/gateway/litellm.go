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

package gateway

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// LiteLLMProcess manages the LiteLLM proxy as a child process of the sidecar.
// It starts litellm with the generated config, monitors health, and restarts
// on crash. The guardrail Python module directory is added to PYTHONPATH so
// LiteLLM can import it.
type LiteLLMProcess struct {
	cfg            *config.GuardrailConfig
	ciscoAIDefense *config.CiscoAIDefenseConfig
	logger         *audit.Logger
	health         *SidecarHealth
	apiPort        int
	dataDir        string
}

func NewLiteLLMProcess(cfg *config.GuardrailConfig, aid *config.CiscoAIDefenseConfig, logger *audit.Logger, health *SidecarHealth, apiPort int, dataDir ...string) *LiteLLMProcess {
	p := &LiteLLMProcess{cfg: cfg, ciscoAIDefense: aid, logger: logger, health: health, apiPort: apiPort}
	if len(dataDir) > 0 {
		p.dataDir = dataDir[0]
	}
	return p
}

// Run starts the LiteLLM proxy and keeps it running until ctx is cancelled.
// If the process exits unexpectedly, it is restarted with exponential backoff.
func (l *LiteLLMProcess) Run(ctx context.Context) error {
	if !l.cfg.Enabled {
		l.health.SetGuardrail(StateDisabled, "", nil)
		fmt.Fprintf(os.Stderr, "[guardrail] disabled (enable via: defenseclaw setup guardrail)\n")
		<-ctx.Done()
		return nil
	}

	binary, err := l.findBinary()
	if err != nil {
		l.health.SetGuardrail(StateError, err.Error(), nil)
		fmt.Fprintf(os.Stderr, "[guardrail] %v\n", err)
		<-ctx.Done()
		return err
	}

	if _, err := os.Stat(l.cfg.LiteLLMConfig); os.IsNotExist(err) {
		msg := fmt.Sprintf("litellm config not found: %s (run: defenseclaw setup guardrail)", l.cfg.LiteLLMConfig)
		l.health.SetGuardrail(StateError, msg, nil)
		fmt.Fprintf(os.Stderr, "[guardrail] %s\n", msg)
		<-ctx.Done()
		return fmt.Errorf("guardrail: %s", msg)
	}

	if err := l.verifyProxyExtras(binary); err != nil {
		l.health.SetGuardrail(StateError, err.Error(), nil)
		fmt.Fprintf(os.Stderr, "[guardrail] %v\n", err)
		<-ctx.Done()
		return err
	}

	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		l.health.SetGuardrail(StateStarting, "", map[string]interface{}{
			"port":   l.cfg.Port,
			"mode":   l.cfg.Mode,
			"config": l.cfg.LiteLLMConfig,
		})

		fmt.Fprintf(os.Stderr, "[guardrail] starting LiteLLM (port=%d mode=%s)\n", l.cfg.Port, l.cfg.Mode)
		_ = l.logger.LogAction("guardrail-start", "", fmt.Sprintf("port=%d mode=%s", l.cfg.Port, l.cfg.Mode))

		exitErr := l.runProcess(ctx, binary)

		if ctx.Err() != nil {
			l.health.SetGuardrail(StateStopped, "", nil)
			fmt.Fprintf(os.Stderr, "[guardrail] stopped\n")
			return nil
		}

		errMsg := ""
		if exitErr != nil {
			errMsg = exitErr.Error()
		}
		l.health.SetGuardrail(StateError, fmt.Sprintf("exited: %s", errMsg), nil)
		fmt.Fprintf(os.Stderr, "[guardrail] process exited (%v), restarting in %s...\n", exitErr, backoff)
		_ = l.logger.LogAction("guardrail-crash", "", fmt.Sprintf("exit=%v backoff=%s", exitErr, backoff))

		select {
		case <-ctx.Done():
			l.health.SetGuardrail(StateStopped, "", nil)
			return nil
		case <-time.After(backoff):
		}

		backoff = backoff * 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (l *LiteLLMProcess) runProcess(ctx context.Context, binary string) error {
	args := []string{
		"--config", l.cfg.LiteLLMConfig,
		"--port", fmt.Sprintf("%d", l.cfg.Port),
		"--detailed_debug",
	}

	cmd := exec.CommandContext(ctx, binary, args...)

	cmd.Env = l.buildEnv()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("guardrail: stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("guardrail: stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("guardrail: start: %w", err)
	}

	go l.streamLog("litellm:out", stdout)
	go l.streamLog("litellm:err", stderr)

	// Wait for LiteLLM to become healthy
	go l.waitForHealthy(ctx)

	return cmd.Wait()
}

func (l *LiteLLMProcess) buildEnv() []string {
	env := os.Environ()

	// Load ~/.defenseclaw/.env for daemon contexts where the user's
	// shell environment (and its API keys) aren't inherited.
	envFile := filepath.Join(filepath.Dir(l.cfg.LiteLLMConfig), ".env")
	if dotenv, err := loadDotEnv(envFile); err == nil {
		present := make(map[string]bool, len(env))
		for _, e := range env {
			if k, _, ok := strings.Cut(e, "="); ok {
				present[k] = true
			}
		}
		for k, v := range dotenv {
			if !present[k] {
				env = append(env, k+"="+v)
			}
		}
	}

	pythonPath := l.cfg.GuardrailDir
	for _, e := range env {
		if strings.HasPrefix(e, "PYTHONPATH=") {
			existing := strings.TrimPrefix(e, "PYTHONPATH=")
			pythonPath = l.cfg.GuardrailDir + string(filepath.ListSeparator) + existing
			break
		}
	}

	// Vars we set explicitly — filter out any inherited copies to avoid
	// duplicates (last-writer-wins is OS-dependent).
	overridden := map[string]bool{
		"PYTHONPATH":                  true,
		"DEFENSECLAW_GUARDRAIL_MODE":  true,
		"DEFENSECLAW_SCANNER_MODE":    true,
		"DEFENSECLAW_API_PORT":        true,
		"DEFENSECLAW_DATA_DIR":        true,
		"LITELLM_MASTER_KEY":          true,
	}
	filtered := make([]string, 0, len(env)+6)
	for _, e := range env {
		if k, _, ok := strings.Cut(e, "="); ok && overridden[k] {
			continue
		}
		filtered = append(filtered, e)
	}
	filtered = append(filtered, "PYTHONPATH="+pythonPath)
	filtered = append(filtered, "DEFENSECLAW_GUARDRAIL_MODE="+l.cfg.Mode)
	if l.cfg.ScannerMode != "" {
		filtered = append(filtered, "DEFENSECLAW_SCANNER_MODE="+l.cfg.ScannerMode)
	}
	if l.apiPort > 0 {
		filtered = append(filtered, fmt.Sprintf("DEFENSECLAW_API_PORT=%d", l.apiPort))
	}
	if l.dataDir != "" {
		filtered = append(filtered, "DEFENSECLAW_DATA_DIR="+l.dataDir)
	}

	if mk := l.deriveMasterKey(); mk != "" {
		filtered = append(filtered, "LITELLM_MASTER_KEY="+mk)
	}

	if l.cfg.ScannerMode == "remote" || l.cfg.ScannerMode == "both" {
		aid := l.ciscoAIDefense
		if aid != nil {
			if aid.Endpoint != "" {
				filtered = append(filtered, "CISCO_AI_DEFENSE_ENDPOINT="+aid.Endpoint)
			}
			if aid.APIKeyEnv != "" {
				filtered = append(filtered, "CISCO_AI_DEFENSE_API_KEY_ENV="+aid.APIKeyEnv)
			}
			if aid.TimeoutMs > 0 {
				filtered = append(filtered, fmt.Sprintf("CISCO_AI_DEFENSE_TIMEOUT_MS=%d", aid.TimeoutMs))
			}
			if len(aid.EnabledRules) > 0 {
				filtered = append(filtered, "CISCO_AI_DEFENSE_ENABLED_RULES="+strings.Join(aid.EnabledRules, ","))
			}
		}
	}

	return filtered
}

// sensitiveJSONKeys are quoted JSON field names that carry user/assistant
// message payloads. We match these rather than bare substrings to avoid
// false-positive redaction of operational log fields like content-type,
// content-length, prompt_tokens, and completion_tokens.
var sensitiveJSONKeys = []string{
	`"content"`,
	`"messages"`,
	`"message"`,
	`"prompt"`,
}

func containsSensitivePayload(line string) bool {
	lower := strings.ToLower(line)
	for _, key := range sensitiveJSONKeys {
		if strings.Contains(lower, key) {
			return true
		}
	}
	return false
}

func (l *LiteLLMProcess) streamLog(prefix string, r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if containsSensitivePayload(line) {
			fmt.Fprintf(os.Stderr, "[%s] (redacted: %d chars)\n", prefix, len(line))
		} else {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", prefix, line)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] read error: %v\n", prefix, err)
	}
}

func (l *LiteLLMProcess) waitForHealthy(ctx context.Context) {
	client := &http.Client{Timeout: 2 * time.Second}
	addr := fmt.Sprintf("http://127.0.0.1:%d/health/liveliness", l.cfg.Port)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	deadline := time.After(30 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			l.health.SetGuardrail(StateError, "health check timed out after 30s", nil)
			fmt.Fprintf(os.Stderr, "[guardrail] health check timed out\n")
			return
		case <-ticker.C:
			resp, err := client.Get(addr)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				l.health.SetGuardrail(StateRunning, "", map[string]interface{}{
					"port": l.cfg.Port,
					"mode": l.cfg.Mode,
				})
				fmt.Fprintf(os.Stderr, "[guardrail] LiteLLM healthy on port %d\n", l.cfg.Port)
				_ = l.logger.LogAction("guardrail-healthy", "", fmt.Sprintf("port=%d", l.cfg.Port))
				return
			}
		}
	}
}

// verifyProxyExtras checks that litellm[proxy] extras (backoff, etc.) are
// importable by the Python that runs the litellm binary. Without this check
// the sidecar enters a crash-restart loop with a confusing "bad handshake"
// error. The fix is: pip install 'litellm[proxy]'
func (l *LiteLLMProcess) verifyProxyExtras(binary string) error {
	pythonBin := l.resolvePython(binary)
	if pythonBin == "" {
		return nil // can't determine Python — skip check, let litellm fail naturally
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, pythonBin, "-c", "import backoff")
	cmd.Env = l.buildEnv()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("litellm[proxy] extras not installed (missing 'backoff' module) — run: pip install 'litellm[proxy]'")
	}
	return nil
}

// resolvePython reads the shebang of the litellm entry-point script to find
// which Python interpreter it uses, so we can check imports against the
// correct environment.
//
// Handles two common pip entry-point formats:
//   1. Direct:   #!/path/to/python  (or #!/usr/bin/env python3)
//   2. Polyglot: #!/bin/sh on line 1, then '''exec' '/path/to/python' ...
//      on line 2 (used by newer setuptools/pip).
func (l *LiteLLMProcess) resolvePython(binary string) string {
	f, err := os.Open(binary)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return ""
	}
	line := scanner.Text()
	if !strings.HasPrefix(line, "#!") {
		return ""
	}

	shebang := strings.TrimSpace(strings.TrimPrefix(line, "#!"))
	parts := strings.Fields(shebang)
	last := ""
	if len(parts) > 0 {
		last = parts[len(parts)-1]
	}

	if last != "sh" && last != "/bin/sh" && last != "/usr/bin/env" {
		return last
	}

	// Polyglot wrapper: line 2 looks like  '''exec' '/path/to/python' "$0" "$@"
	// Extract all single-quoted tokens and return the first absolute path.
	if scanner.Scan() {
		line2 := scanner.Text()
		if strings.Contains(line2, "exec") {
			for _, p := range extractSingleQuoted(line2) {
				if strings.HasPrefix(p, "/") {
					return p
				}
			}
		}
	}
	return ""
}

// extractSingleQuoted returns all non-empty single-quoted strings from s.
func extractSingleQuoted(s string) []string {
	var out []string
	for {
		start := strings.IndexByte(s, '\'')
		if start < 0 {
			break
		}
		s = s[start+1:]
		end := strings.IndexByte(s, '\'')
		if end < 0 {
			break
		}
		if end > 0 {
			out = append(out, s[:end])
		}
		s = s[end+1:]
	}
	return out
}

func (l *LiteLLMProcess) findBinary() (string, error) {
	path, err := exec.LookPath("litellm")
	if err == nil {
		return path, nil
	}

	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".local", "bin", "litellm"),
		filepath.Join(home, ".cargo", "bin", "litellm"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	return "", fmt.Errorf("litellm binary not found — install with: uv tool install 'litellm[proxy]'")
}

// deriveMasterKey produces a deterministic master key from the device key
// file, matching the Python _derive_master_key() in guardrail.py.
// The key is passed as LITELLM_MASTER_KEY so LiteLLM accepts it without
// requiring a database for virtual key validation.
func (l *LiteLLMProcess) deriveMasterKey() string {
	keyFile := filepath.Join(l.dataDir, "device.key")
	if l.dataDir == "" {
		keyFile = filepath.Join(l.cfg.GuardrailDir, "device.key")
	}
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, []byte("defenseclaw-litellm-master-key"))
	mac.Write(data)
	digest := fmt.Sprintf("%x", mac.Sum(nil))
	if len(digest) > 32 {
		digest = digest[:32]
	}
	return "sk-dc-" + digest
}

// loadDotEnv reads a KEY=VALUE file (one per line).  Blank lines and
// lines starting with # are ignored.  Values may be optionally quoted.
// This lets the sidecar pick up API keys when running as a daemon
// (where the user's shell env isn't inherited).
func loadDotEnv(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		if k != "" {
			out[k] = v
		}
	}
	return out, nil
}
