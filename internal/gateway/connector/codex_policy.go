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

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const (
	codexPolicyInspectionTimeout = 20 * time.Second
	codexPolicyMessageLimit      = 2 << 20
)

// codexEffectivePolicy is intentionally narrow. DefenseClaw does not try to
// reimplement Codex's layered requirements merger: when a selected Codex
// executable is available, configRequirements/read is the authority for
// system, cloud, legacy managed-config, and MDM composition.
type codexEffectivePolicy struct {
	AllowManagedHooksOnly *bool
	Source                string
}

// codexPolicyInspector is replaceable only by package tests. Production uses
// the selected Codex binary and its stable app-server RPC.
var codexPolicyInspector = inspectCodexEffectivePolicy

var codexSystemRequirementsPathForInspection = codexSystemRequirementsPath

var codexAppServerCommand = func(ctx context.Context, executable string) *exec.Cmd {
	return newCodexAppServerCommand(ctx, executable)
}

// enforceCodexUserHookPolicy prevents Setup from reporting success when Codex
// will ignore the user-level hook table we are about to write. Managed-only
// fleets must deploy DefenseClaw through their administrator-owned managed hook
// source; silently bypassing that policy would be both ineffective and unsafe.
func enforceCodexUserHookPolicy(ctx context.Context, opts SetupOpts) error {
	policy, err := codexPolicyInspector(ctx, opts)
	if err != nil {
		return fmt.Errorf("inspect effective Codex managed requirements: %w", err)
	}
	if policy.AllowManagedHooksOnly != nil && *policy.AllowManagedHooksOnly {
		return fmt.Errorf(
			"Codex user hooks are prohibited by allow_managed_hooks_only from %s; deploy the DefenseClaw hook through the administrator-managed Codex requirements source",
			policy.Source,
		)
	}
	return nil
}

func inspectCodexEffectivePolicy(ctx context.Context, opts SetupOpts) (codexEffectivePolicy, error) {
	executable := strings.TrimSpace(opts.AgentExecutable)
	if executable != "" {
		if runtime.GOOS == "windows" {
			validated, err := validateCodexPolicyExecutable(opts)
			if err != nil {
				return codexEffectivePolicy{}, err
			}
			executable = validated
		} else {
			// Preserve the established macOS/Linux discovery contract. Those
			// installers do not create the Windows-only protected selection
			// receipt, but the executable must still be an absolute clean path.
			if strings.ContainsAny(executable, "\x00\r\n") || !filepath.IsAbs(executable) {
				return codexEffectivePolicy{}, fmt.Errorf("selected Codex executable is not absolute: %q", executable)
			}
			executable = filepath.Clean(executable)
		}
		policy, err := inspectCodexPolicyWithAppServer(ctx, executable, codexHomeDir())
		if err != nil {
			return codexEffectivePolicy{}, fmt.Errorf("%s configRequirements/read: %w", executable, err)
		}
		return policy, nil
	}

	if runtime.GOOS == "windows" {
		if _, exists := loadProtectedCodexContractEntry(opts.DataDir); exists {
			return codexEffectivePolicy{}, errors.New(
				"Codex hook contract is missing valid setup-selected executable evidence; run connector repair",
			)
		}
		if path := filepath.Join(opts.DataDir, agentSelectionFile); strings.TrimSpace(opts.DataDir) != "" {
			if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
				return codexEffectivePolicy{}, errors.New(
					"Codex setup selection receipt is invalid or expired; rerun fresh trusted setup discovery",
				)
			}
		}

		// A native Windows registration is executable-specific: setup must first
		// select, hash, and protect the exact codex.exe that will own the hook
		// contract. Falling back to a generic system-requirements read here would
		// let Setup publish a lock with no executable evidence, which the next
		// reconcile must correctly reject. Refuse before any registration mutation.
		return codexEffectivePolicy{}, errors.New(
			"Codex policy inspection requires a fresh setup-selected native executable; rerun trusted connector setup or repair",
		)
	}

	// Tests, pre-provisioning, and older non-Windows Codex installs may not have
	// a runnable app-server path. In that case still honor the documented system
	// source. This fallback deliberately does not claim to inspect cloud policy.
	return inspectCodexSystemRequirements()
}

func validateCodexPolicyExecutable(opts SetupOpts) (string, error) {
	executable := strings.TrimSpace(opts.AgentExecutable)
	if strings.ContainsAny(executable, "\x00\r\n") || !filepath.IsAbs(executable) {
		return "", fmt.Errorf("selected Codex executable is not absolute: %q", executable)
	}
	executable = filepath.Clean(executable)
	name := strings.ToLower(filepath.Base(executable))
	extension := strings.ToLower(filepath.Ext(name))
	product := strings.TrimSuffix(name, extension)
	if product != "codex" {
		return "", fmt.Errorf("selected Codex executable has unexpected product name: %s", executable)
	}
	if runtime.GOOS == "windows" {
		if extension != ".exe" {
			return "", fmt.Errorf(
				"selected Codex policy executable is not a native Windows .exe image: %s",
				executable,
			)
		}
	}

	expectedPath := ""
	expectedVersion := ""
	expectedDigest := ""
	if entry, exists := loadProtectedCodexContractEntry(opts.DataDir); exists {
		if !validCodexAgentExecutableEvidence(entry) {
			return "", errors.New("Codex hook contract has invalid setup-selected executable evidence")
		}
		expectedPath = entry.AgentExecutable
		expectedVersion = entry.RawAgentVersion
		expectedDigest = entry.AgentExecutableSHA256
	} else if selection, ok := loadSetupAgentSelection(opts.DataDir, "codex"); ok {
		expectedPath = selection.Executable
		expectedVersion = selection.RawVersion
		expectedDigest = selection.SHA256
	} else {
		return "", errors.New("Codex policy inspection requires protected setup-selected executable evidence")
	}
	if !sameCodexExecutablePath(executable, expectedPath) {
		return "", fmt.Errorf("selected Codex executable does not match protected evidence: %s", executable)
	}
	if strings.TrimSpace(opts.AgentVersion) != strings.TrimSpace(expectedVersion) {
		return "", errors.New("selected Codex executable evidence is bound to a different agent version")
	}

	info, err := os.Lstat(executable)
	if err != nil {
		return "", fmt.Errorf("inspect selected Codex executable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("selected Codex executable is not a regular non-link file: %s", executable)
	}
	if err := hookAPIValidateDirectory(filepath.Dir(executable)); err != nil {
		return "", fmt.Errorf("validate selected Codex executable ancestry: %w", err)
	}
	if err := hookAPIValidateOwner(executable, info); err != nil {
		return "", fmt.Errorf("validate selected Codex executable ACL: %w", err)
	}
	stablePath, digest, ok := setupSelectedAgentExecutableEvidence(executable)
	if !ok || !sameCodexExecutablePath(stablePath, executable) {
		return "", fmt.Errorf("selected Codex executable changed during validation: %s", executable)
	}
	if digest != expectedDigest {
		return "", fmt.Errorf("selected Codex executable digest does not match protected evidence: %s", executable)
	}
	return executable, nil
}

func sameCodexExecutablePath(left, right string) bool {
	left = filepath.Clean(strings.TrimSpace(left))
	right = filepath.Clean(strings.TrimSpace(right))
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func inspectCodexSystemRequirements() (codexEffectivePolicy, error) {
	path, err := codexSystemRequirementsPathForInspection()
	if err != nil {
		return codexEffectivePolicy{}, fmt.Errorf("resolve Codex system requirements path: %w", err)
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return codexEffectivePolicy{Source: path}, nil
	}
	if err != nil {
		return codexEffectivePolicy{}, fmt.Errorf("read %s: %w", path, err)
	}
	if len(raw) > codexPolicyMessageLimit {
		return codexEffectivePolicy{}, fmt.Errorf("%s exceeds %d bytes", path, codexPolicyMessageLimit)
	}
	var requirements struct {
		AllowManagedHooksOnly *bool `toml:"allow_managed_hooks_only"`
	}
	if err := toml.Unmarshal(raw, &requirements); err != nil {
		return codexEffectivePolicy{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return codexEffectivePolicy{
		AllowManagedHooksOnly: requirements.AllowManagedHooksOnly,
		Source:                path,
	}, nil
}

type codexRPCEnvelope struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type codexRequirementsReadResult struct {
	Requirements *struct {
		AllowManagedHooksOnly *bool `json:"allowManagedHooksOnly"`
	} `json:"requirements"`
}

type codexRPCEvent struct {
	Envelope codexRPCEnvelope
	Err      error
}

func inspectCodexPolicyWithAppServer(parent context.Context, executable, codexHome string) (policy codexEffectivePolicy, retErr error) {
	ctx, cancel := context.WithTimeout(parent, codexPolicyInspectionTimeout)
	defer cancel()

	cmd := codexAppServerCommand(ctx, executable)
	baseEnv := cmd.Env
	if baseEnv == nil {
		baseEnv = os.Environ()
	}
	cmd.Env = replaceProcessEnv(baseEnv, "CODEX_HOME", codexHome)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return policy, fmt.Errorf("open stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return policy, fmt.Errorf("open stdout: %w", err)
	}
	stderr := &boundedDiagnosticBuffer{limit: 64 << 10}
	cmd.Stderr = stderr
	cleanup, err := startCodexAppServerTree(cmd)
	if err != nil {
		return policy, fmt.Errorf("start app-server: %w", err)
	}
	defer func() {
		_ = stdin.Close()
		cleanup()
	}()

	events := make(chan codexRPCEvent, 3)
	go decodeCodexRPC(stdout, events)

	encoder := json.NewEncoder(stdin)
	if err := encoder.Encode(map[string]any{
		"method": "initialize",
		"id":     1,
		"params": map[string]any{
			"clientInfo": map[string]string{
				"name":    "defenseclaw",
				"title":   "DefenseClaw",
				"version": "1",
			},
		},
	}); err != nil {
		return policy, fmt.Errorf("send initialize: %w", err)
	}
	if _, err := waitCodexRPC(ctx, events, 1); err != nil {
		return policy, withCodexStderr(err, stderr.String())
	}
	if err := encoder.Encode(map[string]any{"method": "initialized"}); err != nil {
		return policy, fmt.Errorf("send initialized: %w", err)
	}
	if err := encoder.Encode(map[string]any{
		"method": "configRequirements/read",
		"id":     2,
		"params": map[string]any{},
	}); err != nil {
		return policy, fmt.Errorf("send configRequirements/read: %w", err)
	}
	envelope, err := waitCodexRPC(ctx, events, 2)
	if err != nil {
		return policy, withCodexStderr(err, stderr.String())
	}
	var result codexRequirementsReadResult
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return policy, fmt.Errorf("decode configRequirements/read result: %w", err)
	}
	policy.Source = fmt.Sprintf("Codex app-server %s effective requirements", executable)
	if result.Requirements != nil {
		policy.AllowManagedHooksOnly = result.Requirements.AllowManagedHooksOnly
	}
	return policy, nil
}

func decodeCodexRPC(reader io.Reader, events chan<- codexRPCEvent) {
	defer close(events)
	limited := &io.LimitedReader{R: reader, N: codexPolicyMessageLimit + 1}
	decoder := json.NewDecoder(limited)
	seen := map[int]bool{}
	for {
		var envelope codexRPCEnvelope
		if err := decoder.Decode(&envelope); err != nil {
			if limited.N <= 0 {
				err = fmt.Errorf("app-server response exceeds %d bytes", codexPolicyMessageLimit)
			}
			events <- codexRPCEvent{Err: err}
			return
		}
		var id int
		if err := json.Unmarshal(envelope.ID, &id); err != nil || (id != 1 && id != 2) || seen[id] {
			continue
		}
		seen[id] = true
		events <- codexRPCEvent{Envelope: envelope}
	}
}

func waitCodexRPC(
	ctx context.Context,
	events <-chan codexRPCEvent,
	wantID int,
) (codexRPCEnvelope, error) {
	for {
		select {
		case <-ctx.Done():
			return codexRPCEnvelope{}, fmt.Errorf("timed out waiting for response %d: %w", wantID, ctx.Err())
		case event, ok := <-events:
			if !ok {
				return codexRPCEnvelope{}, errors.New("app-server response stream closed")
			}
			if event.Err != nil {
				return codexRPCEnvelope{}, fmt.Errorf("read app-server response: %w", event.Err)
			}
			envelope := event.Envelope
			var id int
			if err := json.Unmarshal(envelope.ID, &id); err != nil {
				return codexRPCEnvelope{}, fmt.Errorf("decode app-server response id: %w", err)
			}
			if id != wantID {
				return codexRPCEnvelope{}, fmt.Errorf("received app-server response %d while waiting for %d", id, wantID)
			}
			if envelope.Error != nil {
				return codexRPCEnvelope{}, fmt.Errorf(
					"RPC %d failed (%d): %s",
					wantID,
					envelope.Error.Code,
					envelope.Error.Message,
				)
			}
			if len(envelope.Result) == 0 {
				return codexRPCEnvelope{}, fmt.Errorf("RPC %d returned no result", wantID)
			}
			return envelope, nil
		}
	}
}

func replaceProcessEnv(env []string, key, value string) []string {
	replaced := make([]string, 0, len(env)+1)
	for _, item := range env {
		separator := strings.IndexByte(item, '=')
		name := item
		if separator >= 0 {
			name = item[:separator]
		}
		matches := name == key
		if runtime.GOOS == "windows" {
			matches = strings.EqualFold(name, key)
		}
		if matches {
			continue
		}
		replaced = append(replaced, item)
	}
	return append(replaced, key+"="+value)
}

func withCodexStderr(err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return err
	}
	return fmt.Errorf("%w (stderr: %s)", err, stderr)
}

type boundedDiagnosticBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	limit  int
}

func (w *boundedDiagnosticBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	original := len(p)
	remaining := w.limit - w.buffer.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = w.buffer.Write(p)
	}
	return original, nil
}

func (w *boundedDiagnosticBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}
