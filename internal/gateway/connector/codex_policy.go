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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
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
	return processutil.CommandContext(ctx, executable, "app-server", "--stdio")
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
		if strings.ContainsAny(executable, "\x00\r\n") || !filepath.IsAbs(executable) {
			return codexEffectivePolicy{}, fmt.Errorf("selected Codex executable is not absolute: %q", executable)
		}
		policy, err := inspectCodexPolicyWithAppServer(ctx, executable, codexHomeDir())
		if err != nil {
			return codexEffectivePolicy{}, fmt.Errorf("%s configRequirements/read: %w", executable, err)
		}
		return policy, nil
	}

	// Tests, pre-provisioning, and older Codex installs may not have a runnable
	// app-server path. In that case still honor the documented system source.
	// This fallback deliberately does not claim to have inspected cloud policy.
	return inspectCodexSystemRequirements()
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
	if err := cmd.Start(); err != nil {
		return policy, fmt.Errorf("start app-server: %w", err)
	}
	defer func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	responses := make(chan codexRPCEnvelope, 8)
	decodeErr := make(chan error, 1)
	go decodeCodexRPC(stdout, responses, decodeErr)

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
	if _, err := waitCodexRPC(ctx, responses, decodeErr, 1); err != nil {
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
	envelope, err := waitCodexRPC(ctx, responses, decodeErr, 2)
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

func decodeCodexRPC(reader io.Reader, responses chan<- codexRPCEnvelope, decodeErr chan<- error) {
	decoder := json.NewDecoder(io.LimitReader(reader, codexPolicyMessageLimit))
	for {
		var envelope codexRPCEnvelope
		if err := decoder.Decode(&envelope); err != nil {
			decodeErr <- err
			return
		}
		if len(envelope.ID) == 0 {
			continue
		}
		responses <- envelope
	}
}

func waitCodexRPC(
	ctx context.Context,
	responses <-chan codexRPCEnvelope,
	decodeErr <-chan error,
	wantID int,
) (codexRPCEnvelope, error) {
	for {
		select {
		case <-ctx.Done():
			return codexRPCEnvelope{}, fmt.Errorf("timed out waiting for response %d: %w", wantID, ctx.Err())
		case err := <-decodeErr:
			return codexRPCEnvelope{}, fmt.Errorf("read app-server response: %w", err)
		case envelope := <-responses:
			var id int
			if err := json.Unmarshal(envelope.ID, &id); err != nil || id != wantID {
				continue
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
	buffer bytes.Buffer
	limit  int
}

func (w *boundedDiagnosticBuffer) Write(p []byte) (int, error) {
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

func (w *boundedDiagnosticBuffer) String() string { return w.buffer.String() }
