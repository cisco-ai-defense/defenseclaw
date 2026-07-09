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
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const agentControlRawEventLogName = "gateway-events-unredacted.jsonl"

// newAgentControlEventWriter creates the integration-private raw spool. The
// parent is deliberately fixed below data_dir instead of following
// agent_control.managed_dir: this prevents an operator-selected artifact path
// from moving sensitive prompt content outside DefenseClaw's protected runtime
// directory.
func newAgentControlEventWriter(
	cfg *config.Config,
	validator *gatewaylog.Validator,
) (*gatewaylog.Writer, error) {
	if cfg == nil || !cfg.AgentControl.Enabled || !cfg.AgentControl.Observability.Enabled ||
		!cfg.AgentControl.Observability.IncludeContent || !cfg.Privacy.DisableRedaction {
		return nil, nil
	}

	dataDir, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve data_dir: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data_dir: %w", err)
	}
	resolvedDataDir, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve data_dir symlinks: %w", err)
	}

	privateDir := filepath.Join(resolvedDataDir, "agent-control")
	if err := os.MkdirAll(privateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create Agent Control private event directory: %w", err)
	}
	dirInfo, err := os.Lstat(privateDir)
	if err != nil {
		return nil, fmt.Errorf("inspect Agent Control private event directory: %w", err)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return nil, fmt.Errorf("Agent Control private event path must be a real directory: %s", privateDir)
	}
	if err := os.Chmod(privateDir, 0o700); err != nil {
		return nil, fmt.Errorf("protect Agent Control private event directory: %w", err)
	}

	path := filepath.Join(privateDir, agentControlRawEventLogName)
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("Agent Control private event log must be a regular non-symlink file: %s", path)
		}
	} else if !os.IsNotExist(statErr) {
		return nil, fmt.Errorf("inspect Agent Control private event log: %w", statErr)
	} else {
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			return nil, fmt.Errorf("create Agent Control private event log: %w", createErr)
		}
		if chmodErr := file.Chmod(0o600); chmodErr != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return nil, fmt.Errorf("protect Agent Control private event log: %w", chmodErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return nil, fmt.Errorf("close Agent Control private event log: %w", closeErr)
		}
	}
	if err := safefile.ValidateRegular(path); err != nil {
		return nil, fmt.Errorf("validate Agent Control private event log: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("protect Agent Control private event log: %w", err)
	}

	return gatewaylog.New(gatewaylog.Config{
		JSONLPath:  path,
		MaxSizeMB:  25,
		MaxBackups: 3,
		MaxAgeDays: 7,
		Compress:   true,
		Validator:  validator,
	})
}
