//go:build !windows

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

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enterpriseHookAgentVersionTarget is one (account, connector) row of the
// agent-versions record, in the guardian ledger's target shape so the gateway
// reads it with the ledger reader (managedHookLedgerTarget).
type enterpriseHookAgentVersionTarget struct {
	User      string                           `json:"user"`
	UID       int                              `json:"uid"`
	Connector string                           `json:"connector"`
	OK        bool                             `json:"ok"`
	Result    enterpriseHookAgentVersionResult `json:"result"`
}

type enterpriseHookAgentVersionResult struct {
	AgentVersion string `json:"agent_version"`
}

// enterpriseHookAgentVersionTargets are the versions the cycle verified
// (UnixEnumeratorState.VerifiedAgents), one row per account and connector,
// sorted. A Linux or macOS machine-policy connector has no per-user guardian
// row, so these are the only per-account versions the gateway can read
// (rel-1-0-10:GAP-0114).
func enterpriseHookAgentVersionTargets(state *enterprisehooks.UnixEnumeratorState) []enterpriseHookAgentVersionTarget {
	if state == nil {
		return nil
	}
	targets := make([]enterpriseHookAgentVersionTarget, 0, len(state.VerifiedAgents))
	for key, verified := range state.VerifiedAgents {
		user, conn, ok := strings.Cut(key, "\x00")
		version := strings.TrimSpace(verified.Version)
		if !ok || user == "" || conn == "" || version == "" || verified.Owner.UID < 0 ||
			!enterprisehooks.ValidUnixAgentVersion(version) {
			continue
		}
		targets = append(targets, enterpriseHookAgentVersionTarget{
			User: user, UID: verified.Owner.UID, Connector: conn, OK: true,
			Result: enterpriseHookAgentVersionResult{AgentVersion: version},
		})
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].UID != targets[j].UID {
			return targets[i].UID < targets[j].UID
		}
		return targets[i].Connector < targets[j].Connector
	})
	return targets
}

// writeEnterpriseHookAgentVersions publishes the cycle's verified agent
// versions next to the guardian ledger, with its ownership and mode
// (managed.HookGuardianAgentVersionsFile), for the gateway's per-caller hook
// profile. An empty list removes the file.
func writeEnterpriseHookAgentVersions(dataDir string, state *enterprisehooks.UnixEnumeratorState) error {
	dir := managed.HookGuardianAuthorizationDir(dataDir)
	path := filepath.Join(dir, managed.HookGuardianAgentVersionsFile)
	targets := enterpriseHookAgentVersionTargets(state)
	if len(targets) == 0 {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := ensureEnterpriseHookStandaloneAuthDir(dir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(struct {
		Version int                                `json:"version"`
		Targets []enterpriseHookAgentVersionTarget `json:"protected_targets"`
	}{Version: 1, Targets: targets}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeEnterpriseHookProtectedFile(path, append(data, '\n')); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return err
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return err
	}
	return enterpriseHookAuthorizationFileTrustCheck(path)
}
