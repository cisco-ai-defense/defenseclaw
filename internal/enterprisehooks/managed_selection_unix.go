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

//go:build !windows

package enterprisehooks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// selectManagedAgentExecutable binds a connector whose setup admits only a
// protected, setup-selected agent executable (OpenHands on macOS) to the
// target user's own image. The per-user install runs as that user, hashes
// the image and records it in the protected agent_selection.json receipt
// that the connector's executable admission and hook-contract publication
// read (connector.WriteManagedSetupAgentSelection). A later replacement of
// the image is still refused by the connector's digest check. Connectors
// without protected executable admission, and callers that already chose
// an executable, are left unchanged. Only the standalone profile selects:
// the Secure Client macOS guardian keeps its earlier OpenHands behavior.
func selectManagedAgentExecutable(home, dataDir, connectorName string, setupOpts *connector.SetupOpts) error {
	if setupOpts == nil || !standaloneProfileProcess() || !connector.ProtectedSetupSelectionConnector(connectorName) ||
		strings.TrimSpace(setupOpts.AgentExecutable) != "" {
		return nil
	}
	executable, err := unixManagedAgentExecutable(home, connectorName)
	if err != nil {
		return fmt.Errorf("enterprise hooks: connector %s cannot be managed for this user: %w", connectorName, err)
	}
	// A first install may run before the per-user data directory exists;
	// the receipt and its lock file live there. The caller holds the target
	// user's credentials and a 0077 umask.
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("enterprise hooks: create data dir for the %s executable selection: %w", connectorName, err)
	}
	if err := connector.WriteManagedSetupAgentSelection(dataDir, connectorName, executable, setupOpts.AgentVersion); err != nil {
		return fmt.Errorf("enterprise hooks: record managed %s executable selection: %w", connectorName, err)
	}
	setupOpts.AgentExecutable = executable
	return nil
}

// unixManagedAgentExecutable returns the image of connectorName's CLI that
// the target user runs, searching the same locations as the version probe
// (DiscoverUnixAgentVersion) in the same order.
func unixManagedAgentExecutable(home, connectorName string) (string, error) {
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	probe, ok := unixAgentProbes[connectorName]
	if !ok || len(probe.binaries) == 0 {
		return "", fmt.Errorf("no executable probe for connector %s", connectorName)
	}
	for _, binary := range probe.binaries {
		for _, candidate := range unixAgentBinaryCandidates(filepath.Clean(home), binary) {
			if image, ok := unixAgentExecutableImage(candidate, binary); ok {
				return image, nil
			}
		}
	}
	return "", fmt.Errorf("no %s executable was found in the user's or the machine's bin directories", connectorName)
}

// unixAgentExecutableImage resolves one candidate to the regular executable
// file it runs. uv and pipx install the CLI as a link in ~/.local/bin to the
// entry point inside the tool's environment; the connector admits only a
// regular, non-link file that carries the CLI's own name, so a link whose
// target has another name is not a match.
func unixAgentExecutableImage(candidate, binary string) (string, bool) {
	if _, err := os.Lstat(candidate); err != nil {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Base(resolved) != binary {
		return "", false
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", false
	}
	return resolved, true
}
