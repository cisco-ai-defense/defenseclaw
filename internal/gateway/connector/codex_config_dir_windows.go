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

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// ensureCodexConfigDir creates a missing per-user Codex directory with a
// private DACL and validates the complete path before a lock or config file is
// opened beneath it. CreatePrivateDirectory rejects reparse points throughout
// the chain and does not rewrite an existing operator-owned ACL.
func ensureCodexConfigDir(path string) error {
	created, err := safefile.CreatePrivateDirectory(path)
	if err != nil {
		return fmt.Errorf("create private Codex configuration directory: %w", err)
	}
	if err := hookAPIValidateDirectory(path); err != nil {
		state := "existing"
		if created {
			state = "new"
		}
		return fmt.Errorf("validate %s Codex configuration directory: %w", state, err)
	}
	return nil
}

// codexHomeLinkRefusal refuses, before Setup changes anything, a per-user
// Codex home that goes through a symbolic link or junction. The config writer
// (ensureCodexConfigDir) refuses the same path, but only after Setup has moved
// the hooks from an earlier home, so the rollback was incomplete and the error
// told the user to close the agent and run defenseclaw upgrade, which does not
// help (GAP-2339). Any other error is left to the writer, as before.
func codexHomeLinkRefusal(home string) error {
	err := safefile.RejectReparseChain(home)
	if err == nil || !errors.Is(err, safefile.ErrReparsePoint) {
		return nil
	}
	// defenseclaw setup passes the default home as CODEX_HOME too, so only a
	// CODEX_HOME that names another folder is the user's own choice to undo;
	// for the default home "unset it" would point at the same link (GAP-2402).
	fix := "make " + home + " a real folder"
	defaultHome := filepath.Join(userHomeDir(), ".codex")
	if env := strings.TrimSpace(os.Getenv("CODEX_HOME")); env != "" && !strings.EqualFold(filepath.Clean(env), filepath.Clean(defaultHome)) {
		fix = "set CODEX_HOME to the real folder, or unset it to use " + defaultHome
	}
	return refuseForAgentConfig(fmt.Errorf( //nolint:staticcheck // Preserve the product name in this operator diagnostic.
		"Codex home %s goes through a symbolic link or junction (%v), and DefenseClaw does not write Codex settings through one on Windows; %s, then run: defenseclaw setup codex",
		home, err, fix,
	))
}
