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

package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

// RetiredConnector returns a teardown-only connector for a connector ID an
// older release shipped and this build replaced (see legacyconnector). It is
// never registered: discovery, setup, routing and the hook API cannot reach
// it. Callers use it only to remove the state an older release left behind.
func RetiredConnector(name string) (Connector, bool) {
	if !legacyconnector.IsRetired(name) {
		return nil, false
	}
	return &retiredDesktopConnector{}, true
}

// RetiredCleanupReport describes what a retired connector's last Teardown
// removed from the agent's hook file.
type RetiredCleanupReport struct {
	HooksPath      string
	RemovedEntries int
}

// RetiredCleanupReporter is implemented by connectors RetiredConnector returns.
type RetiredCleanupReporter interface {
	LastCleanup() RetiredCleanupReport
	// HasResidue reports whether DefenseClaw-owned hook entries or scripts
	// are still present. Unreadable foreign files do not count as residue.
	HasResidue(opts SetupOpts) bool
}

type retiredDesktopConnector struct {
	mu   sync.Mutex
	last RetiredCleanupReport
}

var (
	_ Connector              = (*retiredDesktopConnector)(nil)
	_ RetiredCleanupReporter = (*retiredDesktopConnector)(nil)
)

func (c *retiredDesktopConnector) Name() string { return legacyconnector.RetiredDesktopID }

func (c *retiredDesktopConnector) Description() string {
	return "retired connector ID; Devin Desktop is covered by the " + legacyconnector.Replacement + " connector"
}

func (c *retiredDesktopConnector) ToolInspectionMode() ToolInspectionMode {
	return ToolModePreExecution
}

func (c *retiredDesktopConnector) SubprocessPolicy() SubprocessPolicy { return SubprocessNone }

func (c *retiredDesktopConnector) Setup(context.Context, SetupOpts) error {
	return fmt.Errorf(
		"connector %q is retired: the product is now Devin Desktop; run `defenseclaw setup %s` instead",
		legacyconnector.RetiredDesktopID,
		legacyconnector.Replacement,
	)
}

// Teardown removes only what an older DefenseClaw release wrote: its entries
// in the legacy hooks file, its hook scripts, its setup backup and its hook
// contract lock entry.
func (c *retiredDesktopConnector) Teardown(_ context.Context, opts SetupOpts) error {
	path := retiredCascadeHooksPath(opts)
	var errs []error
	removed, err := legacyconnector.RemoveOwnedCascadeHooks(path, opts.DataDir, nativeHookBinaryOwnershipCandidates()...)
	if err != nil {
		errs = append(errs, err)
	}
	c.mu.Lock()
	c.last = RetiredCleanupReport{HooksPath: path, RemovedEntries: removed}
	c.mu.Unlock()
	for _, script := range legacyconnector.OwnedHookScripts(opts.DataDir) {
		if err := os.Remove(script); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", script, err))
		}
	}
	if backup := legacyconnector.BackupDir(opts.DataDir); backup != "" {
		if err := os.RemoveAll(backup); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", backup, err))
		}
	}
	if err := ClearHookContractLockEntry(opts.DataDir, legacyconnector.RetiredDesktopID); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// VerifyClean fails while DefenseClaw entries or scripts remain.
func (c *retiredDesktopConnector) VerifyClean(opts SetupOpts) error {
	path := retiredCascadeHooksPath(opts)
	count, err := legacyconnector.CountOwnedCascadeHooks(path, opts.DataDir, nativeHookBinaryOwnershipCandidates()...)
	if err != nil {
		return fmt.Errorf("%s cleanup could not read %s: %w", legacyconnector.RetiredDesktopID, path, err)
	}
	if count > 0 {
		return fmt.Errorf("%s cleanup incomplete: %s still has %d DefenseClaw hook entries", legacyconnector.RetiredDesktopID, path, count)
	}
	for _, script := range legacyconnector.OwnedHookScripts(opts.DataDir) {
		if _, err := os.Lstat(script); err == nil {
			return fmt.Errorf("%s cleanup incomplete: %s still exists", legacyconnector.RetiredDesktopID, script)
		}
	}
	return nil
}

func (c *retiredDesktopConnector) HasResidue(opts SetupOpts) bool {
	count, err := legacyconnector.CountOwnedCascadeHooks(retiredCascadeHooksPath(opts), opts.DataDir, nativeHookBinaryOwnershipCandidates()...)
	if err == nil && count > 0 {
		return true
	}
	for _, script := range legacyconnector.OwnedHookScripts(opts.DataDir) {
		if _, err := os.Lstat(script); err == nil {
			return true
		}
	}
	return false
}

func (c *retiredDesktopConnector) LastCleanup() RetiredCleanupReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

func (c *retiredDesktopConnector) Authenticate(*http.Request) bool { return false }

func (c *retiredDesktopConnector) Route(*http.Request, []byte) (*ConnectorSignals, error) {
	return nil, fmt.Errorf("connector %q is retired", legacyconnector.RetiredDesktopID)
}

func (c *retiredDesktopConnector) SetCredentials(string, string) {}

// retiredCascadeHooksPath resolves the legacy hooks file under the bound
// profile: an explicit absolute ConfigHome from native maintenance, otherwise
// the connector package's user home.
func retiredCascadeHooksPath(opts SetupOpts) string {
	home := strings.TrimSpace(opts.ConfigHome)
	if home == "" || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		home = strings.TrimSpace(userHomeDir())
	}
	if home == "" {
		return ""
	}
	return legacyconnector.CascadeUserHooksPath(home)
}
