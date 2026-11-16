// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A Claude Code or Codex hook call from a running agent after the
// administrator took the connector off the roster is allowed without
// inspection (the connector is no longer governed). The hook runs as the
// user, so it cannot read the administrator-only removed-connectors record. It
// reads this marker instead: one administrator-owned, user-readable file per
// connector in the machine hook runtime directory, beside the hot-config undo
// closure, published by the hook guardian while the loaded config does not
// publish the connector and removed again as soon as it does. It carries no
// account, only the roster fact. The hook allows only when this marker is
// present and valid, the closure is not held or unreadable, and the connector's
// machine policy is absent; any other state keeps the existing refusal.

const windowsConnectorOffRosterFilePrefix = ".defenseclaw-connector-off-roster-"

func windowsConnectorOffRosterBody(name string) []byte {
	return []byte("connector-off-roster-v1 " + name + "\n")
}

// WindowsConnectorOffRosterConnector reports the connectors the marker covers:
// the machine-scope connectors whose hook binary can still be called by a
// running agent (Cursor's adapter is replaced by its own tombstone).
func WindowsConnectorOffRosterConnector(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "claudecode", "codex":
		return true
	}
	return false
}

func windowsConnectorOffRosterPath(layout managed.StandaloneLayout, name string) string {
	return filepath.Join(layout.HookRuntimeDir, windowsConnectorOffRosterFilePrefix+strings.ToLower(strings.TrimSpace(name)))
}

// PublishWindowsConnectorOffRoster is the guardian's step: it publishes the
// marker of name when offRoster, and removes it otherwise. Run as LocalSystem.
func PublishWindowsConnectorOffRoster(name string, offRoster bool) error {
	if !WindowsConnectorOffRosterConnector(name) {
		return fmt.Errorf("enterprise hooks: %q has no off-roster marker", name)
	}
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return err
	}
	return publishWindowsConnectorOffRoster(layout, name, offRoster)
}

func publishWindowsConnectorOffRoster(layout managed.StandaloneLayout, name string, offRoster bool) error {
	name = strings.ToLower(strings.TrimSpace(name))
	path := windowsConnectorOffRosterPath(layout, name)
	if !offRoster {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("enterprise hooks: remove the %s off-roster marker: %w", name, err)
		}
		return nil
	}
	if err := windowsStandaloneHookClosureEnsure(layout.HookRuntimeDir); err != nil {
		return err
	}
	if data, exists, err := readTrustedWindowsManagedPolicyFile(path); err == nil && exists && bytes.Equal(data, windowsConnectorOffRosterBody(name)) {
		return nil
	}
	if err := windowsStandaloneHookClosureWrite(path, windowsConnectorOffRosterBody(name), true); err != nil {
		return err
	}
	if off, err := windowsConnectorOffRoster(layout, name); err != nil || !off {
		return fmt.Errorf("enterprise hooks: prove the %s off-roster marker: %v", name, err)
	}
	return nil
}

// WindowsConnectorOffRoster is the hook's read: whether the guardian has
// published name as off the roster. A directory that is not trusted, a link,
// a damaged or unreadable marker, and an absent marker are all "no".
func WindowsConnectorOffRoster(name string) (bool, error) {
	if !WindowsConnectorOffRosterConnector(name) {
		return false, nil
	}
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return false, err
	}
	return windowsConnectorOffRoster(layout, name)
}

func windowsConnectorOffRoster(layout managed.StandaloneLayout, name string) (bool, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if err := windowsManagedPolicyDirTrustCheck(layout.HookRuntimeDir); err != nil {
		return false, err
	}
	data, exists, err := readTrustedWindowsManagedPolicyFile(windowsConnectorOffRosterPath(layout, name))
	if err != nil || !exists {
		return false, err
	}
	if !bytes.Equal(data, windowsConnectorOffRosterBody(name)) {
		return false, fmt.Errorf("enterprise hooks: the %s off-roster marker changed", name)
	}
	return true, nil
}
