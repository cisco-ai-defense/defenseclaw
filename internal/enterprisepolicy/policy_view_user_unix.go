// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterprisepolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const managedPreferencesRoot = "/Library/Managed Preferences"

var policyViewUserReadFile = readPolicyFile

func accountPreferenceName(connector string) string {
	switch connector {
	case ConnectorCodex:
		return "com.openai.codex.plist"
	case ConnectorClaudeCode:
		return "com.anthropic.claudecode.plist"
	default:
		return ""
	}
}

func validPolicyViewAccount(account string) bool {
	return account != "" && account != "." && account != ".." && len(account) <= 255 &&
		!strings.ContainsAny(account, "/\\\x00")
}

func accountPreferencePath(opts Options, connector, account string) (string, error) {
	if opts.goos() != "darwin" || !validPolicyViewAccount(account) {
		return "", fmt.Errorf("invalid macOS policy-view account %q", account)
	}
	name := accountPreferenceName(connector)
	if name == "" {
		return "", fmt.Errorf("%s has no per-account managed preference", connector)
	}
	return filepath.Join(rooted(opts, managedPreferencesRoot), account, name), nil
}

// PolicyViewUserPins records each per-account managed preference under the
// root lifecycle's privileges. Its protected descriptor records which
// account's file the hook must read; an unreadable relevant file still closes.
func PolicyViewUserPins(opts Options, connector string) (map[string]managed.PolicyViewFilePin, error) {
	if opts.goos() != "darwin" || accountPreferenceName(connector) == "" {
		return nil, nil
	}
	if opts.Root == "" && os.Geteuid() != 0 {
		return nil, errors.New("per-account policy-view pins require root")
	}
	root := rooted(opts, managedPreferencesRoot)
	if !opts.SkipTrustChecks {
		if err := validateTrustedAncestors(opts, filepath.Join(root, "x")); err != nil {
			return nil, err
		}
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pins := make(map[string]managed.PolicyViewFilePin)
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			// An unrelated preference may be a symlink. A symlink that
			// stands in for an account directory cannot be trusted.
			target, err := os.Stat(filepath.Join(root, entry.Name()))
			if err != nil || target.IsDir() {
				return nil, fmt.Errorf("macOS managed-preferences account entry %q is a symlink", entry.Name())
			}
			continue
		}
		if !entry.IsDir() {
			continue
		}
		account := entry.Name()
		if !validPolicyViewAccount(account) {
			return nil, fmt.Errorf("invalid macOS managed-preferences account %q", account)
		}
		path, _ := accountPreferencePath(opts, connector, account)
		before, statErr := os.Lstat(path)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
		data, exists, err := readPolicyFile(opts, path)
		if err != nil {
			return nil, fmt.Errorf("read %s preference for %s: %w", connector, account, err)
		}
		if !exists {
			if _, statErr := os.Lstat(path); statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
				return nil, fmt.Errorf("%s preference for %s changed during attestation", connector, account)
			}
			continue
		}
		if statErr != nil {
			return nil, fmt.Errorf("%s preference for %s appeared during attestation", connector, account)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		pin, err := policyViewFilePin(info, data)
		if err != nil {
			return nil, err
		}
		if err := matchPolicyViewFilePin(before, pin); err != nil {
			return nil, fmt.Errorf("%s preference for %s changed during attestation: %w", connector, account, err)
		}
		if len(pins) == 128 {
			return nil, fmt.Errorf("%s has more than 128 per-account preferences", connector)
		}
		pins[account] = pin
	}
	return pins, nil
}

// VerifyPolicyViewUserPin checks the invoking account's one relevant plist.
// The root's byte attestation does not substitute for what the hook sees:
// unreadable relevant files and any other uncertainty close.
func VerifyPolicyViewUserPin(opts Options, connector, account string, pin managed.PolicyViewFilePin) error {
	path, err := accountPreferencePath(opts, connector, account)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if !opts.SkipTrustChecks {
			if err := validateTrustedAncestors(opts, path); err != nil {
				return err
			}
		}
		if pin.SHA256 != "" {
			return fmt.Errorf("%s preference for %s is hidden or removed", connector, account)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if pin.SHA256 == "" {
		return fmt.Errorf("%s preference for %s has no privileged pin", connector, account)
	}
	if !opts.SkipTrustChecks {
		if err := validateTrustedPolicyFile(opts, path); err != nil {
			return err
		}
	}
	if err := matchPolicyViewFilePin(info, pin); err != nil {
		return err
	}
	data, exists, readErr := policyViewUserReadFile(opts, path)
	if readErr != nil {
		return readErr
	}
	if !exists || sha256Hex(data) != pin.SHA256 {
		return fmt.Errorf("%s preference for %s differs from its privileged pin", connector, account)
	}
	// A second metadata read closes a replacement during the byte read.
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return matchPolicyViewFilePin(current, pin)
}

func matchPolicyViewFilePin(info os.FileInfo, pin managed.PolicyViewFilePin) error {
	current, err := policyViewFilePin(info, nil)
	if err != nil {
		return err
	}
	if current.Size != pin.Size || current.Mode != pin.Mode || current.Device != pin.Device ||
		current.Inode != pin.Inode || current.MTime != pin.MTime || current.CTime != pin.CTime {
		return fmt.Errorf("per-account preference differs from its privileged file attestation")
	}
	return nil
}
