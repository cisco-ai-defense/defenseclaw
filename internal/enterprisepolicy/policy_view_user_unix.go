// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterprisepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const managedPreferencesRoot = "/Library/Managed Preferences"

// The descriptor keeps at most this many per-account pins per connector, in
// at most this many bytes, so one crowded managed-preferences folder can not
// push the descriptor over its size limit and fail the whole host.
const (
	maxPolicyViewUserPins       = 128
	policyViewUserPinByteBudget = 24 << 10
)

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

// PolicyViewUserPins returns the SHA-256 of each account's managed
// preference for connector, read with root's privileges through the trusted
// policy-file reader. Only content counts: an MDM agent that rewrites the
// same bytes keeps the pin. An account entry that can not be pinned (an
// invalid name, a symlinked folder, an unreadable, untrusted or oversize
// file, or one past the descriptor's budget) is left out and named in the
// returned problems; the other accounts keep their pins. The error is for a
// failure of the folder itself.
func PolicyViewUserPins(opts Options, connector string) (map[string]string, []string, error) {
	if opts.goos() != "darwin" || accountPreferenceName(connector) == "" {
		return nil, nil, nil
	}
	if opts.Root == "" && os.Geteuid() != 0 {
		return nil, nil, errors.New("per-account policy-view pins require root")
	}
	root := rooted(opts, managedPreferencesRoot)
	if !opts.SkipTrustChecks {
		if err := validateTrustedAncestors(opts, filepath.Join(root, "x")); err != nil {
			return nil, nil, err
		}
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	pins := make(map[string]string)
	var problems []string
	budget := policyViewUserPinByteBudget
	for _, entry := range entries {
		account := entry.Name()
		if entry.Type()&os.ModeSymlink != 0 {
			// An unrelated preference may be a symlink. A symlink that
			// stands in for an account folder can not be trusted.
			if target, err := os.Stat(filepath.Join(root, account)); err != nil || target.IsDir() {
				problems = append(problems, fmt.Sprintf("%s managed-preferences entry %q is a symlink", connector, account))
			}
			continue
		}
		if !entry.IsDir() {
			continue
		}
		if !validPolicyViewAccount(account) {
			problems = append(problems, fmt.Sprintf("%s managed-preferences account %q has an invalid name", connector, account))
			continue
		}
		path, _ := accountPreferencePath(opts, connector, account)
		data, exists, err := readPolicyFile(opts, path)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s preference for %s can not be pinned: %v", connector, account, err))
			continue
		}
		if !exists {
			continue
		}
		quoted, _ := json.Marshal(account)
		cost := len(quoted) + sha256HexLen + 4 // "account":"digest",
		if len(pins) == maxPolicyViewUserPins || cost > budget {
			problems = append(problems, fmt.Sprintf("%s preference for %s is not pinned: the runtime descriptor has no room for more per-account pins", connector, account))
			continue
		}
		budget -= cost
		pins[account] = sha256Hex(data)
	}
	return pins, problems, nil
}

const sha256HexLen = 64

// VerifyPolicyViewUserPin checks the invoking account's one relevant plist
// against its root pin by content. Another account's preference is never
// read here.
func VerifyPolicyViewUserPin(opts Options, connector, account, pin string) error {
	path, err := accountPreferencePath(opts, connector, account)
	if err != nil {
		return err
	}
	data, exists, err := policyViewUserReadFile(opts, path)
	switch {
	case err != nil:
		return err
	case !exists && pin != "":
		return fmt.Errorf("%s preference for %s is hidden or removed", connector, account)
	case !exists:
		return nil
	case pin == "":
		return fmt.Errorf("%s preference for %s has no privileged pin", connector, account)
	case sha256Hex(data) != pin:
		return fmt.Errorf("%s preference for %s differs from its privileged pin", connector, account)
	}
	return nil
}
