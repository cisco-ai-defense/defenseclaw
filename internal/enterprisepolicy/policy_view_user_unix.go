// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterprisepolicy

import (
	"crypto/subtle"
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

// policyViewAccountSources are, on macOS, the managed-preferences folder and
// each account's preference for connector: what PolicyViewStamp watches for
// PolicyViewAccountsUnproven. At most maxPolicyViewAccountStamps accounts
// are listed; the folder's own stamp still moves when an entry is added or
// removed.
func policyViewAccountSources(opts Options, connector string) []string {
	if opts.goos() != "darwin" || accountPreferenceName(connector) == "" {
		return nil
	}
	root := rooted(opts, managedPreferencesRoot)
	paths := []string{root}
	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		if len(paths) > maxPolicyViewAccountStamps {
			break
		}
		if path, err := accountPreferencePath(opts, connector, entry.Name()); err == nil {
			paths = append(paths, path)
		}
	}
	return paths
}

const maxPolicyViewAccountStamps = 1024

// PolicyViewAccountsUnproven names the macOS accounts whose own managed
// preference for connector the descriptor's per-account pins do not prove by
// content: a changed, removed or unpinned preference, one the caller can not
// read or does not trust, or a symlinked account folder. Only content counts:
// an MDM agent that rewrites the same bytes keeps the account proven. It
// reads with the caller's own permissions (the gateway's), so an account it
// can not read is unproven, never proven. The error is for the folder
// itself, which leaves no account proven.
func PolicyViewAccountsUnproven(opts Options, connector string, pins map[string]string) (map[string]bool, error) {
	if opts.goos() != "darwin" || accountPreferenceName(connector) == "" {
		return nil, nil
	}
	unproven := make(map[string]bool, len(pins))
	for account := range pins {
		// A pinned account is unproven until its preference matches.
		unproven[account] = true
	}
	root := rooted(opts, managedPreferencesRoot)
	if !opts.SkipTrustChecks {
		if err := validateTrustedAncestors(opts, filepath.Join(root, "x")); err != nil {
			return nil, err
		}
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return unproven, nil
	}
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		account := entry.Name()
		if !validPolicyViewAccount(account) {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			// A symlink that stands in for an account folder can not be
			// trusted; an unrelated preference may be a symlink.
			if target, err := os.Stat(filepath.Join(root, account)); err != nil || target.IsDir() {
				unproven[account] = true
			}
			continue
		}
		if !entry.IsDir() {
			continue
		}
		path, _ := accountPreferencePath(opts, connector, account)
		data, exists, err := readPolicyFile(opts, path)
		pin := pins[account]
		switch {
		case err != nil:
			unproven[account] = true
		case !exists:
			// Proven only when it was never pinned; a pinned one that is
			// gone stays unproven.
		case pin != "" && subtle.ConstantTimeCompare([]byte(sha256Hex(data)), []byte(pin)) == 1:
			delete(unproven, account)
		default:
			unproven[account] = true
		}
	}
	return unproven, nil
}
