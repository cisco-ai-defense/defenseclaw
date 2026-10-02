// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// perUserKept is what one enrolled account still has after a default
// uninstall, which keeps the accounts' own DefenseClaw files.
type perUserKept struct {
	user     string
	data     bool
	binaries bool
}

// perUserLeftovers lists the enrolled accounts (from the enumerator's
// eligible-accounts record, read before the uninstall removes it) with
// what each has: ~/.defenseclaw, and the per-user install's binaries or
// launcher in ~/.local/bin. ok is false when the record is unreadable.
func (env *Env) perUserLeftovers() ([]perUserKept, bool) {
	data, err := readBounded(env.P(enterprisehooks.UnixEligibleAccountsPath(env.Layout.ManifestPath)), maxInputBytes)
	if err != nil {
		return nil, false
	}
	var record struct {
		Accounts []struct {
			User string `json:"user"`
			Home string `json:"home"`
		} `json:"accounts"`
	}
	if json.Unmarshal(data, &record) != nil {
		return nil, false
	}
	var kept []perUserKept
	for _, account := range record.Accounts {
		user, home := strings.TrimSpace(account.User), strings.TrimSpace(account.Home)
		if user == "" || home == "" {
			continue
		}
		home = env.P(home)
		entry := perUserKept{user: user}
		_, statErr := os.Lstat(filepath.Join(home, ".defenseclaw"))
		entry.data = statErr == nil
		for _, name := range []string{"defenseclaw-gateway", "defenseclaw-acp", "defenseclaw"} {
			if _, err := os.Lstat(filepath.Join(home, ".local", "bin", name)); err == nil {
				entry.binaries = true
				break
			}
		}
		if entry.data || entry.binaries {
			kept = append(kept, entry)
		}
	}
	return kept, true
}

// keptPerUserLine names, per account, the DefenseClaw files a default
// uninstall kept, and how to delete them (GAP-1949): "each enrolled user's
// ~/.defenseclaw and per-user binaries" named no account and claimed
// binaries for accounts that never had a per-user install. It is "" when
// the record shows that no enrolled account has any.
func (l *lifecycle) keptPerUserLine(record *Deployment) string {
	next := l.keptPerUserNextStep(record)
	if !l.keptKnown {
		return "kept: each enrolled account's DefenseClaw per-user data (~/.defenseclaw) and any per-user binaries in ~/.local/bin. " + next
	}
	var dataUsers, binaryUsers []string
	for _, entry := range l.keptPerUser {
		if entry.data {
			dataUsers = append(dataUsers, entry.user)
		}
		if entry.binaries {
			binaryUsers = append(binaryUsers, entry.user)
		}
	}
	var parts []string
	if len(dataUsers) > 0 {
		parts = append(parts, "the DefenseClaw per-user data (~/.defenseclaw) of "+strings.Join(dataUsers, ", "))
	}
	if len(binaryUsers) > 0 {
		parts = append(parts, "the per-user binaries in ~/.local/bin of "+strings.Join(binaryUsers, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return "kept: " + strings.Join(parts, "; ") + ". " + next
}

// keptPerUserNextStep says how to delete the per-user files a default
// uninstall keeps. --purge needs the gateway binary, which this uninstall
// removed unless the deb/rpm owns it, so the next step must not name a
// binary that is gone (GAP-1721).
func (l *lifecycle) keptPerUserNextStep(record *Deployment) string {
	env := l.env
	purge := "`" + env.lifecycleCommand(ActionUninstall) + " --purge`"
	if !exists(env.P(filepath.Join(env.Layout.BinDir, binGateway))) {
		return "To delete them too, install the DefenseClaw enterprise package again and run " + purge + "."
	}
	if record != nil && record.Channel == ChannelPackage && env.GOOS == "linux" {
		return "To delete them too, run " + purge + " while the defenseclaw-enterprise package is installed (once the package is removed, install it again first)."
	}
	return "To delete them too, run " + purge + "."
}
