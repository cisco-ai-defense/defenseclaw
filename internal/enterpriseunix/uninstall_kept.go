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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
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
		if entry := perUserFilesOf(user, env.P(home)); entry.data || entry.binaries {
			kept = append(kept, entry)
		}
	}
	return kept, true
}

// perUserFilesOf is what the account user has in home: ~/.defenseclaw,
// and the per-user install's binaries or launcher in ~/.local/bin.
func perUserFilesOf(user, home string) perUserKept {
	entry := perUserKept{user: user}
	_, statErr := os.Lstat(filepath.Join(home, ".defenseclaw"))
	entry.data = statErr == nil
	for _, name := range []string{"defenseclaw-gateway", "defenseclaw-acp", "defenseclaw"} {
		if _, err := os.Lstat(filepath.Join(home, ".local", "bin", name)); err == nil {
			entry.binaries = true
			break
		}
	}
	return entry
}

// perUserFilesOnHost lists the local accounts (getent passwd, Linux only)
// whose home holds DefenseClaw per-user files. It is for a purge that has
// no enrollment record left to name the enrolled accounts by.
func (env *Env) perUserFilesOnHost(ctx context.Context) []perUserKept {
	if env.GOOS != "linux" {
		return nil
	}
	out, err := env.Runner.Run(ctx, "getent", "passwd")
	if err != nil {
		return nil
	}
	var found []perUserKept
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out.Stdout), "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 7 {
			continue
		}
		user, home := fields[0], filepath.Clean(fields[5])
		if user == "" || !filepath.IsAbs(home) || home == "/" || seen[user] {
			continue
		}
		seen[user] = true
		if entry := perUserFilesOf(user, env.P(home)); entry.data || entry.binaries {
			found = append(found, entry)
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].user < found[j].user })
	return found
}

// warnUnpurgedPerUser warns, on a purge with no deployment and no
// enrollment record left, for each account whose per-user files stay. A
// default uninstall removes that record, and the purge after it (the step
// the uninstall itself named) reported done while every account kept its
// ~/.defenseclaw (GAP-2632).
func (l *lifecycle) warnUnpurgedPerUser(ctx context.Context) {
	files := describePerUserFiles(l.env.perUserFilesOnHost(ctx))
	if files == "" {
		return
	}
	l.result.AddWarning(codePerUserState, "not removed: "+files+". No DefenseClaw enrollment record is left (the uninstall before this one removed it), so this purge cannot tell which accounts were enrolled. "+l.purgeAgainStep())
}

// describePerUserFiles names, per account, the DefenseClaw per-user files
// in entries; "" when there are none.
func describePerUserFiles(entries []perUserKept) string {
	var dataUsers, binaryUsers []string
	for _, entry := range entries {
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
	return strings.Join(parts, "; ")
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
	files := describePerUserFiles(l.keptPerUser)
	if files == "" {
		return ""
	}
	return "kept: " + files + ". " + next
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
	if !exists(env.P(env.Layout.ManifestPath)) || !exists(env.P(env.Layout.ConfigPath)) {
		// A purge finds the enrolled accounts through the enrollment record
		// and config this uninstall removed (GAP-2632).
		return "To delete them too, " + l.purgeAgainStep()
	}
	if record != nil && record.Channel == ChannelPackage && env.GOOS == "linux" {
		return "To delete them too, run " + purge + " while the defenseclaw-enterprise package is installed (once the package is removed, install it again first)."
	}
	return "To delete them too, run " + purge + "."
}

// purgeAgainStep is how to delete per-user files once the enrollment record
// is gone: a purge needs the deployment back, which names the accounts again.
func (l *lifecycle) purgeAgainStep() string {
	env := l.env
	purge := "`" + env.lifecycleCommand(ActionUninstall) + " --purge`"
	if l.packageManaged {
		return "activate the deployment again with `" + env.lifecycleCommand(ActionEnsure) + " --from-package --config <file>` and run " + purge + ", or delete those files by hand."
	}
	return "install the DefenseClaw enterprise package again and run " + purge + ", or delete those files by hand."
}
