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
	home     string
	data     bool
	binaries bool
	// manifest is set when the enrollment manifest names the account, so
	// the purge removes its ~/.defenseclaw. An eligible account the
	// manifest does not name is covered only by the machine policy, and the
	// purge keeps its folder (GAP-2237).
	manifest bool
}

// perUserLeftovers lists the enrolled accounts (from the enumerator's
// eligible-accounts record, read before the uninstall removes it) with
// what each has: ~/.defenseclaw, and the per-user install's binaries or
// launcher in ~/.local/bin. ok is false when the record is unreadable.
func (env *Env) perUserLeftovers() (kept []perUserKept, enrolled map[string]bool, ok bool) {
	data, err := readBounded(env.P(enterprisehooks.UnixEligibleAccountsPath(env.Layout.ManifestPath)), maxInputBytes)
	if err != nil {
		return nil, nil, false
	}
	var record struct {
		Accounts []enterprisehooks.UnixEligibleAccount `json:"accounts"`
	}
	if json.Unmarshal(data, &record) != nil {
		return nil, nil, false
	}
	// The accounts the manifest names, whose ~/.defenseclaw the purge
	// removes. An unreadable manifest names every eligible account, as
	// before.
	named := record.Accounts
	if manifest, err := enterprisehooks.LoadStandaloneManifest(env.P(env.Layout.ManifestPath)); err == nil {
		named = enterprisehooks.ManifestEnrolledAccounts(record.Accounts, manifest)
	}
	inManifest := map[string]bool{}
	for _, account := range named {
		inManifest[strings.TrimSpace(account.User)] = true
	}
	enrolled = map[string]bool{}
	for _, account := range record.Accounts {
		user, home := strings.TrimSpace(account.User), strings.TrimSpace(account.Home)
		if user == "" || home == "" {
			continue
		}
		enrolled[filepath.Clean(env.P(home))] = true
		if entry := perUserFilesOf(user, env.P(home)); entry.data || entry.binaries {
			entry.manifest = inManifest[user]
			kept = append(kept, entry)
		}
	}
	return kept, enrolled, true
}

// reportUnenrolledUserData names, after a purge, the accounts the deployment
// never enrolled whose home still holds DefenseClaw per-user files (an
// earlier per-user install, or hooks a former enrollment left): a purge
// removes only enrolled accounts' data, and reported nothing for these
// (GAP-1654). It never deletes them.
func (l *lifecycle) reportUnenrolledUserData(ctx context.Context) {
	if !l.keptKnown {
		return
	}
	var others []perUserKept
	for _, entry := range l.env.perUserFilesOnHost(ctx) {
		if !l.enrolledHomes[filepath.Clean(entry.home)] {
			others = append(others, entry)
		}
	}
	if files := describePerUserFiles(others); files != "" {
		l.result.AddWarning(codePerUserState, "kept: "+files+", accounts this deployment did not enroll; a purge removes only the DefenseClaw data of enrolled accounts. Each account's owner can delete these files, or an administrator can if DefenseClaw left them")
	}
}

// reportRetainedEnrolledUserData makes a successful Unix purge account for
// enrolled users whose OSS data survived remove-all. The lifecycle only
// observes these user-owned files; it never deletes them to make the result
// look complete.
//
// An account the machine policy covers but the enrollment manifest does not
// name keeps the folder too, and when that folder holds no install of its
// own (only the hook files and connector backups DefenseClaw wrote there)
// it is not the account's own data: those accounts go on one kept: line
// that says so, instead of a per-account "enrolled user ... account-owned
// folder" warning (GAP-2237).
func (l *lifecycle) reportRetainedEnrolledUserData() {
	var policyOnly []perUserKept
	for _, before := range l.keptPerUser {
		// The remove-all worker may already have removed eligible-accounts.json.
		// Use the home captured before removal to inspect what still exists.
		if !before.data || l.perUserStateKept[before.user] || !perUserFilesOf(before.user, before.home).data {
			continue
		}
		if !before.manifest && !holdsOwnInstall(before.home) {
			policyOnly = append(policyOnly, perUserKept{user: before.user, home: before.home, data: true})
			continue
		}
		l.result.AddWarning(codePerUserState, "kept per-user data (~/.defenseclaw) for enrolled user "+before.user+" after --purge; this account-owned folder still exists and must be reviewed with its owner")
	}
	if files := describePerUserFiles(policyOnly); files != "" {
		l.result.AddWarning(codePerUserState, "kept: "+files+", accounts the machine policy covered without a per-user enrollment; a purge removes ~/.defenseclaw only of the accounts the enrollment manifest names. These folders hold no DefenseClaw install of their own, only the hook files and connector backups DefenseClaw wrote there; an administrator can delete them")
	}
}

// holdsOwnInstall reports whether home/.defenseclaw holds the account's own
// per-user install. A folder that is not a plain directory, or that cannot
// be read, counts as one, so its account keeps the account-owned warning.
func holdsOwnInstall(home string) bool {
	dataDir := filepath.Join(home, ".defenseclaw")
	info, err := os.Lstat(dataDir)
	if err != nil || !info.IsDir() {
		return true
	}
	own, err := enterprisehooks.HoldsPerUserInstall(dataDir)
	return own || err != nil
}

// perUserFilesOf is what the account user has in home: ~/.defenseclaw,
// and the per-user install's binaries or launcher in ~/.local/bin.
func perUserFilesOf(user, home string) perUserKept {
	entry := perUserKept{user: user, home: home}
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

// perUserFilesOnHost lists the accounts whose home holds DefenseClaw
// per-user files: the local accounts (getent passwd) on Linux, the homes in
// /Users on macOS (local and mobile directory accounts alike).
func (env *Env) perUserFilesOnHost(ctx context.Context) []perUserKept {
	if env.GOOS == "darwin" {
		return env.perUserFilesInMacHomes()
	}
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

// perUserFilesInMacHomes is perUserFilesOnHost on macOS: each folder in
// /Users but Shared, named by its folder.
func (env *Env) perUserFilesInMacHomes() []perUserKept {
	entries, err := os.ReadDir(env.P("/Users"))
	if err != nil {
		return nil
	}
	var found []perUserKept
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || name == "Shared" || strings.HasPrefix(name, ".") {
			continue
		}
		if files := perUserFilesOf(name, env.P(filepath.Join("/Users", name))); files.data || files.binaries {
			found = append(found, files)
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
