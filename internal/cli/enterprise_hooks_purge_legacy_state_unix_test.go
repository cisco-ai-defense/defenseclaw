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

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func purgeTargetsOf(job *enterpriseHookWorkerJob) []string {
	if job == nil {
		return nil
	}
	var dirs []string
	for _, target := range job.Request.Targets {
		if target.Mode == enterpriseHookWorkerModePurge {
			dirs = append(dirs, target.Options.DataDir)
		}
	}
	return dirs
}

// rel-1-0-2 GAP-0576, rel-1-0-6 GAP-0178: an uninstall --purge also purges
// the ~/.defenseclaw of an eligible account the manifest does not name when
// that folder holds only what DefenseClaw wrote there (an earlier failed
// install's hook script, token, hook config and backups). An account whose
// folder holds its own per-user install, initialised or not (rel-1-0-6
// GAP-0484: the one-liner's .venv and installer folder, no config yet), or
// that has no folder, gets no purge, and an account the manifest names gets
// exactly one.
func TestRemoveAllPurgesTheLegacyStateOnlyOfAccountsWithoutAnOwnInstall(t *testing.T) {
	gid := os.Getgid()
	namedUID, legacyUID, ownUID, emptyUID, freshUID := os.Getuid()+1, os.Getuid()+2, os.Getuid()+3, os.Getuid()+4, os.Getuid()+5
	f := newStandaloneFixture(t, standaloneTestResolver{accounts: map[string]unixidentity.Account{}})
	named := f.home(t, "sample-named", 0o700)
	legacy := f.home(t, "sample-legacy", 0o700)
	own := f.home(t, "sample-own", 0o700)
	empty := f.home(t, "sample-empty", 0o700)
	fresh := f.home(t, "sample-fresh", 0o700)
	homes := map[string]int{named: namedUID, legacy: legacyUID, own: ownUID, empty: emptyUID, fresh: freshUID}
	enterpriseHookCheckHome = func(home string, uid int) enterprisehooks.HomeCheck {
		if homes[home] == uid {
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeUntrusted}
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, home := range []string{legacy, own} {
		write(filepath.Join(home, ".defenseclaw", "hooks", "claude-code-hook.sh"), "#!/bin/sh\nexit 0\n")
		write(filepath.Join(home, ".defenseclaw", ".hook-claudecode.token"), "sample\n")
		write(filepath.Join(home, ".defenseclaw", ".hookcfg-claudecode.json"), "{}\n")
		write(filepath.Join(home, ".defenseclaw", "connector_backups", "claudecode", "settings.json.json"), "{}\n")
	}
	write(filepath.Join(own, ".defenseclaw", "config.yaml"), "data_dir: ~/.defenseclaw\n")
	write(filepath.Join(own, ".defenseclaw", "session-facts.json"), "{}\n")
	// The one-liner install as it is before `defenseclaw init`.
	write(filepath.Join(fresh, ".defenseclaw", ".venv", "bin", "defenseclaw"), "#!/bin/sh\n")
	write(filepath.Join(fresh, ".defenseclaw", "installer", "binaries.sha256"), "sample\n")
	write(filepath.Join(fresh, ".defenseclaw", "receipts", "installer.sha256"), "sample\n")
	write(filepath.Join(fresh, ".defenseclaw", "logs", "install.log"), "sample\n")
	f.writeManifest(t, enterprisehooks.ManifestTarget{Connector: "hermes", User: "sample-named", UID: &namedUID, GID: &gid, UserHome: named})
	manifest, err := enterprisehooks.LoadManifest(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	accounts := []enterprisehooks.UnixEligibleAccount{
		{User: "sample-named", UID: namedUID, GID: gid, Home: named},
		{User: "sample-legacy", UID: legacyUID, GID: gid, Home: legacy},
		{User: "sample-own", UID: ownUID, GID: gid, Home: own},
		{User: "sample-empty", UID: emptyUID, GID: gid, Home: empty},
		{User: "sample-fresh", UID: freshUID, GID: gid, Home: fresh},
	}
	plan := func(skip map[int]string) map[int]*enterpriseHookWorkerJob {
		rows := resolveEnterpriseHookRemoveRows(manifest)
		jobs, _, _ := enterpriseHookRemoveJobs(rows)
		addEnterpriseHookPersonalClaudeUnblocks(jobs, accounts)
		addEnterpriseHookStatePurges(jobs, rows, skip)
		addEnterpriseHookLegacyStatePurges(jobs, rows, accounts, skip)
		return jobs
	}
	jobs := plan(nil)
	if got := purgeTargetsOf(jobs[legacyUID]); len(got) != 1 || got[0] != filepath.Join(legacy, ".defenseclaw") {
		t.Fatalf("the legacy-only folder is not purged once: %v", got)
	}
	if got := purgeTargetsOf(jobs[ownUID]); len(got) != 0 {
		t.Fatalf("an account's own per-user install was given a purge: %v", got)
	}
	if got := purgeTargetsOf(jobs[freshUID]); len(got) != 0 {
		t.Fatalf("an own per-user install that never ran init was given a purge: %v", got)
	}
	if got := purgeTargetsOf(jobs[emptyUID]); len(got) != 0 {
		t.Fatalf("an account without ~/.defenseclaw was given a purge: %v", got)
	}
	if got := purgeTargetsOf(jobs[namedUID]); len(got) != 1 {
		t.Fatalf("the enrolled account must keep exactly one purge: %v", got)
	}
	jobs = plan(map[int]string{legacyUID: enterpriseHookPurgeSkipPending})
	if got := purgeTargetsOf(jobs[legacyUID]); len(got) != 0 {
		t.Fatalf("a pending cleanup must keep the legacy folder: %v", got)
	}
}
