// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// rootRuntimeLeftoverNames are the private runtime files a sudo-started
// gateway writes into the data directory. It is the list Doctor names in
// file_permissions.SUDO_RUNTIME_LEFTOVER_NAMES; a test pins the two.
var rootRuntimeLeftoverNames = []string{
	"gateway.pid",
	"watchdog.pid",
	"hook_contract_lock.json",
	"active_connector.json",
	"ai_discovery_state.json",
	"application_protection_state.json",
	"redaction-correlation.key",
	"device.key",
	"device.key.provenance",
}

// gatewayPIDRecordNames are the PID records start and restart validate before
// anything else, in the install home.
var gatewayPIDRecordNames = []string{"gateway.pid", "watchdog.pid"}

// StoreDirEntry names the data directory itself in RootOwnedStartBlockers.
const StoreDirEntry = "./"

// ownerOfFile is a variable so a test can stand in for the root-owned files
// it cannot create as an ordinary user.
var ownerOfFile = fileOwnerUID

// dirUsable reports whether this account can write to and enter a directory.
// It is a variable so a test can stand in for a root-owned directory.
var dirUsable = accountCanUseDir

// RootOwnedStartBlockers returns what root owns under dataDir (GAP-0788) that
// stops a gateway start by an account that is not root, and which of those
// files also grant group or others access. A gateway stopped after a sudo run
// leaves them: this account cannot read or replace them, so the start fails
// inside the daemon with the raw protected-state text. It is the Go side of
// Doctor root_owned_start_blockers and reads with lstat, which needs no read
// access:
//   - a root-owned file from the runtime list, of any mode; the gateway also
//     refuses one that grants group or others access, so loose reports it and
//     the repair takes that access away after the owner is returned;
//   - StoreDirEntry when root owns the data directory and this account cannot
//     write there, since a root-owned 0700 store hides every file in it;
//   - the PID records in pidDir when that is another folder than dataDir;
//   - ai_discovery_state.json only when discovery is enabled, because the
//     gateway reads it then and not otherwise.
//
// Paths in blockers and loose are relative to dataDir, except those from
// pidDir, which are absolute. It returns nothing on Windows and for a root
// caller.
func RootOwnedStartBlockers(dataDir, pidDir string, aiDiscoveryEnabled bool) (blockers, loose []string) {
	if dataDir == "" || os.Geteuid() <= 0 {
		return nil, nil
	}
	names := make([]string, 0, len(rootRuntimeLeftoverNames))
	for _, name := range rootRuntimeLeftoverNames {
		if aiDiscoveryEnabled || name != "ai_discovery_state.json" {
			names = append(names, name)
		}
	}
	if info, err := os.Lstat(dataDir); err == nil && info.IsDir() && rootOwned(info) && !dirUsable(dataDir) {
		blockers = append(blockers, StoreDirEntry)
	}
	for _, entry := range rootOwnedRuntimeFiles(dataDir, names) {
		blockers = append(blockers, entry.rel)
		if entry.loose {
			loose = append(loose, filepath.Join(dataDir, entry.rel))
		}
	}
	if pidDir != "" && filepath.Clean(pidDir) != filepath.Clean(dataDir) {
		for _, entry := range rootOwnedRuntimeFiles(pidDir, gatewayPIDRecordNames) {
			path := filepath.Join(pidDir, entry.rel)
			blockers = append(blockers, path)
			if entry.loose {
				loose = append(loose, path)
			}
		}
	}
	return blockers, loose
}

type rootOwnedEntry struct {
	rel   string
	loose bool
}

// rootOwnedRuntimeFiles lists the root-owned regular files from names under
// dir, and the hooks directory and its tokens, with whether each grants group
// or others anything.
func rootOwnedRuntimeFiles(dir string, names []string) []rootOwnedEntry {
	var found []rootOwnedEntry
	add := func(rel string) {
		info, err := os.Lstat(filepath.Join(dir, rel))
		if err != nil || !info.Mode().IsRegular() || !rootOwned(info) {
			return
		}
		found = append(found, rootOwnedEntry{rel: rel, loose: info.Mode().Perm()&0o077 != 0})
	}
	for _, name := range names {
		add(name)
	}
	hooksDir := filepath.Join(dir, "hooks")
	info, err := os.Lstat(hooksDir)
	if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return found
	}
	if rootOwned(info) && info.Mode().Perm()&0o022 == 0 {
		found = append(found, rootOwnedEntry{rel: "hooks/"})
	}
	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		return found
	}
	hookNames := make([]string, 0, len(entries))
	for _, entry := range entries {
		hookNames = append(hookNames, entry.Name())
	}
	sort.Strings(hookNames)
	for _, name := range hookNames {
		if strings.HasPrefix(name, ".hook-") && strings.HasSuffix(name, ".token") {
			add("hooks/" + name)
		}
	}
	return found
}

func rootOwned(info fs.FileInfo) bool {
	uid, ok := ownerOfFile(info)
	return ok && uid == 0
}

// RootLeftoversRemedy is the one repair for root-owned runtime files a
// sudo-started gateway left behind: the same stop, return, start chain Doctor
// prints for its Sudo leftovers row (GAP-0711, GAP-0713). installHome is the
// install home the root run was started for; the chain also returns the store
// the config of that home moved the data to. loosen lists root-owned files that also
// grant group or others access, which the gateway refuses once the owner is
// returned: the chain takes that access away before the start.
func RootLeftoversRemedy(installHome string, loosen []string) string {
	command, note := rootGatewayRecoveryStepsLoosening(installHome, loosen)
	lead := "stop"
	if note != "" {
		lead = note + "Then stop"
	}
	return lead + " the gateway if it runs as root, give its files back to this account and start it as yourself: " + command
}
