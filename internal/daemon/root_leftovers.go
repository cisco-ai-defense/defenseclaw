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

// ownerOfFile is a variable so a test can stand in for the root-owned files
// it cannot create as an ordinary user.
var ownerOfFile = fileOwnerUID

// RootOwnedRuntimeLeftovers returns the relative paths of the private runtime
// files under dataDir that root owns while this process does not run as root.
// Such a file cannot be read or replaced by this account, so a gateway start
// over it fails (GAP-0788). It is the Go side of Doctor's Sudo leftovers row
// and reads the same files with lstat, which needs no read access. It returns
// nothing on Windows and for a root caller.
func RootOwnedRuntimeLeftovers(dataDir string) []string {
	if dataDir == "" || os.Geteuid() <= 0 {
		return nil
	}
	var leftovers []string
	for _, name := range rootRuntimeLeftoverNames {
		if rootOwnedPrivateRegularFile(filepath.Join(dataDir, name)) {
			leftovers = append(leftovers, name)
		}
	}
	hooksDir := filepath.Join(dataDir, "hooks")
	info, err := os.Lstat(hooksDir)
	if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return leftovers
	}
	if uid, ok := ownerOfFile(info); ok && uid == 0 && info.Mode().Perm()&0o022 == 0 {
		leftovers = append(leftovers, "hooks/")
	}
	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		return leftovers
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		if !strings.HasPrefix(name, ".hook-") || !strings.HasSuffix(name, ".token") {
			continue
		}
		if rootOwnedPrivateRegularFile(filepath.Join(hooksDir, name)) {
			leftovers = append(leftovers, "hooks/"+name)
		}
	}
	return leftovers
}

// rootOwnedPrivateRegularFile reports a regular file that root owns and that
// grants nothing to group or others.
func rootOwnedPrivateRegularFile(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return false
	}
	uid, ok := ownerOfFile(info)
	return ok && uid == 0
}

// RootLeftoversRemedy is the one repair for root-owned runtime files a
// sudo-started gateway left behind: the same stop, return, start chain Doctor
// prints for its Sudo leftovers row (GAP-0711, GAP-0713). installHome is the
// install home the root run was started for; the chain also returns the store
// that home's config moved the data to.
func RootLeftoversRemedy(installHome string) string {
	command, note := rootGatewayRecoverySteps(installHome)
	lead := "stop"
	if note != "" {
		lead = note + "Then stop"
	}
	return lead + " the gateway if it runs as root, give its files back to this account and start it as yourself: " + command
}
