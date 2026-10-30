//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsEnterpriseProfileHome is one local or domain account profile that
// ProfileList records on this computer.
type windowsEnterpriseProfileHome struct {
	SID  string
	Home string
}

// windowsEnterpriseProfileHomes lists the account profiles on this computer;
// tests replace it.
var windowsEnterpriseProfileHomes = listWindowsEnterpriseProfileHomes

// windowsEnterpriseTombstoneUserStatePurge reports whether the standalone
// deployment record is an uninstall tombstone that recorded the per-user
// purge (Setup PURGE=1); tests replace it.
var windowsEnterpriseTombstoneUserStatePurge = readWindowsEnterpriseTombstoneUserStatePurge

// windowsEnterpriseStandaloneStateRootGone reports whether the standalone
// StateRoot no longer exists, the end state of a completed purge; tests
// replace it.
var windowsEnterpriseStandaloneStateRootGone = func() bool {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return false
	}
	_, err = os.Lstat(roots.StateRoot)
	return os.IsNotExist(err)
}

var windowsEnterpriseProfileSIDPattern = lazyregexp.New(`^S-1-(5-21|12-1)-[0-9-]+$`)

func listWindowsEnterpriseProfileHomes() []windowsEnterpriseProfileHome {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`,
		registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	sort.Strings(names)
	var homes []windowsEnterpriseProfileHome
	for _, sid := range names {
		if !windowsEnterpriseProfileSIDPattern.MatchString(sid) {
			continue
		}
		profile, err := registry.OpenKey(key, sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		home, _, err := profile.GetStringValue("ProfileImagePath")
		profile.Close()
		if err != nil {
			continue
		}
		if expanded, err := registry.ExpandString(home); err == nil {
			home = expanded
		}
		if home = strings.TrimSpace(home); home != "" {
			homes = append(homes, windowsEnterpriseProfileHome{SID: sid, Home: home})
		}
	}
	return homes
}

// windowsEnterpriseLeftoverUserStateFolders names each account whose
// %USERPROFILE%\.defenseclaw is still a real folder ("account (SID): path").
// It only reads: with no deployment record nothing can tell DefenseClaw's
// files there from the account's own (GAP-0533).
func windowsEnterpriseLeftoverUserStateFolders() []string {
	var labels []string
	for _, profile := range windowsEnterpriseProfileHomes() {
		folder := filepath.Join(profile.Home, ".defenseclaw")
		info, err := os.Lstat(folder)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		labels = append(labels, windowsPrincipalLabel(profile.SID)+": "+folder)
	}
	return labels
}

// addWindowsEnterpriseLeftoverUserStateWarning names the per-user folders a
// purge with no deployment left to remove still finds: a killed PURGE=1
// whose machine purge Setup's recovery finished, or an earlier uninstall,
// kept them, and its result named them once or never. The run that asked for
// the purge, or the recovery of one, says so instead of a silent success
// (GAP-2094). A plain uninstall keeps these folders by design and is not
// asked.
func addWindowsEnterpriseLeftoverUserStateWarning(result *enterprisestatus.Result, recovered bool) {
	folders := windowsEnterpriseLeftoverUserStateFolders()
	if len(folders) == 0 {
		return
	}
	intro := "no DefenseClaw deployment is installed, so this purge had nothing left to remove, but"
	if recovered {
		intro = "the recovery finished the interrupted /uninstall PURGE=1 and removed the machine deployment, but"
	}
	result.AddWarning("per_user_state_remaining", fmt.Sprintf(
		"%s %d account(s) still have a DefenseClaw per-user folder %%USERPROFILE%%\\.defenseclaw. "+
			"An uninstall keeps it for an account whose agent registrations stay (a signed-out or disconnected account; its connector_backups restore them), "+
			"or for one it could not clean when it was interrupted. With no deployment record left, Setup cannot tell DefenseClaw's files there from the account's own, so it removes nothing. "+
			"To remove a folder with its agent registrations, %s; if that account has no DefenseClaw registration left and runs no per-user DefenseClaw of its own, delete the folder as an administrator. Accounts: %s",
		intro, len(folders), windowsEnterpriseLocalSystemRemedy("/uninstall PURGE=1"), windowsEnterpriseBoundedLabels(folders)))
}

// readWindowsEnterpriseTombstoneUserStatePurge reads the per-user purge mode
// the standalone uninstall tombstone recorded at its commit. Anything but a
// readable tombstone with uninstall_purge_user_state_requested true is false:
// the answer only decides whether a recovery names leftover folders.
func readWindowsEnterpriseTombstoneUserStatePurge() bool {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return false
	}
	file, err := os.Open(roots.MetadataPath)
	if err != nil {
		return false
	}
	defer file.Close()
	const maximum = 128 << 10
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(body) > maximum {
		return false
	}
	var record struct {
		Installed *bool `json:"installed"`
		UserState *bool `json:"uninstall_purge_user_state_requested"`
	}
	if json.Unmarshal(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}), &record) != nil {
		return false
	}
	return record.Installed != nil && !*record.Installed && record.UserState != nil && *record.UserState
}
