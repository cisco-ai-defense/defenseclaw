// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package systemdunits

import (
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0279: a hook guardian started before the clean-session
// folder existed saw it read-only (ProtectSystem=strict; the "-" entry of a
// missing path binds nothing) and refused every foreign-hook removal of an
// account with entries until it was restarted. Both guardian units create
// the folder from the tmpfiles.d entry, outside the sandbox, before the
// guardian starts, so their ReadWritePaths entry is always bound. The
// gateway does not create it: a gateway that started without the folder
// writes no entries (its outage calls stay blocked), and one that created
// it could write entries a guardian started earlier cannot remove.
func TestGuardianUnitsCreateTheCleanSessionFolderBeforeTheyStart(t *testing.T) {
	const folder = "/var/lib/defenseclaw-foreign-hook-clean"
	data, err := ReadFile(TmpfilesName)
	if err != nil {
		t.Fatal(err)
	}
	var entries []string
	for _, line := range strings.Split(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[1] == folder {
			entries = append(entries, strings.Join(fields, " "))
		}
	}
	if len(entries) != 1 || entries[0] != "d "+folder+" 0711 defenseclaw defenseclaw -" {
		t.Fatalf("tmpfiles.d must create %s once, 0711 for the service account: %v", folder, entries)
	}
	create := "ExecStartPre=-+/usr/bin/systemd-tmpfiles --create --prefix=" + folder
	for unit, wantCreate := range map[string]bool{
		"defenseclaw-hook-guardian.service":           true,
		"defenseclaw-hook-guardian-reconcile.service": true,
		"defenseclaw-gateway.service":                 false,
	} {
		data, err := ReadFile(unit)
		if err != nil {
			t.Fatal(err)
		}
		var pre []string
		writable := false
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ExecStartPre=") {
				pre = append(pre, line)
			}
			if value, ok := strings.CutPrefix(line, "ReadWritePaths="); ok {
				for _, path := range strings.Fields(value) {
					writable = writable || path == "-"+folder
				}
			}
		}
		if !writable {
			t.Errorf("%s: ReadWritePaths lacks -%s", unit, folder)
		}
		created := len(pre) == 1 && pre[0] == create
		if wantCreate && !created {
			t.Errorf("%s: want exactly %q before the start, got %v", unit, create, pre)
		}
		if !wantCreate && len(pre) != 0 {
			t.Errorf("%s: no ExecStartPre expected, got %v", unit, pre)
		}
	}
}

// The package postinstall calls systemd-tmpfiles --create on a live host.
// The socket directory must be created on that call as it was in 1.0.3.
func TestHookSocketTmpfilesEntryAppliesOnLiveInstall(t *testing.T) {
	data, err := ReadFile(TmpfilesName)
	if err != nil {
		t.Fatal(err)
	}
	const socketDir = "/run/defenseclaw-hook"
	var entries [][]string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == socketDir {
			entries = append(entries, fields)
		}
	}
	if len(entries) != 1 || len(entries[0]) != 6 || strings.Join(entries[0], " ") != "d /run/defenseclaw-hook 0755 defenseclaw defenseclaw -" {
		t.Fatalf("live tmpfiles must create the hook socket directory once: %v", entries)
	}
}
