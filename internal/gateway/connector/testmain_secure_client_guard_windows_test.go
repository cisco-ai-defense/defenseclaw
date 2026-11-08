// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// secureClientTrees are the shared Cisco Secure Client folders of the real
// machine (ProgramData and Program Files). The connector tests run against
// temp layouts (t.TempDir) and the package layout seams; a run that creates
// the tree itself, or a DefenseClaw* folder directly under it (GAP-0780, the
// DefenseClaw-Cert folder), wrote to the real machine. A root that cannot be
// resolved is left out: nothing there can be judged.
func secureClientTrees() []string {
	var trees []string
	for _, resolve := range []func() (string, error){winpath.TrustedProgramData, winpath.TrustedProgramFiles} {
		if base, err := resolve(); err == nil && base != "" {
			trees = append(trees, filepath.Join(base, "Cisco", "Cisco Secure Client"))
		}
	}
	return trees
}

// defenseClawChildPrefix starts the names of the folders the DefenseClaw
// module and its certification runs create under the tree.
const defenseClawChildPrefix = "defenseclaw"

// guardSecureClientTree records the real Secure Client folders now and
// returns the check that names what the run added. The check is skipped when
// a DefenseClaw or Cisco Secure Client service is installed: those services
// and the module write their own folders while the run goes on.
func guardSecureClientTree() func() []string {
	return guardSecureClientTreeWith(secureClientTrees(), installedSecureClientService)
}

func guardSecureClientTreeWith(trees []string, installedService func() string) func() []string {
	if name := installedService(); name != "" {
		fmt.Fprintf(os.Stderr, "note: the Cisco Secure Client folder guard is skipped, the %s service is installed\n", name)
		return func() []string { return nil }
	}
	return guardTreesAdditions(trees)
}

// installedSecureClientService returns the name of the first DefenseClaw
// (DefenseClaw*) or Cisco Secure Client (vpnagent, csc_*) Windows service on
// the machine, or "" when there is none or the service list cannot be read
// (the guard then stays on: it only judges the root and DefenseClaw* children).
func installedSecureClientService() string {
	handle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return ""
	}
	manager := &mgr.Mgr{Handle: handle}
	defer manager.Disconnect()
	names, err := manager.ListServices()
	if err != nil {
		return ""
	}
	sort.Strings(names)
	for _, name := range names {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, defenseClawChildPrefix) || strings.HasPrefix(lower, "csc_") || lower == "vpnagent" {
			return name
		}
	}
	return ""
}

type treeState struct {
	rootExists bool
	children   map[string]bool
}

func guardTreesAdditions(trees []string) func() []string {
	before := map[string]treeState{}
	for _, tree := range trees {
		before[tree] = readTreeState(tree)
	}
	return func() []string {
		var added []string
		for _, tree := range trees {
			was, now := before[tree], readTreeState(tree)
			if now.rootExists && !was.rootExists {
				added = append(added, tree)
			}
			for child := range now.children {
				if !was.children[child] {
					added = append(added, filepath.Join(tree, child))
				}
			}
		}
		sort.Strings(added)
		return added
	}
}

// readTreeState lists the tree root and its direct DefenseClaw* children
// only. It never opens a child: a pre-existing DefenseClaw* folder is owned
// by the services of the module. An absent or unreadable root has no children.
func readTreeState(tree string) treeState {
	state := treeState{children: map[string]bool{}}
	entries, err := os.ReadDir(tree)
	if err != nil {
		if info, statErr := os.Stat(tree); statErr == nil && info.IsDir() {
			state.rootExists = true
		}
		return state
	}
	state.rootExists = true
	for _, entry := range entries {
		if strings.HasPrefix(strings.ToLower(entry.Name()), defenseClawChildPrefix) {
			state.children[entry.Name()] = true
		}
	}
	return state
}
