// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// A teardown keeps a link at the Codex machine-policy folder (GAP-0773).
//
// The folder is C:\ProgramData\OpenAI\Codex. Install, ensure and repair write
// DefenseClaw's requirements there and refuse a reparse point on the path,
// which is right: they must not write through a link. A teardown, a read of
// the registry on the way to a teardown, and the removal of the machine
// requirements write nothing there. When an administrator has made the folder
// a junction (or a link sits on a parent), nothing of DefenseClaw is known to
// be behind it, so the teardown must not read, open, lock, write or delete
// anything behind it, must not fail on it, and names the link once.
//
// The standalone profile only. Secure Client keeps the strict trust walk it
// always ran, which fails closed on a link.

// windowsCodexMachineStandaloneProcess reports whether this process serves the
// standalone profile, from the protected profile pin every standalone service
// and lifecycle helper carries (a hook never carries it). Tests replace it.
var windowsCodexMachineStandaloneProcess = func() bool {
	return managed.IsStandaloneProfile(managed.NormalizeEnterpriseProfile(os.Getenv(managed.EnterpriseProfileEnv)))
}

// windowsCodexMachineReparseProbe finds the first reparse point on the path or
// one of its parents, without following it. Tests replace it with injected
// results.
var windowsCodexMachineReparseProbe = findWindowsCodexMachineReparsePoint

func findWindowsCodexMachineReparsePoint(path string) (string, error) {
	current := filepath.Clean(path)
	for {
		ptr, err := winpath.UTF16Ptr(current)
		if err != nil {
			return "", err
		}
		attrs, err := windows.GetFileAttributes(ptr)
		if err == nil && attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return current, nil
		}
		if err != nil && err != windows.ERROR_FILE_NOT_FOUND && err != windows.ERROR_PATH_NOT_FOUND {
			return "", fmt.Errorf("inspect Codex machine path %s: %w", current, err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", nil
		}
		current = parent
	}
}

var windowsCodexMachineKept = struct {
	sync.Mutex
	paths map[string]string
}{paths: map[string]string{}}

func noteWindowsCodexMachineFolderKept(folder, kept string) {
	windowsCodexMachineKept.Lock()
	_, seen := windowsCodexMachineKept.paths[kept]
	windowsCodexMachineKept.paths[kept] = folder
	windowsCodexMachineKept.Unlock()
	if seen {
		return
	}
	managed.EmitResilienceEvent(managed.MarkerBoundary, map[string]string{
		"path":   kept,
		"folder": folder,
		"reason": "a link or a non-folder sits at the Codex machine-policy folder: the link is not followed, changed or removed, and nothing of DefenseClaw is read or written behind it",
	})
}

// WindowsCodexMachineFoldersKept returns, sorted, the paths this process's
// teardown kept at the Codex machine-policy folder because a link sits there.
func WindowsCodexMachineFoldersKept() []string {
	windowsCodexMachineKept.Lock()
	defer windowsCodexMachineKept.Unlock()
	out := make([]string, 0, len(windowsCodexMachineKept.paths))
	for path := range windowsCodexMachineKept.paths {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// WindowsCodexMachineFolderKept inspects the Codex machine-policy folder for a
// teardown without creating, opening or following anything. It returns the
// path of the link (a reparse point on the folder or on a parent) or of the
// folder itself when something that is not a folder sits there, and names it
// once. It returns "" when the folder is absent or plain, and always outside
// the standalone profile.
func WindowsCodexMachineFolderKept() (string, error) {
	if !windowsCodexMachineStandaloneProcess() {
		return "", nil
	}
	programData, err := windowsCodexMachineProgramData()
	if err != nil {
		return "", fmt.Errorf("resolve ProgramData: %w", err)
	}
	folder := filepath.Join(programData, "OpenAI", "Codex")
	kept, err := windowsCodexMachineReparseProbe(folder)
	if err != nil {
		return "", err
	}
	if kept == "" {
		info, statErr := os.Lstat(folder)
		switch {
		case errors.Is(statErr, os.ErrNotExist):
			return "", nil
		case statErr != nil:
			return "", fmt.Errorf("inspect Codex machine policy folder %s: %w", folder, statErr)
		case !info.IsDir():
			kept = folder
		}
	}
	if kept != "" {
		noteWindowsCodexMachineFolderKept(folder, kept)
	}
	return kept, nil
}

// windowsCodexMachineLinkKeptDetail is what a teardown says about a kept link:
// kept, not verified, and what that can leave behind.
func windowsCodexMachineLinkKeptDetail(kept string) string {
	return "kept, not verified: a link sits at " + kept +
		"; DefenseClaw does not follow, change or remove it and did not read what is behind it, " +
		"so a Codex requirement there may still name the DefenseClaw hook binary that the uninstall removes"
}

// ResolveWindowsCodexManagedRuntimeRegistryForTeardown is the registry read a
// teardown makes. A link at the Codex folder is not read through: the result
// is an empty registry with Kept set to the link, and the caller keeps the
// link. Anything else is ResolveWindowsCodexManagedRuntimeRegistry.
func ResolveWindowsCodexManagedRuntimeRegistryForTeardown(
	hookExecutable string,
) (WindowsCodexManagedRuntimeRegistry, error) {
	kept, err := WindowsCodexMachineFolderKept()
	if err != nil {
		return WindowsCodexManagedRuntimeRegistry{}, err
	}
	if kept != "" {
		return WindowsCodexManagedRuntimeRegistry{Kept: kept}, nil
	}
	return ResolveWindowsCodexManagedRuntimeRegistry(hookExecutable)
}
