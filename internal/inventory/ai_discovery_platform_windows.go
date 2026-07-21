// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	maxWindowsApplicationNames         = 4096
	maxWindowsStartMenuDepth           = 4
	maxWindowsRegistryDisplayNameUTF16 = 512
	windowsUninstallRegistry           = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
)

type windowsDiscoveryKnownFolderResolver func(*windows.KNOWNFOLDERID, uint32) (string, error)

type windowsApplicationSearchRoot struct {
	path             string
	recursive        bool
	includeDirectory bool
}

type windowsRegistryApplicationLocation struct {
	root registry.Key
	view uint32
}

func platformDiscoveryHomeDir() (string, error) {
	path, err := winpath.CurrentUserKnownFolderPathWithFlags(windows.FOLDERID_Profile, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return "", err
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("Windows Profile Known Folder is empty")
	}
	return filepath.Clean(path), nil
}

func platformDiscoveryVariable(name, home string) (string, bool) {
	var folderID *windows.KNOWNFOLDERID
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "HOME", "USERPROFILE":
		folderID = windows.FOLDERID_Profile
	case "APPDATA":
		folderID = windows.FOLDERID_RoamingAppData
	case "LOCALAPPDATA":
		folderID = windows.FOLDERID_LocalAppData
	case "PROGRAMDATA":
		folderID = windows.FOLDERID_ProgramData
	case "PROGRAMFILES":
		folderID = windows.FOLDERID_ProgramFiles
	case "PROGRAMFILES(X86)":
		folderID = windows.FOLDERID_ProgramFilesX86
	default:
		return os.LookupEnv(name)
	}
	if value := windowsKnownFolderValue(winpath.CurrentUserKnownFolderPathWithFlags, folderID); value != "" {
		return value, true
	}
	// Known Folder lookup should normally succeed. A caller-provided home is a
	// bounded fallback for stripped-down Windows images and deterministic tests;
	// process-level APPDATA overrides never become discovery roots.
	home = strings.TrimSpace(home)
	if home == "" {
		return "", false
	}
	switch folderID {
	case windows.FOLDERID_Profile:
		return filepath.Clean(home), true
	case windows.FOLDERID_RoamingAppData:
		return filepath.Join(home, "AppData", "Roaming"), true
	case windows.FOLDERID_LocalAppData:
		return filepath.Join(home, "AppData", "Local"), true
	default:
		return "", false
	}
}

func platformInstalledApplicationNames(_ string) []string {
	roots := windowsApplicationSearchRoots(winpath.CurrentUserKnownFolderPathWithFlags)
	names := collectWindowsApplicationNames(roots, nil)
	ordinaryNames := mergeWindowsApplicationNames(names, windowsRegistryApplicationNames())
	return mergeWindowsApplicationNames(
		windowsShellApplicationNames(),
		withoutReservedWindowsApplicationNames(ordinaryNames),
	)
}

func windowsApplicationSearchRoots(resolve windowsDiscoveryKnownFolderResolver) []windowsApplicationSearchRoot {
	var out []windowsApplicationSearchRoot
	seen := map[string]bool{}
	add := func(folderID *windows.KNOWNFOLDERID, recursive bool) {
		path := windowsKnownFolderValue(resolve, folderID)
		key := strings.ToLower(path)
		if path == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, windowsApplicationSearchRoot{
			path: path, recursive: recursive, includeDirectory: true,
		})
	}
	add(windows.FOLDERID_Programs, true)
	add(windows.FOLDERID_CommonPrograms, true)
	add(windows.FOLDERID_UserProgramFiles, false)
	add(windows.FOLDERID_ProgramFiles, false)
	add(windows.FOLDERID_ProgramFilesX86, false)
	return out
}

func collectWindowsApplicationNames(roots []windowsApplicationSearchRoot, seed []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] || len(out) >= maxWindowsApplicationNames {
			return
		}
		seen[value] = true
		out = append(out, value)
	}
	for _, value := range seed {
		add(value)
	}
	for _, root := range roots {
		if len(out) >= maxWindowsApplicationNames {
			break
		}
		if !root.recursive {
			children, err := os.ReadDir(root.path)
			if err != nil {
				continue
			}
			for _, child := range children {
				if child.IsDir() && root.includeDirectory {
					add(child.Name())
				} else if windowsApplicationShortcut(child.Name()) {
					add(child.Name())
				}
			}
			continue
		}

		_ = filepath.WalkDir(root.path, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if entry != nil && entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if len(out) >= maxWindowsApplicationNames {
				return filepath.SkipAll
			}
			if path == root.path {
				return nil
			}
			relative, err := filepath.Rel(root.path, path)
			if err != nil {
				return nil
			}
			depth := strings.Count(filepath.Clean(relative), string(os.PathSeparator)) + 1
			if entry.IsDir() {
				if root.includeDirectory {
					add(entry.Name())
				}
				if depth >= maxWindowsStartMenuDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if windowsApplicationShortcut(entry.Name()) {
				add(entry.Name())
			}
			return nil
		})
	}
	sort.Strings(out)
	return out
}

func windowsApplicationShortcut(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, suffix := range []string{".lnk", ".appref-ms", ".exe", ".url"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func windowsRegistryApplicationNames() []string {
	locations := []windowsRegistryApplicationLocation{
		{registry.CURRENT_USER, registry.WOW64_64KEY},
		{registry.CURRENT_USER, registry.WOW64_32KEY},
		{registry.LOCAL_MACHINE, registry.WOW64_64KEY},
		{registry.LOCAL_MACHINE, registry.WOW64_32KEY},
	}
	return windowsRegistryApplicationNamesAt(locations, windowsUninstallRegistry)
}

func windowsRegistryApplicationNamesAt(locations []windowsRegistryApplicationLocation, keyPath string) []string {
	var out []string
	for _, location := range locations {
		if len(out) >= maxWindowsApplicationNames {
			break
		}
		key, err := registry.OpenKey(location.root, keyPath, registry.READ|location.view)
		if err != nil {
			continue
		}
		names, readErr := key.ReadSubKeyNames(maxWindowsApplicationNames - len(out))
		_ = key.Close()
		if readErr != nil && readErr != io.EOF {
			continue
		}
		for _, name := range names {
			subkey, err := registry.OpenKey(location.root, keyPath+`\`+name, registry.QUERY_VALUE|location.view)
			if err != nil {
				continue
			}
			displayName, valueOK := boundedWindowsRegistryDisplayName(subkey)
			_ = subkey.Close()
			if valueOK && strings.TrimSpace(displayName) != "" {
				out = append(out, displayName)
			}
		}
	}
	return out
}

func boundedWindowsRegistryDisplayName(key registry.Key) (string, bool) {
	// GetStringValue grows its buffer to the size advertised by the registry.
	// DisplayName can be user-controlled under HKCU, so use one fixed-size read
	// and reject ERROR_MORE_DATA instead of allocating from that advertised size.
	var data [2 * (maxWindowsRegistryDisplayNameUTF16 + 1)]byte
	n, valueType, err := key.GetValue("DisplayName", data[:])
	if err != nil || n <= 0 || n > len(data) {
		return "", false
	}
	return decodeBoundedWindowsRegistryString(data[:n], valueType, maxWindowsRegistryDisplayNameUTF16)
}

func decodeBoundedWindowsRegistryString(data []byte, valueType uint32, maximumUTF16 int) (string, bool) {
	if (valueType != registry.SZ && valueType != registry.EXPAND_SZ) ||
		maximumUTF16 <= 0 || len(data) < 2 || len(data)%2 != 0 {
		return "", false
	}
	unitCount := len(data) / 2
	if unitCount-1 > maximumUTF16 || windowsRegistryUTF16Unit(data, unitCount-1) != 0 {
		return "", false
	}

	// Validate before allocating the decoded string. In particular, reject
	// embedded NULs and unpaired surrogates rather than silently truncating or
	// replacing attacker-controlled malformed input.
	for i := 0; i < unitCount-1; i++ {
		unit := windowsRegistryUTF16Unit(data, i)
		switch {
		case unit == 0 || unit >= 0xdc00 && unit <= 0xdfff:
			return "", false
		case unit >= 0xd800 && unit <= 0xdbff:
			if i+1 >= unitCount-1 {
				return "", false
			}
			next := windowsRegistryUTF16Unit(data, i+1)
			if next < 0xdc00 || next > 0xdfff {
				return "", false
			}
			i++
		}
	}

	runes := make([]rune, 0, unitCount-1)
	for i := 0; i < unitCount-1; i++ {
		unit := windowsRegistryUTF16Unit(data, i)
		if unit >= 0xd800 && unit <= 0xdbff {
			next := windowsRegistryUTF16Unit(data, i+1)
			runes = append(runes, utf16.DecodeRune(rune(unit), rune(next)))
			i++
			continue
		}
		runes = append(runes, rune(unit))
	}
	return string(runes), true
}

func windowsRegistryUTF16Unit(data []byte, index int) uint16 {
	offset := index * 2
	return uint16(data[offset]) | uint16(data[offset+1])<<8
}

func mergeWindowsApplicationNames(groups ...[]string) []string {
	var roots []windowsApplicationSearchRoot
	var seed []string
	for _, group := range groups {
		seed = append(seed, group...)
	}
	return collectWindowsApplicationNames(roots, seed)
}

func platformEditorExtensionRoots(_ string) []string {
	return windowsEditorExtensionRoots(winpath.CurrentUserKnownFolderPathWithFlags)
}

func windowsEditorExtensionRoots(resolve windowsDiscoveryKnownFolderResolver) []string {
	var roots []string
	if roaming := windowsKnownFolderValue(resolve, windows.FOLDERID_RoamingAppData); roaming != "" {
		for _, product := range []string{"Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"} {
			roots = append(roots, filepath.Join(roaming, product, "User", "globalStorage"))
		}
		if matches, err := filepath.Glob(filepath.Join(roaming, "JetBrains", "*", "plugins")); err == nil {
			roots = append(roots, matches...)
		}
	}
	if local := windowsKnownFolderValue(resolve, windows.FOLDERID_LocalAppData); local != "" {
		if matches, err := filepath.Glob(filepath.Join(local, "JetBrains", "*", "plugins")); err == nil {
			roots = append(roots, matches...)
		}
	}
	return roots
}

func platformShellHistoryPaths(_ string) []string {
	return windowsShellHistoryPaths(winpath.CurrentUserKnownFolderPathWithFlags)
}

func windowsShellHistoryPaths(resolve windowsDiscoveryKnownFolderResolver) []string {
	roaming := windowsKnownFolderValue(resolve, windows.FOLDERID_RoamingAppData)
	if roaming == "" {
		return nil
	}
	return []string{
		filepath.Join(roaming, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
		filepath.Join(roaming, "Microsoft", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
	}
}

func platformModelScanRoots(_ string) []modelScanRoot {
	return windowsModelScanRoots(winpath.CurrentUserKnownFolderPathWithFlags)
}

func windowsModelScanRoots(resolve windowsDiscoveryKnownFolderResolver) []modelScanRoot {
	var roots []modelScanRoot
	if local := windowsKnownFolderValue(resolve, windows.FOLDERID_LocalAppData); local != "" {
		roots = append(roots, modelScanRoot{
			path: filepath.Join(local, "nomic.ai", "GPT4All"), provider: "gpt4all", specialized: true,
		})
	}
	if roaming := windowsKnownFolderValue(resolve, windows.FOLDERID_RoamingAppData); roaming != "" {
		roots = append(roots,
			modelScanRoot{path: filepath.Join(roaming, "Jan", "data", "models"), provider: "jan", specialized: true},
			modelScanRoot{path: filepath.Join(roaming, "anythingllm-desktop", "storage", "models"), provider: "anythingllm", specialized: true},
		)
	}
	return roots
}

func windowsKnownFolderValue(resolve windowsDiscoveryKnownFolderResolver, folderID *windows.KNOWNFOLDERID) string {
	value, err := resolve(folderID, windows.KF_FLAG_DONT_VERIFY)
	if err != nil || strings.TrimSpace(value) == "" {
		return ""
	}
	return filepath.Clean(value)
}
