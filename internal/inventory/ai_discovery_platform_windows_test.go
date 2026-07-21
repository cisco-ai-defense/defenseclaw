// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestCollectWindowsApplicationNamesCoversStartMenuAndProgramDirectories(t *testing.T) {
	tmp := t.TempDir()
	startMenu := filepath.Join(tmp, "Start Menu", "Programs")
	programs := filepath.Join(tmp, "Programs")
	mustWrite(t, filepath.Join(startMenu, "AI Tools", "Cursor.lnk"), "shortcut")
	mustWrite(t, filepath.Join(startMenu, "Jan.appref-ms"), "shortcut")
	mustWrite(t, filepath.Join(startMenu, "README.txt"), "not an application")
	if err := os.MkdirAll(filepath.Join(programs, "LM Studio"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := collectWindowsApplicationNames([]windowsApplicationSearchRoot{
		{path: startMenu, recursive: true, includeDirectory: true},
		{path: programs, includeDirectory: true},
	}, []string{"GPT4All", "gpt4all"})
	if !slices.IsSorted(got) {
		t.Fatalf("application names are not deterministic: %v", got)
	}
	for _, want := range []string{"ai tools", "cursor.lnk", "jan.appref-ms", "lm studio", "gpt4all"} {
		if !slices.Contains(got, want) {
			t.Errorf("Windows application inventory missing %q: %v", want, got)
		}
	}
	if slices.Contains(got, "readme.txt") {
		t.Errorf("non-application Start Menu file was inventoried: %v", got)
	}
	if count := countString(got, "gpt4all"); count != 1 {
		t.Errorf("case-insensitive registry/filesystem dedupe count = %d, want 1: %v", count, got)
	}
}

func TestWindowsKnownFolderDiscoveryLocations(t *testing.T) {
	tmp := t.TempDir()
	paths := map[*windows.KNOWNFOLDERID]string{
		windows.FOLDERID_Profile:          filepath.Join(tmp, "profile"),
		windows.FOLDERID_RoamingAppData:   filepath.Join(tmp, "roaming"),
		windows.FOLDERID_LocalAppData:     filepath.Join(tmp, "local"),
		windows.FOLDERID_Programs:         filepath.Join(tmp, "start-user"),
		windows.FOLDERID_CommonPrograms:   filepath.Join(tmp, "start-common"),
		windows.FOLDERID_UserProgramFiles: filepath.Join(tmp, "user-programs"),
		windows.FOLDERID_ProgramFiles:     filepath.Join(tmp, "program-files"),
		windows.FOLDERID_ProgramFilesX86:  filepath.Join(tmp, "program-files-x86"),
	}
	resolve := func(id *windows.KNOWNFOLDERID, flags uint32) (string, error) {
		if flags != windows.KF_FLAG_DONT_VERIFY {
			t.Fatalf("Known Folder flags = %#x, want KF_FLAG_DONT_VERIFY", flags)
		}
		if value := paths[id]; value != "" {
			return value, nil
		}
		return "", errors.New("not configured")
	}

	applicationRoots := windowsApplicationSearchRoots(resolve)
	if len(applicationRoots) != 5 {
		t.Fatalf("application roots = %v, want five Known Folder roots", applicationRoots)
	}
	if !applicationRoots[0].recursive || !applicationRoots[1].recursive {
		t.Fatalf("Start Menu roots must be recursive: %v", applicationRoots)
	}

	jetBrains := filepath.Join(paths[windows.FOLDERID_RoamingAppData], "JetBrains", "IdeaIC2026.1", "plugins")
	if err := os.MkdirAll(jetBrains, 0o755); err != nil {
		t.Fatal(err)
	}
	editorRoots := windowsEditorExtensionRoots(resolve)
	for _, want := range []string{
		filepath.Join(paths[windows.FOLDERID_RoamingAppData], "Code", "User", "globalStorage"),
		filepath.Join(paths[windows.FOLDERID_RoamingAppData], "Cursor", "User", "globalStorage"),
		jetBrains,
	} {
		if !slices.Contains(editorRoots, want) {
			t.Errorf("editor roots missing %q: %v", want, editorRoots)
		}
	}

	history := windowsShellHistoryPaths(resolve)
	if len(history) != 2 || !strings.Contains(history[0], `Windows\PowerShell\PSReadLine`) ||
		!strings.Contains(history[1], `Microsoft\PowerShell\PSReadLine`) {
		t.Fatalf("PowerShell history paths = %v", history)
	}

	modelRoots := windowsModelScanRoots(resolve)
	wantedModels := map[string]string{
		"gpt4all":     filepath.Join(paths[windows.FOLDERID_LocalAppData], "nomic.ai", "GPT4All"),
		"jan":         filepath.Join(paths[windows.FOLDERID_RoamingAppData], "Jan", "data", "models"),
		"anythingllm": filepath.Join(paths[windows.FOLDERID_RoamingAppData], "anythingllm-desktop", "storage", "models"),
	}
	for _, root := range modelRoots {
		if want := wantedModels[root.provider]; want != root.path || !root.specialized {
			t.Errorf("unexpected Windows model root: %+v (want %q)", root, want)
		}
		delete(wantedModels, root.provider)
	}
	if len(wantedModels) != 0 {
		t.Errorf("missing Windows model roots: %v", wantedModels)
	}
}

func TestWindowsRegistryApplicationNamesReadsBoundedDisplayNames(t *testing.T) {
	keyPath := fmt.Sprintf(`Software\Classes\DefenseClawAIDiscoveryTest-%d-%d`, os.Getpid(), time.Now().UnixNano())
	fixtureKeys := []string{"boundary", "cursor", "missing-display-name", "oversized", "wrong-type"}
	t.Cleanup(func() {
		for _, key := range fixtureKeys {
			_ = registry.DeleteKey(registry.CURRENT_USER, keyPath+`\`+key)
		}
		_ = registry.DeleteKey(registry.CURRENT_USER, keyPath)
	})
	for _, fixture := range []struct {
		key, displayName string
		wrongType        bool
	}{
		{key: "boundary", displayName: strings.Repeat("b", maxWindowsRegistryDisplayNameUTF16)},
		{key: "cursor", displayName: "Cursor"},
		{key: "missing-display-name"},
		{key: "oversized", displayName: strings.Repeat("x", maxWindowsRegistryDisplayNameUTF16+1)},
		{key: "wrong-type", displayName: "not a registry string", wrongType: true},
	} {
		key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath+`\`+fixture.key, registry.ALL_ACCESS)
		if err != nil {
			t.Fatal(err)
		}
		if fixture.displayName != "" {
			var valueErr error
			if fixture.wrongType {
				valueErr = key.SetBinaryValue("DisplayName", []byte(fixture.displayName))
			} else {
				valueErr = key.SetStringValue("DisplayName", fixture.displayName)
			}
			if valueErr != nil {
				_ = key.Close()
				t.Fatal(valueErr)
			}
		}
		if err := key.Close(); err != nil {
			t.Fatal(err)
		}
	}
	got := windowsRegistryApplicationNamesAt(
		[]windowsRegistryApplicationLocation{{root: registry.CURRENT_USER}}, keyPath,
	)
	if !slices.Contains(got, "Cursor") ||
		!slices.Contains(got, strings.Repeat("b", maxWindowsRegistryDisplayNameUTF16)) || len(got) != 2 {
		t.Fatalf("registry application display names = %v, want Cursor and the exact-size boundary", got)
	}
}

func TestDecodeBoundedWindowsRegistryStringRejectsMalformedValues(t *testing.T) {
	encode := func(units ...uint16) []byte {
		out := make([]byte, len(units)*2)
		for i, unit := range units {
			out[i*2] = byte(unit)
			out[i*2+1] = byte(unit >> 8)
		}
		return out
	}
	for _, tc := range []struct {
		name      string
		data      []byte
		valueType uint32
	}{
		{name: "empty", valueType: registry.SZ},
		{name: "odd byte count", data: []byte{'A', 0, 0}, valueType: registry.SZ},
		{name: "missing terminator", data: encode('A'), valueType: registry.SZ},
		{name: "embedded nul", data: encode('A', 0, 'B', 0), valueType: registry.SZ},
		{name: "unpaired high surrogate", data: encode(0xd83d, 0), valueType: registry.SZ},
		{name: "unpaired low surrogate", data: encode(0xde00, 0), valueType: registry.SZ},
		{name: "wrong type", data: encode('A', 0), valueType: registry.BINARY},
		{name: "over limit", data: encode('A', 'B', 0), valueType: registry.SZ},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := decodeBoundedWindowsRegistryString(tc.data, tc.valueType, 1); ok {
				t.Fatalf("malformed registry string decoded as %q", got)
			}
		})
	}

	validEmoji := encode('A', 0xd83d, 0xde00, 0)
	if got, ok := decodeBoundedWindowsRegistryString(validEmoji, registry.EXPAND_SZ, 3); !ok || got != "A😀" {
		t.Fatalf("valid surrogate pair decoded as (%q, %t), want (A😀, true)", got, ok)
	}
}

func TestWindowsReservedDiscoveryVariablesIgnoreProcessOverrides(t *testing.T) {
	for _, tc := range []struct {
		name     string
		folderID *windows.KNOWNFOLDERID
	}{
		{name: "HOME", folderID: windows.FOLDERID_Profile},
		{name: "USERPROFILE", folderID: windows.FOLDERID_Profile},
		{name: "APPDATA", folderID: windows.FOLDERID_RoamingAppData},
		{name: "LOCALAPPDATA", folderID: windows.FOLDERID_LocalAppData},
		{name: "PROGRAMDATA", folderID: windows.FOLDERID_ProgramData},
		{name: "PROGRAMFILES", folderID: windows.FOLDERID_ProgramFiles},
		{name: "PROGRAMFILES(X86)", folderID: windows.FOLDERID_ProgramFilesX86},
	} {
		t.Run(tc.name, func(t *testing.T) {
			override := filepath.Join(t.TempDir(), "untrusted-override")
			t.Setenv(tc.name, override)
			got, ok := platformDiscoveryVariable(tc.name, t.TempDir())
			if !ok || strings.EqualFold(filepath.Clean(got), filepath.Clean(override)) {
				t.Fatalf("%s expansion trusted the process override: (%q, %t)", tc.name, got, ok)
			}
			want := windowsKnownFolderValue(winpathResolverForTest, tc.folderID)
			if want == "" {
				t.Fatalf("%s token-bound Known Folder is unavailable", tc.name)
			}
			if !strings.EqualFold(filepath.Clean(got), want) {
				t.Fatalf("%s expansion = %q, want token-bound Known Folder %q", tc.name, got, want)
			}
		})
	}
}

func winpathResolverForTest(id *windows.KNOWNFOLDERID, flags uint32) (string, error) {
	return winpath.CurrentUserKnownFolderPathWithFlags(id, flags)
}

func countString(values []string, want string) int {
	count := 0
	for _, value := range values {
		if value == want {
			count++
		}
	}
	return count
}
