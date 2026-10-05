// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

// uninstall --purge kept a per-user install's %USERPROFILE%\.local\bin and
// its user Path entry. The purge removes DefenseClaw's files there; an
// emptied folder goes with its Path entry, and a folder other tools still use
// keeps both.
func TestPurgeWindowsUserBinariesRemovesTheFilesFolderAndPathEntry(t *testing.T) {
	original := windowsEnterpriseMutationIdentityCheck
	originalHives := windowsUserHives
	t.Cleanup(func() {
		windowsEnterpriseMutationIdentityCheck = original
		windowsUserHives = originalHives
	})
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	hives := fmt.Sprintf(`Software\DefenseClawTest\user-binaries-%d`, time.Now().UnixNano())
	windowsUserHives.root, windowsUserHives.path = registry.CURRENT_USER, hives
	t.Cleanup(func() {
		deleteRegistryTreeForTest(registry.CURRENT_USER, hives)
		// The shared parent goes only once no other test run uses it.
		_ = registry.DeleteKey(registry.CURRENT_USER, `Software\DefenseClawTest`)
	})

	sid := currentWindowsTestSID(t).String()
	home := filepath.Join(t.TempDir(), "home")
	binDir := filepath.Join(home, ".local", "bin")
	write := func(name, body string) {
		t.Helper()
		if err := os.MkdirAll(binDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	digest := func(body string) string {
		sum := sha256.Sum256([]byte(body))
		return hex.EncodeToString(sum[:])
	}
	install := func() {
		t.Helper()
		for _, name := range []string{"defenseclaw.cmd", "defenseclaw.exe", "defenseclaw-gateway.exe", "defenseclaw-acp.exe", "skill-scanner.cmd", "mcp-scanner.cmd", ".defenseclaw-source-root"} {
			write(name, name)
		}
		write("uv.exe", "uv")
		write("uvx.exe", "uvx")
		write("defenseclaw-uv.sha256", digest("uv")+"  uv.exe\n"+digest("uvx")+"  uvx.exe\n")
		if err := os.MkdirAll(filepath.Join(binDir, ".defenseclaw-install-custody", "old"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	env := hives + `\` + sid + `\Environment`
	setPath := func(value string) {
		t.Helper()
		key, _, err := registry.CreateKey(registry.CURRENT_USER, env, registry.SET_VALUE)
		if err != nil {
			t.Fatal(err)
		}
		defer key.Close()
		if err := key.SetExpandStringValue("Path", value); err != nil {
			t.Fatal(err)
		}
	}
	getPath := func() (string, uint32) {
		t.Helper()
		key, err := registry.OpenKey(registry.CURRENT_USER, env, registry.QUERY_VALUE)
		if err != nil {
			t.Fatal(err)
		}
		defer key.Close()
		value, kind, err := key.GetStringValue("Path")
		if err != nil {
			t.Fatal(err)
		}
		return value, kind
	}

	// Another tool still uses the folder: only DefenseClaw's files go.
	install()
	write("uvw.exe", "uvw-of-the-user")
	write("rg.exe", "ripgrep")
	setPath(`%USERPROFILE%\.local\bin;C:\Tools`)
	if _, err := PurgeWindowsUserBinaries(home, sid); err != nil {
		t.Fatalf("PurgeWindowsUserBinaries: %v", err)
	}
	entries, err := os.ReadDir(binDir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, entry := range entries {
		left = append(left, entry.Name())
	}
	sort.Strings(left)
	if got := strings.Join(left, ","); got != "rg.exe,uvw.exe" {
		t.Fatalf("%s holds %s, want rg.exe,uvw.exe", binDir, got)
	}
	if value, _ := getPath(); value != `%USERPROFILE%\.local\bin;C:\Tools` {
		t.Fatalf("the Path entry of a folder still in use went: %q", value)
	}

	// Nothing else is left: the folder and its Path entry go, and the other
	// entries keep their text and the value its kind.
	for _, name := range []string{"rg.exe", "uvw.exe"} {
		if err := os.Remove(filepath.Join(binDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	install()
	setPath(`%SystemRoot%\system32;"` + binDir + `\";C:\Tools`)
	removed, err := PurgeWindowsUserBinaries(home, sid)
	if err != nil {
		t.Fatalf("PurgeWindowsUserBinaries: %v", err)
	}
	if _, err := os.Lstat(binDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the emptied %s stayed: %v", binDir, err)
	}
	if value, kind := getPath(); value != `%SystemRoot%\system32;C:\Tools` || kind != registry.EXPAND_SZ {
		t.Fatalf("Path %q (kind %d) after the purge", value, kind)
	}
	if !strings.Contains(strings.Join(removed, "\n"), "Path entry "+binDir) {
		t.Fatalf("the result does not name the Path entry: %v", removed)
	}

	// A rerun, or no folder at all, is not an error.
	if _, err := PurgeWindowsUserBinaries(home, sid); err != nil {
		t.Fatalf("rerun: %v", err)
	}

	// A signed-out account (no loaded hive) keeps its Path entry, and the
	// error says so.
	install()
	deleteRegistryTreeForTest(registry.CURRENT_USER, hives)
	if _, err := PurgeWindowsUserBinaries(home, sid); !errors.Is(err, ErrWindowsUserHiveNotLoaded) {
		t.Fatalf("signed-out account: %v, want ErrWindowsUserHiveNotLoaded", err)
	}
	if _, err := os.Lstat(binDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the emptied %s stayed for a signed-out account: %v", binDir, err)
	}
}

func deleteRegistryTreeForTest(root registry.Key, path string) {
	key, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		names, _ := key.ReadSubKeyNames(-1)
		key.Close()
		for _, name := range names {
			deleteRegistryTreeForTest(root, path+`\`+name)
		}
	}
	_ = registry.DeleteKey(root, path)
}
