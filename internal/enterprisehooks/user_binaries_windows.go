// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// The per-user install (scripts/install.ps1) puts these in
// %USERPROFILE%\.local\bin. Every name is DefenseClaw's own.
var windowsUserBinaryNames = []string{
	"defenseclaw.cmd",
	"defenseclaw",
	"defenseclaw-gateway.exe",
	"defenseclaw-acp.exe",
	"defenseclaw-hook.exe",
	"skill-scanner.cmd",
	"mcp-scanner.cmd",
	"defenseclaw-hook-state.json",
	".defenseclaw-source-root",
	".defenseclaw-install-custody",
}

// windowsUserUVNames are the uv files install.ps1 may have put there; its
// record lists each one's digest, and only an unchanged one goes.
var windowsUserUVNames = map[string]bool{"uv.exe": true, "uvx.exe": true, "uvw.exe": true}

const (
	windowsUserUVRecord         = "defenseclaw-uv.sha256"
	windowsUserUVRecordMaxBytes = 4096
)

// windowsUserHives holds the loaded user hives, one subkey per SID.
// Replaceable in tests, which cannot load a hive under HKEY_USERS.
var windowsUserHives = struct {
	root registry.Key
	path string
}{root: registry.USERS}

// ErrWindowsUserHiveNotLoaded reports that an account's registry hive is not
// loaded (it is signed out), so its user environment cannot be changed.
var ErrWindowsUserHiveNotLoaded = errors.New("its registry hive is not loaded while it is signed out")

// PurgeWindowsUserBinaries removes, as LocalSystem, what the per-user
// install put in an enrolled account's %USERPROFILE%\.local\bin, for the
// standalone Windows uninstall with purge: the DefenseClaw launchers and
// binaries, the uv files that still match the installer's record, the record
// and the installer's bookkeeping. Every step stays inside the folder and
// follows no link. When the folder is then empty it goes too, and so does its
// entry in the account's user Path (HKEY_USERS\<SID>\Environment), which the
// install added; a folder other tools still use, and its Path entry, stay.
// It returns the paths it removed. A missing folder is not an error.
func PurgeWindowsUserBinaries(rawHome, rawSID string) ([]string, error) {
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return nil, err
	}
	home, sid, err := validateWindowsEnterpriseHome(rawHome, rawSID)
	if err != nil {
		return nil, err
	}
	binDir := filepath.Join(home, ".local", "bin")
	removed, emptied, err := removeWindowsUserBinariesIn(home, binDir)
	if err != nil {
		return removed, err
	}
	if !emptied {
		return removed, nil
	}
	if err := os.Remove(binDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return removed, fmt.Errorf("enterprise hooks: remove the empty %s: %w", binDir, err)
	}
	removed = append(removed, binDir)
	changed, err := removeWindowsUserPathEntry(sid.String(), home, binDir)
	if err != nil {
		return removed, fmt.Errorf("enterprise hooks: the user Path entry %s stays: %w; remove it from that account's Path", binDir, err)
	}
	if changed {
		removed = append(removed, `Path entry `+binDir)
	}
	return removed, nil
}

// removeWindowsUserBinariesIn removes DefenseClaw's entries from binDir and
// reports whether binDir is then empty (true when it does not exist).
func removeWindowsUserBinariesIn(home, binDir string) ([]string, bool, error) {
	for _, dir := range []string{filepath.Dir(binDir), binDir} {
		info, err := os.Lstat(dir)
		if errors.Is(err, os.ErrNotExist) {
			return nil, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return nil, false, fmt.Errorf("enterprise hooks: refusing to clean %s, which is not a plain folder", dir)
		}
	}
	// The account can rename or replace its own folder: the pin (which
	// shares no delete access) holds it, and the root must be that folder.
	pin, err := openWindowsUserStatePin(binDir)
	if err != nil {
		return nil, false, err
	}
	defer pin.Close()
	root, err := os.OpenRoot(binDir)
	if err != nil {
		return nil, false, err
	}
	defer root.Close()
	pinned, err := pin.Stat()
	if err != nil {
		return nil, false, err
	}
	opened, err := root.Stat(".")
	if err != nil {
		return nil, false, err
	}
	if !os.SameFile(pinned, opened) {
		return nil, false, fmt.Errorf("enterprise hooks: refusing to clean %s, which changed while it was opened", binDir)
	}

	var removed []string
	var errs []error
	names := append([]string(nil), windowsUserBinaryNames...)
	names = append(names, windowsInstallerUVFiles(root)...)
	for _, name := range names {
		info, err := root.Lstat(name)
		if err != nil {
			continue
		}
		// A link goes as the link itself; only the custody folder is a
		// folder of DefenseClaw's.
		if info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			if name != ".defenseclaw-install-custody" {
				continue
			}
			err = root.RemoveAll(name)
		} else {
			err = root.Remove(name)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, filepath.Join(binDir, name))
	}
	if len(errs) > 0 {
		return removed, false, errors.Join(errs...)
	}
	left, err := rootNames(root)
	if err != nil {
		return removed, false, err
	}
	return removed, len(left) == 0, nil
}

// windowsInstallerUVFiles returns the uv files in root that still match the
// digest install.ps1 recorded, then the record itself.
func windowsInstallerUVFiles(root *os.Root) []string {
	info, err := root.Lstat(windowsUserUVRecord)
	if err != nil || !info.Mode().IsRegular() || info.Size() > windowsUserUVRecordMaxBytes {
		return nil
	}
	file, err := root.Open(windowsUserUVRecord)
	if err != nil {
		return nil
	}
	defer file.Close()
	var names []string
	scanner := bufio.NewScanner(io.LimitReader(file, windowsUserUVRecordMaxBytes))
	for scanner.Scan() {
		digest, name, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "  ")
		if !ok || !windowsUserUVNames[strings.ToLower(name)] {
			continue
		}
		if info, err := root.Lstat(name); err != nil || !info.Mode().IsRegular() {
			continue
		}
		if sum, err := sha256InRoot(root, name); err == nil && strings.EqualFold(sum, digest) {
			names = append(names, name)
		}
	}
	return append(names, windowsUserUVRecord)
}

func sha256InRoot(root *os.Root, name string) (string, error) {
	file, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func rootNames(root *os.Root) ([]string, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return dir.Readdirnames(-1)
}

// removeWindowsUserPathEntry removes binDir from the Path value of the
// account's user environment, keeping its other entries, their order and
// the value's kind (REG_EXPAND_SZ keeps %VAR% entries unexpanded). An entry
// names binDir when it does after %USERPROFILE% is expanded to home. It
// reports whether the value changed. The account's next sign-in, and every
// process it starts after that, gets the new Path.
func removeWindowsUserPathEntry(sid, home, binDir string) (bool, error) {
	path := sid + `\Environment`
	if windowsUserHives.path != "" {
		path = windowsUserHives.path + `\` + path
	}
	hive, err := registry.OpenKey(windowsUserHives.root, strings.TrimSuffix(path, `\Environment`), registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return false, ErrWindowsUserHiveNotLoaded
	}
	if err != nil {
		return false, err
	}
	hive.Close()
	key, err := registry.OpenKey(windowsUserHives.root, path, registry.QUERY_VALUE|registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer key.Close()
	raw, kind, err := key.GetStringValue("Path")
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var kept []string
	for _, entry := range strings.Split(raw, ";") {
		if entry != "" && windowsPathEntryNames(entry, home, binDir) {
			continue
		}
		kept = append(kept, entry)
	}
	value := strings.Join(kept, ";")
	if value == raw {
		return false, nil
	}
	if kind == registry.EXPAND_SZ {
		return true, key.SetExpandStringValue("Path", value)
	}
	return true, key.SetStringValue("Path", value)
}

// windowsPathEntryNames reports whether a Path entry names dir.
func windowsPathEntryNames(entry, home, dir string) bool {
	entry = strings.Trim(strings.TrimSpace(entry), `"`)
	for _, name := range []string{"%USERPROFILE%", "%HOMEDRIVE%%HOMEPATH%"} {
		if len(entry) >= len(name) && strings.EqualFold(entry[:len(name)], name) {
			entry = home + entry[len(name):]
			break
		}
	}
	if !filepath.IsAbs(entry) {
		return false
	}
	return strings.EqualFold(strings.TrimRight(filepath.Clean(entry), `\`), strings.TrimRight(filepath.Clean(dir), `\`))
}
