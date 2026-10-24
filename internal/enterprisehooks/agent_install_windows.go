// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Standalone discovery of the agent installs that keep no package.json for
// the fixed probes (GAP-0226, #1064):
//
//   - The official Codex installer, install.ps1
//     (https://chatgpt.com/codex/install.ps1), unpacks each release into
//     %USERPROFILE%\.codex\packages\standalone\releases\<version>-<target>,
//     points the junction ...\standalone\current at the selected release,
//     and points the junction %LOCALAPPDATA%\Programs\OpenAI\Codex\bin, which
//     it puts first on the user's PATH, at current\bin.
//   - A per-user WinGet package (winget install without --scope machine)
//     records its version in the user's own uninstall registry, readable
//     while the user's hive is loaded (the user is signed in).
//
// Neither was read, so a host whose users installed Codex with install.ps1
// got no Codex target and no machine requirements.toml, Codex ran without
// DefenseClaw hooks, and status and verify still said security_complete.
// Every read here is static and bounded and follows no junction: only the
// name the current junction points at is read. The values are the user's own
// claims, like a package.json version: they select a hook contract, and a
// falsified one can at most keep that user's row from enrolling, which the
// enumerator reports.

// windowsCodexStandaloneReleaseName matches install.ps1's release folder
// "<version>-<target>", with the versions its Assert-ValidReleaseVersion
// admits and the two Windows targets it installs.
var windowsCodexStandaloneReleaseName = regexp.MustCompile(
	`^([0-9]+\.[0-9]+\.[0-9]+(?:-alpha(?:\.[0-9]+){0,2}|-beta(?:\.[0-9]+)?)?)-(?:x86_64|aarch64)-pc-windows-msvc$`)

// windowsReadInstallJunction reads a junction's target without following it;
// tests replace it.
var windowsReadInstallJunction = os.Readlink

// windowsInstallLongPathName returns the long spelling of an existing path;
// tests replace it.
var windowsInstallLongPathName = func(path string) (string, error) {
	short, err := winpath.UTF16Ptr(path)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetLongPathName(short, &buf[0], uint32(len(buf)))
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, n)
	}
}

// windowsInstallPathAttributes reads the attributes of path itself (a final
// reparse point is not followed); tests replace it.
var windowsInstallPathAttributes = func(path string) (uint32, error) {
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return 0, err
	}
	return windows.GetFileAttributes(ptr)
}

// windowsInstallLocalDrivePath accepts a drive path, including its extended
// spelling, without allowing a UNC or device namespace to become a local
// relative path when the prefix is removed.
func windowsInstallLocalDrivePath(path string) (string, error) {
	path = filepath.FromSlash(path)
	if strings.HasPrefix(path, `\\?\`) {
		path = strings.TrimPrefix(path, `\\?\`)
		if len(path) < 3 || path[1] != ':' || path[2] != '\\' {
			return "", fmt.Errorf("path is not on a local drive letter")
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if volume := filepath.VolumeName(abs); len(volume) != 2 || volume[1] != ':' {
		return "", fmt.Errorf("path is not on a local drive letter: %s", abs)
	}
	return abs, nil
}

// windowsRejectInstallReparseChain accepts only local drive-letter paths,
// refusing UNC and device paths. It checks each element from the volume root
// down and refuses a reparse point before reading anything below it. The
// shared winpath.RejectReparseChain also walks root first, but permits paths
// outside local drive letters. A missing element ends either walk.
func windowsRejectInstallReparseChain(path string) error {
	abs, err := windowsInstallLocalDrivePath(path)
	if err != nil {
		return err
	}
	var chain []string
	for current := abs; ; {
		chain = append(chain, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	for i := len(chain) - 1; i >= 0; i-- {
		attributes, err := windowsInstallPathAttributes(chain[i])
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil
		}
		if err != nil {
			return err
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("reparse point in path: %s", chain[i])
		}
	}
	return nil
}

// windowsCodexStandaloneRoot is install.ps1's per-user install root. The
// installer moves it under CODEX_HOME when that is set; such a root is found
// by its PATH folder (windowsCodexStandaloneVisibleBin) and reported.
func windowsCodexStandaloneRoot(profileHome string) string {
	return filepath.Join(profileHome, ".codex", "packages", "standalone")
}

// windowsCodexStandaloneVisibleBin is the folder install.ps1 puts on the
// user's PATH.
func windowsCodexStandaloneVisibleBin(profileHome string) string {
	return filepath.Join(profileHome, "AppData", "Local", "Programs", "OpenAI", "Codex", "bin")
}

// discoverWindowsCodexStandaloneVersion reads the version of the Codex
// release install.ps1 selected for this profile: the name of the release
// folder its current junction points at, which must sit directly in this
// profile's releases folder and hold codex.exe through a plain folder chain.
func discoverWindowsCodexStandaloneVersion(profileHome string) (string, string) {
	root := windowsCodexStandaloneRoot(profileHome)
	releases := filepath.Join(root, "releases")
	if err := windowsRejectInstallReparseChain(releases); err != nil {
		return "", "the Codex standalone install folder has a refused reparse chain"
	}
	releasesInfo, err := os.Lstat(releases)
	if err != nil || !releasesInfo.IsDir() {
		return "", "no Codex standalone install under this profile"
	}
	target, err := windowsReadInstallJunction(filepath.Join(root, "current"))
	if err != nil || strings.TrimSpace(target) == "" {
		return "", "the Codex standalone install selects no release (its current junction is missing or unreadable)"
	}
	target, err = windowsInstallLocalDrivePath(strings.TrimSpace(target))
	if err != nil {
		return "", "the Codex standalone current junction points outside its releases folder"
	}
	// The target is the user's, so nothing touches it before it is known to
	// be on the profile's own local drive: a directory symbolic link (which a
	// user in Developer Mode can create) may name a UNC path, and LocalSystem
	// must never open one. Then the folder is compared by identity, not by
	// spelling, as the junction may name it in a long or short (8.3) form.
	releasesPath, err := windowsInstallLocalDrivePath(releases)
	if err != nil || !strings.EqualFold(filepath.VolumeName(target), filepath.VolumeName(releasesPath)) {
		return "", "the Codex standalone current junction points outside its releases folder"
	}
	// Check the junction target's own spelling before asking Windows to
	// inspect its parent or expand its 8.3 name.
	if windowsRejectInstallReparseChain(target) != nil {
		return "", "the Codex standalone current junction points through a refused reparse chain"
	}
	if !strings.EqualFold(filepath.Dir(target), releasesPath) {
		if parent, err := os.Lstat(filepath.Dir(target)); err != nil || !os.SameFile(parent, releasesInfo) {
			return "", "the Codex standalone current junction points outside its releases folder"
		}
	}
	match := windowsCodexStandaloneReleaseName.FindStringSubmatch(filepath.Base(target))
	if match == nil && strings.Contains(filepath.Base(target), "~") {
		// A junction may name the release by its 8.3 short spelling; the
		// version is in the folder's long name.
		if long, err := windowsInstallLongPathName(target); err == nil {
			match = windowsCodexStandaloneReleaseName.FindStringSubmatch(filepath.Base(long))
		}
	}
	if match == nil || !isValidWindowsAgentVersion(match[1]) {
		return "", "the Codex standalone current release is not named <version>-<target>"
	}
	if !windowsCodexStandaloneReleaseHasCLI(target) {
		return "", "the Codex standalone current release holds no codex.exe"
	}
	return match[1], ""
}

// windowsCodexStandaloneReleaseHasCLI reports a regular codex.exe reached
// through a plain folder chain: bin\codex.exe in install.ps1's package
// layout, codex.exe in its older platform-npm layout.
func windowsCodexStandaloneReleaseHasCLI(release string) bool {
	for _, candidate := range []string{
		filepath.Join(release, "bin", "codex.exe"),
		filepath.Join(release, "codex.exe"),
	} {
		if windowsRejectInstallReparseChain(candidate) != nil {
			continue
		}
		if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// windowsWinGetUserUninstallKey is a user's own uninstall root under
// HKEY_USERS\<SID>, where WinGet records a per-user package as
// "<PackageIdentifier>_<SourceIdentifier>" with its DisplayVersion.
const windowsWinGetUserUninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall`

// windowsWinGetUserMaxSubKeys bounds the listing of that user-writable key.
const windowsWinGetUserMaxSubKeys = 2048

// windowsUserWinGetPackageVersion is the registry seam for per-user WinGet
// discovery so tests do not depend on loaded user hives.
var windowsUserWinGetPackageVersion = readWindowsUserWinGetPackageVersion

// readWindowsUserWinGetPackageVersion returns the DisplayVersion of the
// per-user WinGet package packageID of account sid.
func readWindowsUserWinGetPackageVersion(sid, packageID string) (string, string) {
	sid = canonicalManifestTargetSID(sid)
	if sid == "" {
		return "", ""
	}
	if version, ok := readWindowsWinGetPackageVersion(registry.USERS, sid+`\`+windowsWinGetUserUninstallKey, 0, windowsWinGetUserMaxSubKeys, packageID); ok {
		return version, ""
	}
	return "", fmt.Sprintf("no per-user WinGet package %s in the user's registry (read while the user is signed in)", packageID)
}

// readWindowsWinGetPackageVersion returns the highest valid DisplayVersion
// among the subkeys of root\path named "<packageID>_<source>". limit bounds
// the subkeys listed (0: all, for an administrator-only key).
func readWindowsWinGetPackageVersion(root registry.Key, path string, access uint32, limit int, packageID string) (string, bool) {
	key, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|access)
	if err != nil {
		return "", false
	}
	defer key.Close()
	n := -1
	if limit > 0 {
		n = limit
	}
	names, err := key.ReadSubKeyNames(n)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false
	}
	prefix := strings.ToLower(packageID) + "_"
	best := ""
	for _, name := range names {
		if !strings.HasPrefix(strings.ToLower(name), prefix) {
			continue
		}
		sub, err := registry.OpenKey(root, path+`\`+name, registry.QUERY_VALUE|access)
		if err != nil {
			continue
		}
		version, _, err := sub.GetStringValue("DisplayVersion")
		_ = sub.Close()
		version = strings.TrimSpace(version)
		if err != nil || !isValidWindowsAgentVersion(version) {
			continue
		}
		if best == "" || compareWindowsEnterpriseVersion(version, best) > 0 {
			best = version
		}
	}
	return best, best != ""
}

// windowsWinGetPackagesMaxEntries and windowsWinGetPackagesScanBudget bound
// the listing of a user's WinGet Packages folder, which that user can fill
// with entries: one user cannot delay the rows of the others.
var (
	windowsWinGetPackagesMaxEntries = 4096
	windowsWinGetPackagesScanBudget = time.Second
	// Tests replace the directory read to exercise a stalled filesystem call.
	windowsWinGetReadPackageNames = func(dir *os.File, count int) ([]string, error) {
		return dir.Readdirnames(count)
	}
	// A stalled read keeps its path occupied until the scan goroutine exits.
	windowsWinGetPackageScans = struct {
		sync.Mutex
		inFlight map[string]bool
	}{inFlight: make(map[string]bool)}
)

// windowsWinGetPackagesBatch is how many names one directory read returns.
const windowsWinGetPackagesBatch = 256

// Why a WinGet Packages folder was not fully listed.
const (
	windowsWinGetScanTooManyEntries = "entries"
	windowsWinGetScanTimedOut       = "timeout"
	windowsWinGetScanStillRunning   = "busy"
)

// windowsWinGetPackageScanKey keys the in-flight scans: the spellings of one
// folder (case, the \\?\ prefix, an 8.3 short name) share a slot, so a
// second spelling cannot start a second scan of a stuck folder (GAP-0626).
func windowsWinGetPackageScanKey(packages string) string {
	return winpath.ComparisonKey(packages)
}

// findWindowsWinGetPackageFolder returns the first entry of packages named
// "<packageID>_<source>" for one of packageIDs, and false with the reason
// when the folder was not fully listed before one was found: more than
// windowsWinGetPackagesMaxEntries entries, not within
// windowsWinGetPackagesScanBudget, or an earlier scan of the folder that has
// not returned.
func findWindowsWinGetPackageFolder(packages string, packageIDs []string) (string, bool, string) {
	budget, maxEntries := windowsWinGetPackagesScanBudget, windowsWinGetPackagesMaxEntries
	if budget <= 0 || maxEntries <= 0 {
		return "", false, windowsWinGetScanTooManyEntries
	}
	// The deadline starts before the key: the key's 8.3 lookup touches the
	// same storage, so its (bounded) wait counts against the scan budget.
	deadline := time.Now().Add(budget)
	key := windowsWinGetPackageScanKey(packages)
	windowsWinGetPackageScans.Lock()
	if windowsWinGetPackageScans.inFlight[key] {
		windowsWinGetPackageScans.Unlock()
		return "", false, windowsWinGetScanStillRunning
	}
	windowsWinGetPackageScans.inFlight[key] = true
	windowsWinGetPackageScans.Unlock()
	readNames := windowsWinGetReadPackageNames
	type scanResult struct {
		match      string
		incomplete string
	}
	results := make(chan scanResult, 1)
	var active atomic.Pointer[os.File]
	go func() {
		match, incomplete := func() (string, string) {
			defer func() {
				windowsWinGetPackageScans.Lock()
				delete(windowsWinGetPackageScans.inFlight, key)
				windowsWinGetPackageScans.Unlock()
			}()
			return scanWindowsWinGetPackageFolder(packages, packageIDs, maxEntries, deadline, readNames, &active)
		}()
		results <- scanResult{match, incomplete}
	}()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case found := <-results:
		return found.match, found.incomplete == "", found.incomplete
	case <-timer.C:
		if dir := active.Load(); dir != nil {
			// Closing the handle releases an outstanding directory read. Do
			// not let that close hold up the next account's enumeration.
			go dir.Close()
		}
		return "", false, windowsWinGetScanTimedOut
	}
}

// scanWindowsWinGetPackageFolder lists packages for a match; the second
// result is "" when the folder was listed in full, else why it was not.
func scanWindowsWinGetPackageFolder(packages string, packageIDs []string, maxEntries int, deadline time.Time, readNames func(*os.File, int) ([]string, error), active *atomic.Pointer[os.File]) (string, string) {
	dir, err := os.Open(packages)
	if err != nil {
		return "", ""
	}
	defer dir.Close()
	active.Store(dir)
	defer active.Store(nil)
	prefixes := make([]string, 0, len(packageIDs))
	for _, id := range packageIDs {
		prefixes = append(prefixes, strings.ToLower(id)+"_")
	}
	listed := 0
	for {
		if !time.Now().Before(deadline) {
			return "", windowsWinGetScanTimedOut
		}
		names, err := readNames(dir, windowsWinGetPackagesBatch)
		for _, name := range names {
			listed++
			if listed > maxEntries {
				return "", windowsWinGetScanTooManyEntries
			}
			if !time.Now().Before(deadline) {
				return "", windowsWinGetScanTimedOut
			}
			lower := strings.ToLower(name)
			for _, prefix := range prefixes {
				if strings.HasPrefix(lower, prefix) {
					return filepath.Join(packages, name), ""
				}
			}
		}
		if err != nil {
			// io.EOF: listed in full; any other error lists no more.
			if errors.Is(err, io.EOF) {
				return "", ""
			}
			return "", windowsWinGetScanTimedOut
		}
		if listed >= maxEntries {
			return "", windowsWinGetScanTooManyEntries
		}
	}
}

// windowsStandaloneInstalledAgent returns where the profile has a CLI of
// connectorName installed that no version probe read, and what to do about
// it, or "" when it finds none. Only presence is checked, never through a
// junction: the install is then reported as unprotected instead of being a
// silent gap. When the user's WinGet Packages folder could not be fully
// listed, it returns "" and the reason the account was not fully scanned.
func windowsStandaloneInstalledAgent(profileHome, connectorName string) (string, string) {
	profileHome = strings.TrimSpace(profileHome)
	if !filepath.IsAbs(profileHome) {
		return "", ""
	}
	profileHome = filepath.Clean(profileHome)
	local := filepath.Join(profileHome, "AppData", "Local")
	npm := filepath.Join(profileHome, "AppData", "Roaming", "npm")
	links := filepath.Join(local, "Microsoft", "WinGet", "Links")
	var candidates []string
	switch connectorName {
	case "codex":
		candidates = []string{
			filepath.Join(windowsCodexStandaloneRoot(profileHome), "current"),
			windowsCodexStandaloneVisibleBin(profileHome),
			filepath.Join(npm, "codex.cmd"),
			filepath.Join(links, "codex.exe"),
		}
	case "copilot":
		candidates = []string{
			filepath.Join(npm, "copilot.cmd"),
			filepath.Join(links, "copilot.exe"),
		}
	default:
		return "", ""
	}
	for _, candidate := range candidates {
		if windowsInstallPathPresent(candidate) {
			return candidate, windowsStandaloneInstallFix(connectorName)
		}
	}
	packages := filepath.Join(local, "Microsoft", "WinGet", "Packages")
	if ids := windowsWinGetPackageIDs[connectorName]; len(ids) != 0 && windowsRejectInstallReparseChain(packages) == nil {
		match, complete, why := findWindowsWinGetPackageFolder(packages, ids)
		if match != "" {
			return match, "its WinGet version is read from the user's registry while the user is signed in; the next enumeration after sign-in enrolls the account"
		}
		if !complete {
			return "", windowsWinGetIncompleteScanMessage(connectorName, packages, why)
		}
	}
	return "", ""
}

// windowsWinGetIncompleteScanMessage says why the user's WinGet Packages
// folder was not fully scanned and what helps. Only a folder with too many
// entries is helped by removing packages; a folder whose listing timed out
// or whose earlier scan has not returned sits on storage that does not
// answer (an offline redirected profile, for example), where removing
// packages changes nothing (GAP-0626).
func windowsWinGetIncompleteScanMessage(connectorName, packages, why string) string {
	prefix := fmt.Sprintf("this account was not fully scanned for a per-user WinGet %s install: ", connectorName)
	switch why {
	case windowsWinGetScanTooManyEntries:
		return prefix + fmt.Sprintf("%s holds more entries than DefenseClaw lists (%d); remove the packages the user no longer needs, and the next enumeration scans it again",
			packages, windowsWinGetPackagesMaxEntries)
	case windowsWinGetScanStillRunning:
		return prefix + fmt.Sprintf("an earlier listing of %s has not returned, so its storage does not answer; check that the folder (a redirected or network profile folder, for example) is reachable, and the next enumeration scans it again once that listing returns",
			packages)
	default:
		return prefix + fmt.Sprintf("%s did not list within %s; check that the folder (a redirected or network profile folder, for example) is reachable, and the next enumeration scans it again",
			packages, windowsWinGetPackagesScanBudget)
	}
}

// windowsInstallPathPresent reports whether path exists below a plain folder
// chain; path itself may be a junction (install.ps1's), which is not
// followed.
func windowsInstallPathPresent(path string) bool {
	if windowsRejectInstallReparseChain(filepath.Dir(path)) != nil {
		return false
	}
	_, err := os.Lstat(path)
	return err == nil
}

// windowsStandaloneInstallFix is the operator-facing fix for an install whose
// version no probe can read.
func windowsStandaloneInstallFix(connectorName string) string {
	switch connectorName {
	case "codex":
		return "install it with npm install -g @openai/codex, install.ps1 (default location) or WinGet; the next enumeration enrolls the account"
	case "copilot":
		return "install it with npm install -g @github/copilot or WinGet; the next enumeration enrolls the account"
	default:
		return "install it in a location DefenseClaw reads; the next enumeration enrolls the account"
	}
}

// windowsCodexUnpublishedConsequence is the unprotected-agent consequence
// for Codex while the machine requirements.toml is not published.
const windowsCodexUnpublishedConsequence = "Codex's configured machine requirements.toml is missing; the guardian must restore it, and Codex runs without DefenseClaw hooks until then"

// windowsCodexMachinePolicyPublished reports whether Codex's machine
// requirements.toml is in force. The guardian keeps it published for a
// configured Codex connector even when no user is enrolled. A
// path that cannot be resolved or inspected counts as published, as for
// Cursor. Replaced in tests.
var windowsCodexMachinePolicyPublished = func() bool {
	path, err := windowsCodexMachineRequirementsPath()
	if err != nil {
		return true
	}
	_, err = os.Lstat(path)
	return !errors.Is(err, os.ErrNotExist)
}
