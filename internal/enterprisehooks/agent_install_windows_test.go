// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// GAP-0226 (#1064): Entra users who installed Codex with the official
// install.ps1 got no Codex target and no machine requirements.toml, and
// status said security_complete while Codex ran without hooks.

const testCodexStandaloneRelease = "0.160.0-x86_64-pc-windows-msvc"

// writeCodexStandaloneRelease lays out one release folder as install.ps1
// writes it and returns the folder; legacy is its older platform-npm layout
// with codex.exe at the release root.
func writeCodexStandaloneRelease(t *testing.T, home, release string, legacy bool) string {
	t.Helper()
	dir := filepath.Join(windowsCodexStandaloneRoot(home), "releases", release)
	exe := filepath.Join(dir, "bin", "codex.exe")
	if legacy {
		exe = filepath.Join(dir, "codex.exe")
	}
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatalf("mkdir release: %v", err)
	}
	if err := os.WriteFile(exe, []byte("MZ"), 0o755); err != nil {
		t.Fatalf("write codex.exe: %v", err)
	}
	return dir
}

func makeTestJunction(t *testing.T, link, target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatalf("mkdir junction parent: %v", err)
	}
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Fatalf("mklink /J %s %s: %v: %s", link, target, err, output)
	}
}

// writeCodexStandaloneInstall writes what install.ps1 leaves for one selected
// release: the release, the current junction and the PATH bin junction.
func writeCodexStandaloneInstall(t *testing.T, home string) {
	t.Helper()
	release := writeCodexStandaloneRelease(t, home, testCodexStandaloneRelease, false)
	current := filepath.Join(windowsCodexStandaloneRoot(home), "current")
	makeTestJunction(t, current, release)
	makeTestJunction(t, windowsCodexStandaloneVisibleBin(home), filepath.Join(current, "bin"))
}

func stubUserWinGet(t *testing.T, versions map[string]map[string]string) {
	t.Helper()
	previous := windowsUserWinGetPackageVersion
	t.Cleanup(func() { windowsUserWinGetPackageVersion = previous })
	windowsUserWinGetPackageVersion = func(sid, packageID string) (string, string) {
		if version := versions[canonicalManifestTargetSID(sid)][packageID]; version != "" {
			return version, ""
		}
		return "", "no per-user WinGet package " + packageID
	}
}

func stubCodexMachinePolicyPublished(t *testing.T, published bool) {
	t.Helper()
	previous := windowsCodexMachinePolicyPublished
	t.Cleanup(func() { windowsCodexMachinePolicyPublished = previous })
	windowsCodexMachinePolicyPublished = func() bool { return published }
}

func TestStandaloneWindowsCodexDiscoveryReadsTheOfficialInstallerRelease(t *testing.T) {
	stubMachineWinGet(t, nil)
	home := t.TempDir()
	writeCodexStandaloneInstall(t, home)
	if version, reason := standaloneWindowsAgentVersionExplain(home, "codex"); version != "0.160.0" {
		t.Fatalf("install.ps1 Codex version = %q (%s), want 0.160.0", version, reason)
	}
	// The selected release wins over an npm copy: install.ps1 puts its folder
	// first on the user's PATH.
	writeWindowsAgentPackageJSON(t, filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@openai", "codex"), "0.150.0")
	if version, _ := standaloneWindowsAgentVersionExplain(home, "codex"); version != "0.160.0" {
		t.Fatalf("install.ps1 next to npm = %q, want the selected release 0.160.0", version)
	}

	// The older platform-npm layout keeps codex.exe at the release root.
	legacy := t.TempDir()
	release := writeCodexStandaloneRelease(t, legacy, "0.158.0-aarch64-pc-windows-msvc", true)
	makeTestJunction(t, filepath.Join(windowsCodexStandaloneRoot(legacy), "current"), release)
	if version, reason := standaloneWindowsAgentVersionExplain(legacy, "codex"); version != "0.158.0" {
		t.Fatalf("legacy layout version = %q (%s), want 0.158.0", version, reason)
	}
}

func TestStandaloneWindowsCodexDiscoveryRefusesAForeignOrIncompleteSelection(t *testing.T) {
	stubMachineWinGet(t, nil)
	home := t.TempDir()
	release := writeCodexStandaloneRelease(t, home, testCodexStandaloneRelease, false)
	releases := filepath.Dir(release)
	other := t.TempDir()
	foreign := writeCodexStandaloneRelease(t, other, testCodexStandaloneRelease, false)
	incomplete := filepath.Join(releases, "0.161.0-x86_64-pc-windows-msvc")
	if err := os.MkdirAll(incomplete, 0o755); err != nil {
		t.Fatal(err)
	}
	misnamed := filepath.Join(releases, "latest")
	if err := os.MkdirAll(filepath.Join(misnamed, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(misnamed, "bin", "codex.exe"), []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A release folder that is itself a junction to another profile's copy.
	redirected := filepath.Join(releases, "0.162.1-x86_64-pc-windows-msvc")
	makeTestJunction(t, redirected, foreign)

	previous := windowsReadInstallJunction
	t.Cleanup(func() { windowsReadInstallJunction = previous })
	for name, tc := range map[string]struct {
		target string
		err    error
		reason string
	}{
		"unreadable":  {err: errors.New("not a junction"), reason: "selects no release"},
		"foreign":     {target: foreign, reason: "outside its releases folder"},
		"misnamed":    {target: misnamed, reason: "not named <version>-<target>"},
		"no codex":    {target: incomplete, reason: "holds no codex.exe"},
		"redirected":  {target: redirected, reason: "refused reparse chain"},
		"parent hops": {target: filepath.Join(releases, "..", "..", "..", "..", "x", testCodexStandaloneRelease), reason: "outside its releases folder"},
		// A directory symbolic link may name a share; it is refused before
		// anything opens it.
		"unc":         {target: `\\127.0.0.1\c$\Users\x\.codex\packages\standalone\releases\` + testCodexStandaloneRelease, reason: "outside its releases folder"},
		"device path": {target: `\\?\C:\x\` + testCodexStandaloneRelease, reason: "outside its releases folder"},
		"other drive": {target: `Z:\x\releases\` + testCodexStandaloneRelease, reason: "outside its releases folder"},
	} {
		t.Run(name, func(t *testing.T) {
			windowsReadInstallJunction = func(string) (string, error) { return tc.target, tc.err }
			version, reason := discoverWindowsCodexStandaloneVersion(home)
			if version != "" || !strings.Contains(reason, tc.reason) {
				t.Fatalf("version %q reason %q, want refusal containing %q", version, reason, tc.reason)
			}
		})
	}
}

func TestStandaloneWindowsDiscoveryReadsPerUserWinGetPackages(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, map[string]map[string]string{
		canonicalManifestTargetSID(testEntraUserSID): {"OpenAI.Codex": "0.160.0", "GitHub.Copilot": "1.0.40", "SST.opencode": "1.14.20"},
	})
	home := t.TempDir()
	for connector, want := range map[string]string{"codex": "0.160.0", "copilot": "1.0.40", "opencode": "1.14.20"} {
		if version, reason := standaloneWindowsAgentVersionExplainFor(testEntraUserSID, home, connector); version != want {
			t.Fatalf("%s per-user WinGet version = %q (%s), want %s", connector, version, reason, want)
		}
		// Another account's packages are not this user's.
		if version, _ := standaloneWindowsAgentVersionExplainFor(testLocalUserSID, home, connector); version != "" {
			t.Fatalf("%s for another SID = %q, want none", connector, version)
		}
	}
}

func TestReadWindowsWinGetPackageVersionTakesTheHighestValidMatch(t *testing.T) {
	path := fmt.Sprintf(`Software\DefenseClawTest\winget-%d\Uninstall`, time.Now().UnixNano())
	parent := filepath.Dir(path)
	t.Cleanup(func() {
		names := []string{"OpenAI.Codex_Microsoft.Winget.Source_8wekyb3d8bbwe", "OpenAI.Codex_other", "OpenAI.CodexPreview_x", "OpenAI.Codex_bad"}
		for _, name := range names {
			_ = registry.DeleteKey(registry.CURRENT_USER, path+`\`+name)
		}
		_ = registry.DeleteKey(registry.CURRENT_USER, path)
		_ = registry.DeleteKey(registry.CURRENT_USER, parent)
		_ = registry.DeleteKey(registry.CURRENT_USER, filepath.Dir(parent))
	})
	for name, version := range map[string]string{
		"OpenAI.Codex_Microsoft.Winget.Source_8wekyb3d8bbwe": "0.159.0",
		"OpenAI.Codex_other":    "0.160.0",
		"OpenAI.CodexPreview_x": "9.9.9",
		"OpenAI.Codex_bad":      "9.9.9\nforged",
	} {
		key, _, err := registry.CreateKey(registry.CURRENT_USER, path+`\`+name, registry.ALL_ACCESS)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if err := key.SetStringValue("DisplayVersion", version); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
		_ = key.Close()
	}
	if version, ok := readWindowsWinGetPackageVersion(registry.CURRENT_USER, path, 0, windowsWinGetUserMaxSubKeys, "OpenAI.Codex"); !ok || version != "0.160.0" {
		t.Fatalf("version = %q ok=%t, want 0.160.0 (prefix match, control characters refused)", version, ok)
	}
	if version, ok := readWindowsWinGetPackageVersion(registry.CURRENT_USER, path, 0, windowsWinGetUserMaxSubKeys, "GitHub.Copilot"); ok || version != "" {
		t.Fatalf("absent package = %q ok=%t", version, ok)
	}
}

func TestEnumerateWindowsStandaloneEnrollsAnInstallerCodexForEntraAndLocalUsers(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, nil)
	entra, local := t.TempDir(), t.TempDir()
	writeCodexStandaloneInstall(t, entra)
	writeCodexStandaloneInstall(t, local)
	injectWindowsProfileList(t, map[string]string{testEntraUserSID: entra, testLocalUserSID: local})
	var reported []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if len(manifest.Targets) != 2 {
		t.Fatalf("targets = %+v, want a Codex row for the Entra and the local user", manifest.Targets)
	}
	for _, target := range manifest.Targets {
		if target.Connector != "codex" || target.AgentVersion != "0.160.0" || target.Enabled == nil || !*target.Enabled || !target.Deferred {
			t.Fatalf("row %+v, want an enabled deferred codex row at 0.160.0", target)
		}
	}
	if len(reported) != 0 {
		t.Fatalf("unprotected = %+v, want none", reported)
	}
}

func TestEnumerateWindowsStandaloneReportsAnInstalledCodexItCannotRead(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, nil)
	stubCodexMachinePolicyPublished(t, false)
	home := t.TempDir()
	// install.ps1's older layout: codex.exe copied into the PATH folder, no
	// release record.
	bin := windowsCodexStandaloneVisibleBin(home)
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "codex.exe"), []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	injectWindowsProfileList(t, map[string]string{testEntraUserSID: home})
	var reported []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if len(manifest.Targets) != 0 {
		t.Fatalf("targets = %+v, want none for an unreadable version", manifest.Targets)
	}
	if len(reported) != 1 || reported[0].Connector != "codex" || reported[0].SID != canonicalManifestTargetSID(testEntraUserSID) {
		t.Fatalf("unprotected = %+v, want the Entra user's codex", reported)
	}
	message := reported[0].Message()
	for _, want := range []string{bin, "version could not be read", "npm install -g @openai/codex", "requirements.toml is not published"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message %q does not contain %q", message, want)
		}
	}
}

// Pass-6 review: the reparse check of an install path runs from the volume
// root down and stops at the first reparse point, so nothing below a link a
// user made is touched through it; a path that is not on a local drive
// letter is refused before any check touches it.
func TestWindowsRejectInstallReparseChainChecksFromTheRootDown(t *testing.T) {
	previous := windowsInstallPathAttributes
	t.Cleanup(func() { windowsInstallPathAttributes = previous })
	var touched []string
	stub := func(reparse, missing string) {
		touched = nil
		windowsInstallPathAttributes = func(path string) (uint32, error) {
			touched = append(touched, path)
			switch {
			case strings.EqualFold(path, reparse):
				return windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_REPARSE_POINT, nil
			case strings.EqualFold(path, missing):
				return 0, windows.ERROR_FILE_NOT_FOUND
			}
			return windows.FILE_ATTRIBUTE_DIRECTORY, nil
		}
	}
	leaf := `C:\Users\alice\.codex\packages\standalone\releases`
	stub(`C:\Users\alice\.codex`, "")
	if err := windowsRejectInstallReparseChain(leaf); err == nil || !strings.Contains(err.Error(), `C:\Users\alice\.codex`) {
		t.Fatalf("err = %v, want the user's link refused", err)
	}
	if want := []string{`C:\`, `C:\Users`, `C:\Users\alice`, `C:\Users\alice\.codex`}; strings.Join(touched, "|") != strings.Join(want, "|") {
		t.Fatalf("touched %q, want %q: nothing below the link may be checked through it", touched, want)
	}

	stub("", `C:\Users\alice\.codex`)
	if err := windowsRejectInstallReparseChain(leaf); err != nil || len(touched) != 4 {
		t.Fatalf("missing element: err %v, touched %q", err, touched)
	}

	stub("", "")
	if err := windowsRejectInstallReparseChain(leaf); err != nil || len(touched) != 7 {
		t.Fatalf("plain chain: err %v, touched %q", err, touched)
	}
	stub("", "")
	if err := windowsRejectInstallReparseChain(`\\?\` + leaf + `\`); err != nil || len(touched) != 7 || touched[0] != `C:\` {
		t.Fatalf("extended drive path: err %v, touched %q, want the same root-first chain", err, touched)
	}
	windowsInstallPathAttributes = func(path string) (uint32, error) {
		touched = append(touched, path)
		if strings.EqualFold(path, `C:\Users`) {
			return 0, windows.ERROR_ACCESS_DENIED
		}
		return windows.FILE_ATTRIBUTE_DIRECTORY, nil
	}
	touched = nil
	if err := windowsRejectInstallReparseChain(leaf); !errors.Is(err, windows.ERROR_ACCESS_DENIED) || len(touched) != 2 {
		t.Fatalf("access denied: err %v, touched %q, want refusal before descendants", err, touched)
	}

	for _, path := range []string{`\\127.0.0.1\c$\Users\alice\.codex`, `\\?\UNC\127.0.0.1\c$\x`} {
		stub("", "")
		if err := windowsRejectInstallReparseChain(path); err == nil || len(touched) != 0 {
			t.Fatalf("%s: err %v, touched %q, want a refusal before any check", path, err, touched)
		}
	}
}

// Pass-6 review: the user-writable WinGet Packages folder is listed only up
// to a bound of entries and time, and an account whose folder was not fully
// listed is reported as not fully scanned instead of as having no install.
func TestStandaloneWindowsInstalledAgentBoundsTheWinGetPackagesListing(t *testing.T) {
	home := t.TempDir()
	packages := filepath.Join(home, "AppData", "Local", "Microsoft", "WinGet", "Packages")
	if err := os.MkdirAll(packages, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 600; i++ {
		if err := os.WriteFile(filepath.Join(packages, fmt.Sprintf("AAA.Filler_%04d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	match := filepath.Join(packages, "OpenAI.Codex_Microsoft.Winget.Source_8wekyb3d8bbwe")
	if err := os.MkdirAll(match, 0o755); err != nil {
		t.Fatal(err)
	}
	previousMax, previousBudget := windowsWinGetPackagesMaxEntries, windowsWinGetPackagesScanBudget
	t.Cleanup(func() { windowsWinGetPackagesMaxEntries, windowsWinGetPackagesScanBudget = previousMax, previousBudget })

	if installed, fix := windowsStandaloneInstalledAgent(home, "codex"); !strings.EqualFold(installed, match) || !strings.Contains(fix, "WinGet version") {
		t.Fatalf("within the bound: %q %q, want %q", installed, fix, match)
	}
	if installed, fix := windowsStandaloneInstalledAgent(home, "copilot"); installed != "" || fix != "" {
		t.Fatalf("fully listed, no copilot package: %q %q, want none", installed, fix)
	}

	for name, bound := range map[string]func(){
		"entries": func() { windowsWinGetPackagesMaxEntries = 300 },
		"time":    func() { windowsWinGetPackagesScanBudget = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			windowsWinGetPackagesMaxEntries, windowsWinGetPackagesScanBudget = previousMax, previousBudget
			bound()
			installed, fix := windowsStandaloneInstalledAgent(home, "codex")
			if installed != "" || !strings.Contains(fix, "not fully scanned") || !strings.Contains(fix, packages) {
				t.Fatalf("over the bound: %q %q, want the account reported as not fully scanned", installed, fix)
			}
		})
	}

	// The enumerator reports such an account as unprotected.
	windowsWinGetPackagesMaxEntries, windowsWinGetPackagesScanBudget = 300, previousBudget
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, nil)
	stubCodexMachinePolicyPublished(t, true)
	injectWindowsProfileList(t, map[string]string{testEntraUserSID: home})
	var reported []UnprotectedAgent
	if _, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	}); err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if len(reported) != 1 || reported[0].Connector != "codex" || !strings.Contains(reported[0].Message(), "not fully scanned") {
		t.Fatalf("unprotected = %+v, want the account reported as not fully scanned", reported)
	}
	reported = nil
	(&windowsStandaloneRowContext{sessionActive: true, user: "alice", report: func(agent UnprotectedAgent) {
		reported = append(reported, agent)
	}}).pending(&ManifestTarget{SID: testEntraUserSID, UserHome: home, Connector: "codex"}, "directory lookup is pending")
	if len(reported) != 1 || !strings.Contains(reported[0].Message(), "not fully scanned") {
		t.Fatalf("pending row = %+v, want the incomplete scan named", reported)
	}
}

func TestWindowsWinGetPackageFolderBoundsOneStalledRead(t *testing.T) {
	packages := t.TempDir()
	previousRead, previousBudget := windowsWinGetReadPackageNames, windowsWinGetPackagesScanBudget
	t.Cleanup(func() {
		windowsWinGetReadPackageNames, windowsWinGetPackagesScanBudget = previousRead, previousBudget
	})
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	windowsWinGetReadPackageNames = func(*os.File, int) ([]string, error) {
		close(entered)
		<-release
		defer close(finished)
		return []string{"OpenAI.Codex_Microsoft.Winget.Source"}, nil
	}
	windowsWinGetPackagesScanBudget = 40 * time.Millisecond
	type result struct {
		match    string
		complete bool
	}
	got := make(chan result, 1)
	go func() {
		match, complete, _ := findWindowsWinGetPackageFolder(packages, []string{"OpenAI.Codex"})
		got <- result{match, complete}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("directory read did not start")
	}
	select {
	case scan := <-got:
		if scan.match != "" || scan.complete {
			t.Fatalf("stalled scan = %+v, want an incomplete scan", scan)
		}
	case <-time.After(500 * time.Millisecond):
		close(release)
		t.Fatal("one stalled Packages directory read delayed the next user")
	}
	close(release)
	<-finished
	waitWindowsWinGetPackageScanIdle(t, packages)
}

func waitWindowsWinGetPackageScanIdle(t *testing.T, packages string) {
	t.Helper()
	key := windowsWinGetPackageScanKey(packages)
	deadline := time.Now().Add(time.Second)
	for {
		windowsWinGetPackageScans.Lock()
		busy := windowsWinGetPackageScans.inFlight[key]
		windowsWinGetPackageScans.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Packages scan for %s kept its in-flight slot after the read returned", packages)
		}
		time.Sleep(time.Millisecond)
	}
}

// A timed-out scan retains one slot until its directory read returns. Other
// profiles still scan, and equivalent Windows spellings share that slot.
func TestWindowsWinGetPackageFolderLimitsStalledScansPerPath(t *testing.T) {
	packagesA, packagesB := t.TempDir(), t.TempDir()
	name := "OpenAI.Codex_Microsoft.Winget.Source"
	if err := os.WriteFile(filepath.Join(packagesA, name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packagesB, name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	previousRead, previousBudget := windowsWinGetReadPackageNames, windowsWinGetPackagesScanBudget
	windowsWinGetPackageScans.Lock()
	previousScans := windowsWinGetPackageScans.inFlight
	windowsWinGetPackageScans.inFlight = make(map[string]bool)
	windowsWinGetPackageScans.Unlock()
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		waitWindowsWinGetPackageScanIdle(t, packagesA)
		windowsWinGetReadPackageNames, windowsWinGetPackagesScanBudget = previousRead, previousBudget
		windowsWinGetPackageScans.Lock()
		windowsWinGetPackageScans.inFlight = previousScans
		windowsWinGetPackageScans.Unlock()
	})
	entered := make(chan struct{})
	var enteredOnce sync.Once
	var reads atomic.Int32
	windowsWinGetReadPackageNames = func(dir *os.File, count int) ([]string, error) {
		if strings.EqualFold(filepath.Clean(dir.Name()), packagesA) {
			if reads.Add(1) == 1 {
				enteredOnce.Do(func() { close(entered) })
				<-release
			}
		}
		return dir.Readdirnames(count)
	}
	windowsWinGetPackagesScanBudget = 40 * time.Millisecond
	ids := []string{"OpenAI.Codex"}
	type result struct {
		match    string
		complete bool
		elapsed  time.Duration
	}
	call := func(path string) result {
		start := time.Now()
		match, complete, _ := findWindowsWinGetPackageFolder(path, ids)
		return result{match, complete, time.Since(start)}
	}
	first := make(chan result, 1)
	go func() { first <- call(packagesA) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first Packages read did not start")
	}
	checkIncomplete := func(t *testing.T, got result) {
		t.Helper()
		if got.match != "" || got.complete || got.elapsed > 500*time.Millisecond {
			t.Errorf("stalled Packages scan = %+v, want an incomplete scan within 500 ms", got)
		}
	}
	slotBusy := func() bool {
		windowsWinGetPackageScans.Lock()
		defer windowsWinGetPackageScans.Unlock()
		return windowsWinGetPackageScans.inFlight[windowsWinGetPackageScanKey(packagesA)]
	}
	select {
	case got := <-first:
		checkIncomplete(t, got)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("first stalled Packages scan exceeded its budget")
	}
	t.Run("OneScanForManyCalls", func(t *testing.T) {
		bad := 0
		check := func(got result) {
			if got.match != "" || got.complete || got.elapsed > 500*time.Millisecond {
				bad++
			}
		}
		for i := 0; i < 25; i++ {
			check(call(packagesA))
		}
		results := make(chan result, 25)
		for i := 0; i < 25; i++ {
			go func() { results <- call(packagesA) }()
		}
		for i := 0; i < 25; i++ {
			select {
			case got := <-results:
				check(got)
			case <-time.After(500 * time.Millisecond):
				t.Fatal("concurrent stalled Packages scan exceeded its budget")
			}
		}
		if bad != 0 {
			t.Errorf("%d of 50 stalled lookups returned a match, completed, or exceeded 500 ms", bad)
		}
		if got := reads.Load(); got != 1 {
			t.Errorf("reader started %d scans for one stuck path, want exactly one", got)
		}
	})
	t.Run("DifferentPathStillScans", func(t *testing.T) {
		if !slotBusy() {
			t.Error("stalled path has no in-flight slot")
		}
		if got := call(packagesB); got.match != filepath.Join(packagesB, name) || !got.complete {
			t.Errorf("another Packages path = %+v, want its matching entry", got)
		}
	})
	t.Run("AlternateSpellingSharesSlot", func(t *testing.T) {
		alias := strings.ToUpper(packagesA) + string(os.PathSeparator)
		checkIncomplete(t, call(alias))
		if got := reads.Load(); got != 1 {
			t.Errorf("alternate-case path started scan %d, want one shared slot", got)
		}
	})
	t.Run("SlotClearsAfterStalledRead", func(t *testing.T) {
		if !slotBusy() {
			t.Error("stalled path has no in-flight slot")
		}
		releaseOnce.Do(func() { close(release) })
		waitWindowsWinGetPackageScanIdle(t, packagesA)
		if got := call(packagesA); got.match != filepath.Join(packagesA, name) || !got.complete {
			t.Errorf("rescan after the stuck reader returned = %+v, want its matching entry", got)
		}
		if got := reads.Load(); got != 2 {
			t.Errorf("reader started %d scans after release, want one resumed scan", got)
		}
	})
}

func TestWindowsWinGetPackageFolderClearsSlotBeforeResult(t *testing.T) {
	packages := t.TempDir()
	name := "OpenAI.Codex_Microsoft.Winget.Source"
	if err := os.WriteFile(filepath.Join(packages, name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// The in-flight rejection is also part of the base negative control;
	// the following normal calls check that each completed scan clears it.
	key := windowsWinGetPackageScanKey(packages)
	windowsWinGetPackageScans.Lock()
	windowsWinGetPackageScans.inFlight[key] = true
	windowsWinGetPackageScans.Unlock()
	t.Cleanup(func() {
		windowsWinGetPackageScans.Lock()
		delete(windowsWinGetPackageScans.inFlight, key)
		windowsWinGetPackageScans.Unlock()
	})
	if match, complete, _ := findWindowsWinGetPackageFolder(packages, []string{"OpenAI.Codex"}); match != "" || complete {
		t.Errorf("occupied slot = %q, complete %t; want an incomplete scan", match, complete)
	}
	windowsWinGetPackageScans.Lock()
	delete(windowsWinGetPackageScans.inFlight, key)
	windowsWinGetPackageScans.Unlock()
	for i := 0; i < 100; i++ {
		match, complete, _ := findWindowsWinGetPackageFolder(packages, []string{"OpenAI.Codex"})
		if match != filepath.Join(packages, name) || !complete {
			t.Fatalf("scan %d = %q, complete %t; want the matching entry", i, match, complete)
		}
	}
}

func TestWindowsWinGetPackageFolderCountsEntriesBeforeMatching(t *testing.T) {
	packages := t.TempDir()
	if match, complete, _ := findWindowsWinGetPackageFolder(filepath.Join(packages, "absent"), []string{"OpenAI.Codex"}); match != "" || !complete {
		t.Fatalf("absent Packages directory = %q, complete %t; want the old Glob result of no matches", match, complete)
	}
	previousRead, previousMax := windowsWinGetReadPackageNames, windowsWinGetPackagesMaxEntries
	t.Cleanup(func() {
		windowsWinGetReadPackageNames, windowsWinGetPackagesMaxEntries = previousRead, previousMax
	})
	windowsWinGetReadPackageNames = func(*os.File, int) ([]string, error) {
		return []string{"filler-one", "filler-two", "OpenAI.Codex_Microsoft.Winget.Source"}, nil
	}
	windowsWinGetPackagesMaxEntries = 2
	if match, complete, _ := findWindowsWinGetPackageFolder(packages, []string{"OpenAI.Codex"}); match != "" || complete {
		t.Fatalf("entry beyond the cap = %q, complete %t; want an incomplete scan", match, complete)
	}
}

// Pass-6 review: a current junction that names the release by its 8.3 short
// spelling is read by the release folder's long name.
func TestStandaloneWindowsCodexDiscoveryReadsAShortReleaseName(t *testing.T) {
	home := t.TempDir()
	releases := filepath.Join(windowsCodexStandaloneRoot(home), "releases")
	short := writeCodexStandaloneRelease(t, home, "0160~1.0-X", false)
	previousJunction, previousLong := windowsReadInstallJunction, windowsInstallLongPathName
	t.Cleanup(func() { windowsReadInstallJunction, windowsInstallLongPathName = previousJunction, previousLong })
	windowsReadInstallJunction = func(string) (string, error) { return short, nil }
	windowsInstallLongPathName = func(path string) (string, error) {
		if !strings.EqualFold(path, short) {
			return "", errors.New("unexpected path " + path)
		}
		return filepath.Join(releases, testCodexStandaloneRelease), nil
	}
	if version, reason := discoverWindowsCodexStandaloneVersion(home); version != "0.160.0" {
		t.Fatalf("short release name: version %q (%s), want 0.160.0", version, reason)
	}
	windowsInstallLongPathName = func(string) (string, error) { return "", errors.New("no long name") }
	if version, reason := discoverWindowsCodexStandaloneVersion(home); version != "" || !strings.Contains(reason, "not named <version>-<target>") {
		t.Fatalf("unresolvable short name: version %q reason %q, want a refusal", version, reason)
	}
	previousAttributes := windowsInstallPathAttributes
	t.Cleanup(func() { windowsInstallPathAttributes = previousAttributes })
	windowsInstallPathAttributes = func(path string) (uint32, error) {
		if strings.EqualFold(path, short) {
			return windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_REPARSE_POINT, nil
		}
		return previousAttributes(path)
	}
	longNameRead := false
	windowsInstallLongPathName = func(string) (string, error) {
		longNameRead = true
		return filepath.Join(releases, testCodexStandaloneRelease), nil
	}
	if version, reason := discoverWindowsCodexStandaloneVersion(home); version != "" || !strings.Contains(reason, "refused reparse chain") || longNameRead {
		t.Fatalf("short release link: version %q reason %q long-name read %t, want refusal before opening the leaf", version, reason, longNameRead)
	}
}

// GAP-0626: another spelling of a folder whose scan is stuck (case, the
// \\?\ prefix) shares its slot, and the account's message says the folder's
// storage does not answer instead of asking to remove packages.
func TestWindowsWinGetPackageFolderSharesTheSlotAcrossSpellings(t *testing.T) {
	packages := t.TempDir()
	key := windowsWinGetPackageScanKey(packages)
	for _, spelling := range []string{strings.ToUpper(packages), `\\?\` + packages, packages + `\`} {
		if got := windowsWinGetPackageScanKey(spelling); got != key {
			t.Fatalf("key of %q = %q, want %q", spelling, got, key)
		}
	}
	windowsWinGetPackageScans.Lock()
	windowsWinGetPackageScans.inFlight[key] = true
	windowsWinGetPackageScans.Unlock()
	t.Cleanup(func() {
		windowsWinGetPackageScans.Lock()
		delete(windowsWinGetPackageScans.inFlight, key)
		windowsWinGetPackageScans.Unlock()
	})
	match, complete, why := findWindowsWinGetPackageFolder(`\\?\`+strings.ToUpper(packages), []string{"OpenAI.Codex"})
	if match != "" || complete || why != windowsWinGetScanStillRunning {
		t.Fatalf("another spelling of a busy folder = %q, complete %t, why %q; want the busy slot", match, complete, why)
	}
	busy := windowsWinGetIncompleteScanMessage("codex", packages, why)
	if !strings.Contains(busy, "not fully scanned") || !strings.Contains(busy, "has not returned") || strings.Contains(busy, "remove the packages") {
		t.Fatalf("busy message = %q", busy)
	}
	full := windowsWinGetIncompleteScanMessage("codex", packages, windowsWinGetScanTooManyEntries)
	if !strings.Contains(full, "remove the packages") {
		t.Fatalf("too-many-entries message = %q", full)
	}
	slow := windowsWinGetIncompleteScanMessage("codex", packages, windowsWinGetScanTimedOut)
	if !strings.Contains(slow, "did not list within") || strings.Contains(slow, "remove the packages") {
		t.Fatalf("timed-out message = %q", slow)
	}
}
