// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The Codex machine-policy folder is kept, not followed, by a teardown
// (GAP-0773). These rows use the injected reparse probe; the real-junction row
// below runs against an NTFS junction.

type codexKeepFixture struct {
	programData string
	folder      string
	decoys      map[string]string // name -> sha256
}

// decoyNames are the DefenseClaw-named files an administrator-made link can
// point at: the writer lock, state copies, selector files and requirements.
var codexKeepDecoyNames = []string{
	".defenseclaw-managed-hooks.lock",
	".defenseclaw-managed-hooks.state",
	".defenseclaw-managed-hooks.writer.lock",
	".defenseclaw-managed-runtime-selector.lock",
	".defenseclaw-managed-runtime-selector.state",
	"requirements.toml",
}

func hashCodexKeepTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		out[entry.Name()] = hex.EncodeToString(sum[:])
	}
	return out
}

func equalCodexKeepTrees(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for name, sum := range a {
		if b[name] != sum {
			return false
		}
	}
	return true
}

// newCodexKeepFixture lays out ProgramData with a Codex folder holding
// DefenseClaw-named decoys, in the standalone profile.
func newCodexKeepFixture(t *testing.T, standalone bool) codexKeepFixture {
	t.Helper()
	programData := t.TempDir()
	folder := filepath.Join(programData, "OpenAI", "Codex")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range codexKeepDecoyNames {
		if err := os.WriteFile(filepath.Join(folder, name), []byte("decoy "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	previousProgramData, previousStandalone, previousProbe := windowsCodexMachineProgramData,
		windowsCodexMachineStandaloneProcess, windowsCodexMachineReparseProbe
	t.Cleanup(func() {
		windowsCodexMachineProgramData, windowsCodexMachineStandaloneProcess = previousProgramData, previousStandalone
		windowsCodexMachineReparseProbe = previousProbe
		windowsCodexMachineKept.Lock()
		windowsCodexMachineKept.paths = map[string]string{}
		windowsCodexMachineKept.Unlock()
	})
	windowsCodexMachineProgramData = func() (string, error) { return programData, nil }
	windowsCodexMachineStandaloneProcess = func() bool { return standalone }
	return codexKeepFixture{programData: programData, folder: folder, decoys: hashCodexKeepTree(t, folder)}
}

func codexKeepOptions(t *testing.T, folder string) WindowsCodexMachineRequirementsOptions {
	t.Helper()
	root := t.TempDir()
	managedDir := filepath.Join(root, "bin")
	installDir := filepath.Join(root, "install")
	for _, dir := range []string{managedDir, installDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	hook := filepath.Join(managedDir, "defenseclaw-hook.exe")
	if err := os.WriteFile(hook, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	return WindowsCodexMachineRequirementsOptions{
		RequirementsPath:   filepath.Join(folder, "requirements.toml"),
		ManagedStatePath:   filepath.Join(folder, windowsCodexManagedStateFile),
		ManagedDir:         managedDir,
		HookBinary:         hook,
		OwnershipPath:      filepath.Join(installDir, "codex-requirements-ownership.json"),
		GatewayAddr:        "127.0.0.1:18000",
		GatewayServiceName: "DefenseClawGateway",
		HookContractID:     WindowsCodexManagedHookContract(hook),
	}
}

func TestWindowsCodexMachineFolderKeptClassifiesTheFolder(t *testing.T) {
	linkAt := func(link string) func(string) (string, error) {
		return func(string) (string, error) { return link, nil }
	}
	cases := []struct {
		name       string
		standalone bool
		probe      func(fixture codexKeepFixture) func(string) (string, error)
		remove     bool
		want       func(fixture codexKeepFixture) string
	}{
		{name: "plain folder", standalone: true, probe: func(codexKeepFixture) func(string) (string, error) { return linkAt("") },
			want: func(codexKeepFixture) string { return "" }},
		{name: "link at the folder", standalone: true, probe: func(f codexKeepFixture) func(string) (string, error) { return linkAt(f.folder) },
			want: func(f codexKeepFixture) string { return f.folder }},
		{name: "link on a parent", standalone: true, probe: func(f codexKeepFixture) func(string) (string, error) { return linkAt(filepath.Dir(f.folder)) },
			want: func(f codexKeepFixture) string { return filepath.Dir(f.folder) }},
		{name: "absent folder", standalone: true, remove: true, probe: func(codexKeepFixture) func(string) (string, error) { return linkAt("") },
			want: func(codexKeepFixture) string { return "" }},
		{name: "Secure Client never keeps", standalone: false, probe: func(f codexKeepFixture) func(string) (string, error) { return linkAt(f.folder) },
			want: func(codexKeepFixture) string { return "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newCodexKeepFixture(t, tc.standalone)
			windowsCodexMachineReparseProbe = tc.probe(fixture)
			if tc.remove {
				if err := os.RemoveAll(fixture.folder); err != nil {
					t.Fatal(err)
				}
			}
			got, err := WindowsCodexMachineFolderKept()
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want(fixture) {
				t.Fatalf("kept = %q, want %q", got, tc.want(fixture))
			}
			if tc.want(fixture) != "" {
				if names := WindowsCodexMachineFoldersKept(); len(names) != 1 || names[0] != tc.want(fixture) {
					t.Fatalf("named %q, want just %q", names, tc.want(fixture))
				}
			} else if names := WindowsCodexMachineFoldersKept(); len(names) != 0 {
				t.Fatalf("named %q, want nothing", names)
			}
		})
	}
}

func TestWindowsCodexMachineFolderKeptKeepsANonFolderAndNamesItOnce(t *testing.T) {
	fixture := newCodexKeepFixture(t, true)
	windowsCodexMachineReparseProbe = func(string) (string, error) { return "", nil }
	if err := os.RemoveAll(fixture.folder); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.folder, []byte("a file where the folder belongs"), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		got, err := WindowsCodexMachineFolderKept()
		if err != nil || got != fixture.folder {
			t.Fatalf("kept = %q, %v; want %q", got, err, fixture.folder)
		}
	}
	if names := WindowsCodexMachineFoldersKept(); len(names) != 1 {
		t.Fatalf("named %q, want it once", names)
	}
}

// Over a link the teardown removal and the teardown registry read touch
// nothing behind it: the decoys keep their bytes, no file is created, and the
// removal succeeds and says it kept the link.
func TestWindowsCodexMachineTeardownOverALinkTouchesNothingBehindIt(t *testing.T) {
	fixture := newCodexKeepFixture(t, true)
	opts := codexKeepOptions(t, fixture.folder)
	if adminErr := requireWindowsCodexMachineAdministrator(); adminErr != nil {
		t.Skipf("the removal requires an elevated Administrator or LocalSystem token: %v", adminErr)
	}
	windowsCodexMachineReparseProbe = func(string) (string, error) { return fixture.folder, nil }
	// The layout and trust checks must not run behind the link: make them fail
	// the test if anything reaches them.
	previousDir, previousFile, previousVolume := windowsCodexMachineTrustedDirCheck,
		windowsCodexMachineTrustedFileCheck, windowsCodexMachineVolumeCheck
	t.Cleanup(func() {
		windowsCodexMachineTrustedDirCheck, windowsCodexMachineTrustedFileCheck = previousDir, previousFile
		windowsCodexMachineVolumeCheck = previousVolume
	})
	reached := func(string, string) error {
		t.Error("a trust check reached the Codex folder behind a link")
		return nil
	}
	windowsCodexMachineTrustedDirCheck, windowsCodexMachineTrustedFileCheck = reached, reached
	windowsCodexMachineVolumeCheck = func(string) error { t.Error("the volume check reached the Codex folder behind a link"); return nil }

	registry, err := ResolveWindowsCodexManagedRuntimeRegistryForTeardown(opts.HookBinary)
	if err != nil || registry.Kept != fixture.folder || registry.Active || len(registry.Targets) != 0 {
		t.Fatalf("registry = %+v, %v; want an empty registry that names the link", registry, err)
	}
	report, err := RemoveWindowsCodexMachineRequirementsForTeardown(opts)
	if err != nil {
		t.Fatalf("the removal failed on a link: %v (%s)", err, report.Error)
	}
	assertCodexLinkKeptReport(t, report, fixture.folder)
	if after := hashCodexKeepTree(t, fixture.folder); !equalCodexKeepTrees(after, fixture.decoys) {
		t.Fatalf("the folder changed: before %v after %v", fixture.decoys, after)
	}
	if names := WindowsCodexMachineFoldersKept(); len(names) != 1 || names[0] != fixture.folder {
		t.Fatalf("named %q, want the link once", names)
	}
}

// assertCodexLinkKeptReport pins what a teardown says about a kept link: ok
// and named, but kept and not verified, so it attests neither a binary that is
// safe to remove nor a removed state (GAP-0773).
func assertCodexLinkKeptReport(t *testing.T, report WindowsCodexMachineRequirementsReport, link string) {
	t.Helper()
	if !report.OK || report.Disposition != "link_kept" || !strings.EqualFold(report.LinkKept, link) ||
		report.Changed || report.SurvivingOwnedPathReferences != 0 {
		t.Fatalf("report = %+v", report)
	}
	if report.SafeToRemoveBinary || report.ManagedStateRemovedOrAbsent {
		t.Fatalf("a link that was not read attested a safe binary or a removed state: %+v", report)
	}
	detail := strings.Join(report.Details, "\n")
	if !strings.Contains(detail, "kept, not verified") || !strings.Contains(detail, "may still name the DefenseClaw hook binary") {
		t.Fatalf("the report does not say the policy behind the link was not checked: %q", detail)
	}
}

// Every removal but the uninstall's is strict (GAP-0773): the disabled Codex
// reconcile, the hidden remove action and the guardian remover all call
// RemoveWindowsCodexMachineRequirements, and the disabled reconcile calls it
// from ReconcileWindowsCodexMachineRequirements. With an administrator link at
// the Codex folder and DefenseClaw-named files behind it, each refuses on the
// link: no OK, no kept link, no safe-to-remove-binary, nothing behind the link
// read through or changed.
func TestWindowsCodexMachineNonTeardownRemovalsRefuseALink(t *testing.T) {
	if adminErr := requireWindowsCodexMachineAdministrator(); adminErr != nil {
		t.Skipf("the removal requires an elevated Administrator or LocalSystem token: %v", adminErr)
	}
	programData := t.TempDir()
	target := filepath.Join(t.TempDir(), "codex-target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range codexKeepDecoyNames {
		if err := os.WriteFile(filepath.Join(target, name), []byte("decoy "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	vendor := filepath.Join(programData, "OpenAI")
	if err := os.MkdirAll(vendor, 0o755); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(vendor, "Codex")
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v (%s)", err, output)
	}
	t.Cleanup(func() { _ = os.Remove(junction) })
	before := hashCodexKeepTree(t, target)

	previousProgramData, previousStandalone := windowsCodexMachineProgramData, windowsCodexMachineStandaloneProcess
	previousDir := windowsCodexMachineTrustedDirCheck
	t.Cleanup(func() {
		windowsCodexMachineProgramData, windowsCodexMachineStandaloneProcess = previousProgramData, previousStandalone
		windowsCodexMachineTrustedDirCheck = previousDir
		windowsCodexMachineKept.Lock()
		windowsCodexMachineKept.paths = map[string]string{}
		windowsCodexMachineKept.Unlock()
	})
	// The standalone profile, where a teardown would keep this link; the
	// trust walk is reduced to its link rule so the refusal is the link's.
	windowsCodexMachineProgramData = func() (string, error) { return programData, nil }
	windowsCodexMachineStandaloneProcess = func() bool { return true }
	windowsCodexMachineTrustedDirCheck = func(path, _ string) error { return rejectWindowsCodexMachineReparseChain(path) }
	opts := codexKeepOptions(t, junction)

	for _, tc := range []struct {
		name string
		run  func() (WindowsCodexMachineRequirementsReport, error)
	}{
		{"remove (hidden action and guardian)", func() (WindowsCodexMachineRequirementsReport, error) {
			return RemoveWindowsCodexMachineRequirements(opts)
		}},
		{"reconcile with Codex disabled", func() (WindowsCodexMachineRequirementsReport, error) {
			disabled := opts
			disabled.CodexTargetEnabled = false
			return ReconcileWindowsCodexMachineRequirements(disabled)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := tc.run()
			if err == nil || !strings.Contains(err.Error(), "reparse points are not allowed") ||
				!strings.Contains(err.Error(), junction) {
				t.Fatalf("want a refusal that names the link, got %v", err)
			}
			if report.OK || report.SafeToRemoveBinary || report.ManagedStateRemovedOrAbsent ||
				report.LinkKept != "" || strings.Contains(report.Disposition, "link_kept") {
				t.Fatalf("a non-teardown removal over a link reported success: %+v", report)
			}
			if after := hashCodexKeepTree(t, target); !equalCodexKeepTrees(after, before) {
				t.Fatalf("the folder behind the link changed: before %v after %v", before, after)
			}
			if names := WindowsCodexMachineFoldersKept(); len(names) != 0 {
				t.Fatalf("a non-teardown removal kept a link: %q", names)
			}
		})
	}
	// The same call from the uninstall keeps the link and reads nothing.
	report, err := RemoveWindowsCodexMachineRequirementsForTeardown(opts)
	if err != nil {
		t.Fatalf("the uninstall's removal failed on the link: %v", err)
	}
	assertCodexLinkKeptReport(t, report, junction)
	if after := hashCodexKeepTree(t, target); !equalCodexKeepTrees(after, before) {
		t.Fatalf("the uninstall's removal changed the folder behind the link: before %v after %v", before, after)
	}
}

// Outside the standalone profile the uninstall's removal is strict as well.
func TestWindowsCodexMachineTeardownRemovalKeepsNothingOutsideStandalone(t *testing.T) {
	fixture := newCodexKeepFixture(t, false)
	opts := codexKeepOptions(t, fixture.folder)
	if adminErr := requireWindowsCodexMachineAdministrator(); adminErr != nil {
		t.Skipf("the removal requires an elevated Administrator or LocalSystem token: %v", adminErr)
	}
	windowsCodexMachineReparseProbe = func(string) (string, error) { return fixture.folder, nil }
	report, _ := RemoveWindowsCodexMachineRequirementsForTeardown(opts)
	if report.LinkKept != "" || report.Disposition == "link_kept" {
		t.Fatalf("Secure Client kept a link: %+v", report)
	}
}

// Secure Client keeps the strict walk: the registry read goes through the
// trust checks and fails closed on a link, as before.
func TestWindowsCodexMachineTeardownRegistryUnchangedOutsideStandalone(t *testing.T) {
	fixture := newCodexKeepFixture(t, false)
	opts := codexKeepOptions(t, fixture.folder)
	windowsCodexMachineReparseProbe = func(string) (string, error) { return fixture.folder, nil }
	registry, err := ResolveWindowsCodexManagedRuntimeRegistryForTeardown(opts.HookBinary)
	if registry.Kept != "" {
		t.Fatalf("Secure Client kept a link: %+v", registry)
	}
	direct, directErr := ResolveWindowsCodexManagedRuntimeRegistry(opts.HookBinary)
	if (err == nil) != (directErr == nil) || registry.Active != direct.Active {
		t.Fatalf("teardown read %+v (%v) differs from the plain read %+v (%v)", registry, err, direct, directErr)
	}
}

// A real NTFS junction at ProgramData\OpenAI\Codex, with DefenseClaw-named
// decoys behind it, is found by the real probe and kept: the removal succeeds
// and the target keeps every byte and every name.
func TestWindowsCodexMachineTeardownKeepsARealJunction(t *testing.T) {
	if adminErr := requireWindowsCodexMachineAdministrator(); adminErr != nil {
		t.Skipf("the removal requires an elevated Administrator or LocalSystem token: %v", adminErr)
	}
	programData := t.TempDir()
	target := filepath.Join(t.TempDir(), "codex-target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range codexKeepDecoyNames {
		if err := os.WriteFile(filepath.Join(target, name), []byte("decoy "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	vendor := filepath.Join(programData, "OpenAI")
	if err := os.MkdirAll(vendor, 0o755); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(vendor, "Codex")
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v (%s)", err, output)
	}
	t.Cleanup(func() { _ = os.Remove(junction) })
	before := hashCodexKeepTree(t, target)

	previousProgramData, previousStandalone := windowsCodexMachineProgramData, windowsCodexMachineStandaloneProcess
	t.Cleanup(func() {
		windowsCodexMachineProgramData, windowsCodexMachineStandaloneProcess = previousProgramData, previousStandalone
		windowsCodexMachineKept.Lock()
		windowsCodexMachineKept.paths = map[string]string{}
		windowsCodexMachineKept.Unlock()
	})
	windowsCodexMachineProgramData = func() (string, error) { return programData, nil }
	windowsCodexMachineStandaloneProcess = func() bool { return true }
	opts := codexKeepOptions(t, junction)

	kept, err := WindowsCodexMachineFolderKept()
	if err != nil || !strings.EqualFold(kept, junction) {
		t.Fatalf("kept = %q, %v; want the junction %q", kept, err, junction)
	}
	report, err := RemoveWindowsCodexMachineRequirementsForTeardown(opts)
	if err != nil || !report.OK || report.Disposition != "link_kept" {
		t.Fatalf("removal over a real junction: %+v, %v", report, err)
	}
	assertCodexLinkKeptReport(t, report, junction)
	registry, err := ResolveWindowsCodexManagedRuntimeRegistryForTeardown(opts.HookBinary)
	if err != nil || !strings.EqualFold(registry.Kept, junction) || registry.Active {
		t.Fatalf("registry over a real junction: %+v, %v", registry, err)
	}
	after := hashCodexKeepTree(t, target)
	if !equalCodexKeepTrees(before, after) {
		t.Fatalf("the junction target changed: before %v after %v", before, after)
	}
	var names []string
	for name := range after {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) != len(codexKeepDecoyNames) {
		t.Fatalf("the target now lists %v", names)
	}
	if info, err := os.Lstat(junction); err != nil || info.Mode()&os.ModeSymlink == 0 && info.Mode()&os.ModeIrregular == 0 {
		t.Fatalf("the junction is gone or no longer a link: %v %v", info, err)
	}
	// A plain folder at the same place is not kept.
	if err := os.Remove(junction); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(junction, 0o755); err != nil {
		t.Fatal(err)
	}
	if kept, err := WindowsCodexMachineFolderKept(); err != nil || kept != "" {
		t.Fatalf("a plain folder was kept: %q, %v", kept, err)
	}
}
