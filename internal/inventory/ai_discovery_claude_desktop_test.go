// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/claudedesktop"
)

func claudeDesktopTestCatalog() []AISignature {
	return []AISignature{{ID: claudeDesktopSignatureID, Name: "Claude Desktop", Vendor: "Anthropic", Category: SignalDesktopApp, Confidence: 0.88}}
}

// claudeDesktopTestOS runs a test under another operating system's layout.
func claudeDesktopTestOS(t *testing.T, goos string) {
	t.Helper()
	restore, restoreRoots := discoveryGOOS, claudeDesktopSystemAppRoots
	t.Cleanup(func() { discoveryGOOS, claudeDesktopSystemAppRoots = restore, restoreRoots })
	discoveryGOOS = goos
	claudeDesktopSystemAppRoots = []string{filepath.Join(t.TempDir(), "Applications")}
	// The layouts are seeded under a temporary home and named through the
	// environment (t.Setenv), also on a real Windows host, whose platform
	// lookup reads the account's known folders.
	restoreVariables := discoveryVariableOverride
	t.Cleanup(func() { discoveryVariableOverride = restoreVariables })
	discoveryVariableOverride = os.LookupEnv
}

func claudeDesktopTestService(home string) *ContinuousDiscoveryService {
	return &ContinuousDiscoveryService{
		catalog: claudeDesktopTestCatalog(),
		opts:    AIDiscoveryOptions{HomeDir: home, HomeDirs: []string{home}},
	}
}

func claudeDesktopOne(t *testing.T, s *ContinuousDiscoveryService) AISignal {
	t.Helper()
	signals := s.detectClaudeDesktop()
	if len(signals) != 1 || signals[0].ClaudeDesktop == nil {
		t.Fatalf("claude_desktop signals = %+v, want exactly one with a block", signals)
	}
	sig := signals[0]
	if sig.Detector != claudeDesktopDetector || sig.Category != SignalDesktopApp || sig.SignatureID != claudeDesktopSignatureID {
		t.Fatalf("signal = %s/%s/%s", sig.Detector, sig.Category, sig.SignatureID)
	}
	return sig
}

func sparseFile(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

const claudeDesktopTestPlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.anthropic.claudefordesktop</string>
<key>CFBundleShortVersionString</key>
<string>4.4212.0</string>
</dict></plist>`

// seedClaudeDesktopData writes what a Cowork Mac holds: two engine builds,
// a VM bundle (one large sparse image), a session and the plugin manifest.
func seedClaudeDesktopData(t *testing.T, data string) (bundleBytes int64) {
	t.Helper()
	for _, dir := range []string{"claude-code/2.1.9/aaaa", "claude-code/2.1.309/5af865b9901c", "claude-code/not-a-version"} {
		if err := os.MkdirAll(filepath.Join(data, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bundle := filepath.Join(data, "vm_bundles", "claudevm.bundle")
	sparseFile(t, filepath.Join(bundle, "rootfs.img"), 64<<20)
	mustWrite(t, filepath.Join(bundle, "vmlinuz"), strings.Repeat("k", 1000))
	mustWrite(t, filepath.Join(bundle, ".cowork-adopted"), strings.Repeat("a", 40))
	mustWrite(t, filepath.Join(bundle, "nested", "disk.part"), strings.Repeat("n", 500))
	// The warm VM beside the bundle is not the bundle.
	mustWrite(t, filepath.Join(data, "vm_bundles", "warm", "rootfs.img"), strings.Repeat("w", 7777))
	sessions := filepath.Join(data, "local-agent-mode-sessions")
	mustWrite(t, filepath.Join(sessions, "acct-1", "org-1", "local_abc.json"), `{}`)
	mustWrite(t, filepath.Join(sessions, "acct-1", "org-1", "rpm", "manifest.json"),
		`{"plugins":[{"id":"p1","name":"sales-tools"},{"id":"p2","name":"  finance  "},{"id":"p3","name":""},{"id":"p4","name":"bad\u0007name"},{"id":"p5","name":"sales-tools"}]}`)
	// Anthropic's own skills live beside the accounts and are not plugins.
	mustWrite(t, filepath.Join(sessions, "skills-plugin", "org-1", "acct-1", "manifest.json"), `{"plugins":[{"name":"skills-decoy"}]}`)
	return 64<<20 + 1000 + 40 + 500
}

func TestClaudeDesktopMacOSReportsCoworkFacts(t *testing.T) {
	claudeDesktopTestOS(t, "darwin")
	home := t.TempDir()
	data := filepath.Join(home, "Library", "Application Support", "Claude")
	want := seedClaudeDesktopData(t, data)
	mustWrite(t, filepath.Join(claudeDesktopSystemAppRoots[0], "Claude.app", "Contents", "Info.plist"), claudeDesktopTestPlist)

	sig := claudeDesktopOne(t, claudeDesktopTestService(home))
	info := sig.ClaudeDesktop
	if !info.Installed || info.InstalledSource != ClaudeDesktopInstalledAppBundle || info.Version != "4.4212.0" {
		t.Fatalf("install = %+v", info)
	}
	if info.EngineVersion != "2.1.309" {
		t.Fatalf("engine = %q, want the newest build 2.1.309", info.EngineVersion)
	}
	if !info.VMBundlePresent || info.VMBundleBytes != want {
		t.Fatalf("bundle present=%v bytes=%d, want true/%d (the bundle's files, not the warm VM)", info.VMBundlePresent, info.VMBundleBytes, want)
	}
	if info.CoworkEnabled == nil || !*info.CoworkEnabled || info.CoworkEnabledSource != ClaudeDesktopCoworkSessions {
		t.Fatalf("cowork = %v/%q, want true from the sessions", info.CoworkEnabled, info.CoworkEnabledSource)
	}
	if got := strings.Join(info.CoworkPlugins, ","); got != "finance,sales-tools" {
		t.Fatalf("plugins = %q, want the deduplicated printable names of the account manifest", got)
	}
	if sig.Partial {
		t.Fatalf("a complete read was reported partial (%s)", sig.CoverageReason)
	}
	raw, err := json.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"claude_desktop":{"installed":true,"installed_source":"app_bundle","version":"4.4212.0","cowork_enabled":true,`,
		`"cowork_enabled_source":"cowork_sessions","engine_version":"2.1.309","vm_bundle_present":true,"vm_bundle_bytes":`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("signal JSON lacks %s:\n%s", want, raw)
		}
	}
	if len(sig.Evidence) != 1 || sig.Evidence[0].PathHash != hashPath(data) || sig.Evidence[0].RawPath != "" {
		t.Fatalf("evidence = %+v, want the data folder's hash and no raw path", sig.Evidence)
	}
}

func TestClaudeDesktopCoworkEnabledNeverGuessesTrue(t *testing.T) {
	claudeDesktopTestOS(t, "darwin")
	for _, tc := range []struct {
		name       string
		seed       func(data string)
		wantEnable string // "true", "false" or "null"
		wantSource string
	}{
		{"nothing to go on", func(data string) {
			mustWrite(t, filepath.Join(data, "claude_desktop_config.json"), `{"preferences":{"coworkScheduledTasksEnabled":true}}`)
		}, "null", ""},
		{"the VM image alone", func(data string) {
			mustWrite(t, filepath.Join(data, "vm_bundles", "claudevm.bundle", "rootfs.img"), "x")
		}, "true", ClaudeDesktopCoworkVMBundle},
		{"a session alone", func(data string) {
			mustWrite(t, filepath.Join(data, "local-agent-mode-sessions", "a", "o", "local_1.json"), "{}")
		}, "true", ClaudeDesktopCoworkSessions},
		{"a session folder without a session", func(data string) {
			mustWrite(t, filepath.Join(data, "local-agent-mode-sessions", "a", "o", "scheduled-tasks.json"), "{}")
			mustWrite(t, filepath.Join(data, "local-agent-mode-sessions", "skills-plugin", "o", "local_2.json"), "{}")
		}, "null", ""},
		{"the machine cannot run the VM", func(data string) {
			mustWrite(t, filepath.Join(data, "vm-support-probe.json"), `{"key":"4.4212.0|27.0.0|arm64","virtSupport":"unsupported"}`)
		}, "false", ClaudeDesktopCoworkVMProbeOff},
		{"the machine can run the VM, which proves nothing", func(data string) {
			mustWrite(t, filepath.Join(data, "vm-support-probe.json"), `{"virtSupport":"supported"}`)
		}, "null", ""},
		{"a broken probe", func(data string) {
			mustWrite(t, filepath.Join(data, "vm-support-probe.json"), `{`)
		}, "null", ""},
		{"use beats the probe", func(data string) {
			mustWrite(t, filepath.Join(data, "vm-support-probe.json"), `{"virtSupport":"unsupported"}`)
			mustWrite(t, filepath.Join(data, "local-agent-mode-sessions", "a", "o", "local_1.json"), "{}")
		}, "true", ClaudeDesktopCoworkSessions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			data := filepath.Join(home, "Library", "Application Support", "Claude")
			if err := os.MkdirAll(data, 0o700); err != nil {
				t.Fatal(err)
			}
			tc.seed(data)
			info := claudeDesktopOne(t, claudeDesktopTestService(home)).ClaudeDesktop
			raw, err := json.Marshal(info)
			if err != nil {
				t.Fatal(err)
			}
			if want := `"cowork_enabled":` + tc.wantEnable; !strings.Contains(string(raw), want) {
				t.Fatalf("block = %s, want %s", raw, want)
			}
			if info.CoworkEnabledSource != tc.wantSource {
				t.Fatalf("source = %q, want %q", info.CoworkEnabledSource, tc.wantSource)
			}
			if info.Installed {
				t.Fatalf("a data folder alone reported the macOS app installed: %+v", info)
			}
		})
	}
}

func TestClaudeDesktopNoDataFolderNoSignal(t *testing.T) {
	claudeDesktopTestOS(t, "darwin")
	home := t.TempDir()
	mustWrite(t, filepath.Join(claudeDesktopSystemAppRoots[0], "Claude.app", "Contents", "Info.plist"), claudeDesktopTestPlist)
	if got := claudeDesktopTestService(home).detectClaudeDesktop(); len(got) != 0 {
		t.Fatalf("an app that never ran produced %+v; the application detector reports it", got)
	}
	// Without the catalog entry there is nothing to attach to.
	data := filepath.Join(home, "Library", "Application Support", "Claude")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	s := claudeDesktopTestService(home)
	s.catalog = nil
	if got := s.detectClaudeDesktop(); len(got) != 0 {
		t.Fatalf("no catalog entry still produced %+v", got)
	}
}

func TestClaudeDesktopUserApplicationsBundleCounts(t *testing.T) {
	claudeDesktopTestOS(t, "darwin")
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "Library", "Application Support", "Claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(home, "Applications", "Claude.app", "Contents", "Info.plist"), claudeDesktopTestPlist)
	info := claudeDesktopOne(t, claudeDesktopTestService(home)).ClaudeDesktop
	if !info.Installed || info.Version != "4.4212.0" {
		t.Fatalf("~/Applications bundle not read: %+v", info)
	}
}

func TestClaudeDesktopWindowsLayouts(t *testing.T) {
	claudeDesktopTestOS(t, "windows")
	t.Run("roaming data with a Squirrel install", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
		t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
		t.Setenv("PROGRAMFILES", filepath.Join(home, "Program Files"))
		data := filepath.Join(home, "AppData", "Roaming", "Claude")
		seedClaudeDesktopData(t, data)
		for _, dir := range []string{"app-4.3000.1", "app-4.4212.0", "packages"} {
			if err := os.MkdirAll(filepath.Join(home, "AppData", "Local", "AnthropicClaude", dir), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		info := claudeDesktopOne(t, claudeDesktopTestService(home)).ClaudeDesktop
		if !info.Installed || info.InstalledSource != ClaudeDesktopInstalledInstallFolder || info.Version != "4.4212.0" {
			t.Fatalf("install = %+v", info)
		}
		if info.EngineVersion != "2.1.309" || !info.VMBundlePresent || info.CoworkEnabled == nil || !*info.CoworkEnabled {
			t.Fatalf("data folder facts = %+v", info)
		}
	})
	t.Run("MSIX package", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
		t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
		t.Setenv("PROGRAMFILES", filepath.Join(home, "Program Files"))
		data := filepath.Join(home, "AppData", "Local", "Packages", "Claude_pzs8sxrjxfjjc", "LocalCache", "Roaming", "Claude")
		seedClaudeDesktopData(t, data)
		for _, dir := range []string{"Claude_4.3000.1.0_x64__pzs8sxrjxfjjc", "Claude_4.4212.0.0_x64__pzs8sxrjxfjjc", "Other_9.9.9.9_x64__zzz"} {
			if err := os.MkdirAll(filepath.Join(home, "Program Files", "WindowsApps", dir), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		sig := claudeDesktopOne(t, claudeDesktopTestService(home))
		info := sig.ClaudeDesktop
		// WindowsApps names every build on the machine, not the one this account runs.
		if !info.Installed || info.InstalledSource != ClaudeDesktopInstalledMSIXPackage || info.Version != "" {
			t.Fatalf("install = %+v, want an MSIX install with no version", info)
		}
		if info.EngineVersion != "2.1.309" || !info.VMBundlePresent {
			t.Fatalf("data folder facts = %+v", info)
		}
		if sig.Evidence[0].PathHash != hashPath(data) {
			t.Fatalf("evidence is not the package's data folder")
		}
	})
	t.Run("data folder without an install is not installed", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
		t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
		t.Setenv("PROGRAMFILES", filepath.Join(home, "Program Files"))
		seedClaudeDesktopData(t, filepath.Join(home, "AppData", "Roaming", "Claude"))
		info := claudeDesktopOne(t, claudeDesktopTestService(home)).ClaudeDesktop
		if info.Installed || info.InstalledSource != "" {
			t.Fatalf("leftover data reported installed: %+v", info)
		}
	})
	t.Run("a service scan keeps each profile's install and data apart", func(t *testing.T) {
		root := t.TempDir()
		alice, bob := filepath.Join(root, "Users", "alice"), filepath.Join(root, "Users", "bob")
		seedClaudeDesktopData(t, filepath.Join(alice, "AppData", "Roaming", "Claude"))
		if err := os.MkdirAll(filepath.Join(alice, "AppData", "Local", "AnthropicClaude", "app-4.4212.0"), 0o700); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(bob, "AppData", "Roaming", "Claude", "vm-support-probe.json"), `{"virtSupport":"unsupported"}`)
		t.Setenv("APPDATA", filepath.Join(root, "service", "AppData", "Roaming"))
		s := claudeDesktopTestService(alice)
		s.opts.HomeDirs = []string{alice, bob}
		s.opts.homeOwners = []discoveryHomeOwner{
			{Home: alice, UserID: "S-1-5-21-1-2-3-1001", UserName: "alice"},
			{Home: bob, UserID: "S-1-5-21-1-2-3-1002", UserName: "bob"},
		}
		signals := s.detectClaudeDesktop()
		if len(signals) != 2 {
			t.Fatalf("signals = %+v, want one per profile", signals)
		}
		byUser := map[string]*ClaudeDesktopInfo{}
		for _, sig := range signals {
			byUser[sig.UserName] = sig.ClaudeDesktop
		}
		if a := byUser["alice"]; a == nil || !a.Installed || a.Version != "4.4212.0" || !a.VMBundlePresent {
			t.Fatalf("alice = %+v", a)
		}
		if b := byUser["bob"]; b == nil || b.Installed || b.VMBundlePresent || b.CoworkEnabled == nil || *b.CoworkEnabled {
			t.Fatalf("bob = %+v, want not installed and Cowork off from the probe", b)
		}
	})
}

func TestClaudeDesktopLinuxLayout(t *testing.T) {
	claudeDesktopTestOS(t, "linux")
	home := t.TempDir()
	seedClaudeDesktopData(t, filepath.Join(home, ".config", "Claude"))
	info := claudeDesktopOne(t, claudeDesktopTestService(home)).ClaudeDesktop
	if !info.Installed || info.InstalledSource != ClaudeDesktopInstalledDataFolder || info.Version != "" {
		t.Fatalf("install = %+v, want the data folder as the only install evidence", info)
	}
	if info.EngineVersion != "2.1.309" || !info.VMBundlePresent || info.CoworkEnabled == nil || !*info.CoworkEnabled {
		t.Fatalf("facts = %+v", info)
	}
}

func TestClaudeDesktopUnknownOSReportsNothing(t *testing.T) {
	claudeDesktopTestOS(t, "plan9")
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "Claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := claudeDesktopTestService(home).detectClaudeDesktop(); len(got) != 0 {
		t.Fatalf("signals = %+v", got)
	}
}

func TestClaudeDesktopBoundsAndLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	claudeDesktopTestOS(t, "darwin")
	t.Run("a huge bundle is counted by a bounded listing", func(t *testing.T) {
		home := t.TempDir()
		data := filepath.Join(home, "Library", "Application Support", "Claude")
		bundle := filepath.Join(data, "vm_bundles", "claudevm.bundle")
		for i := 0; i < claudeDesktopMaxBundleEntries+40; i++ {
			mustWrite(t, filepath.Join(bundle, fmt.Sprintf("part-%04d", i)), "12345")
		}
		sig := claudeDesktopOne(t, claudeDesktopTestService(home))
		info := sig.ClaudeDesktop
		if !info.VMBundlePresent || info.VMBundleBytes != int64(claudeDesktopMaxBundleEntries)*5 {
			t.Fatalf("bundle = %v/%d, want a lower bound of %d bytes", info.VMBundlePresent, info.VMBundleBytes, claudeDesktopMaxBundleEntries*5)
		}
		if !sig.Partial || sig.CoverageReason != CoverageReasonCapExceeded {
			t.Fatalf("partial=%v reason=%q, want cap_exceeded", sig.Partial, sig.CoverageReason)
		}
	})
	t.Run("too many plugins are cut and reported partial", func(t *testing.T) {
		home := t.TempDir()
		data := filepath.Join(home, "Library", "Application Support", "Claude")
		var plugins []string
		for i := 0; i < claudeDesktopMaxPlugins+10; i++ {
			plugins = append(plugins, fmt.Sprintf(`{"name":"plugin-%03d"}`, i))
		}
		mustWrite(t, filepath.Join(data, "local-agent-mode-sessions", "a", "o", "rpm", "manifest.json"), `{"plugins":[`+strings.Join(plugins, ",")+`]}`)
		sig := claudeDesktopOne(t, claudeDesktopTestService(home))
		if len(sig.ClaudeDesktop.CoworkPlugins) != claudeDesktopMaxPlugins || sig.CoverageReason != CoverageReasonCapExceeded {
			t.Fatalf("plugins=%d reason=%q", len(sig.ClaudeDesktop.CoworkPlugins), sig.CoverageReason)
		}
	})
	t.Run("an oversized or broken manifest is partial, not fatal", func(t *testing.T) {
		home := t.TempDir()
		data := filepath.Join(home, "Library", "Application Support", "Claude")
		mustWrite(t, filepath.Join(data, "local-agent-mode-sessions", "a", "o", "rpm", "manifest.json"), `{"plugins":`)
		sig := claudeDesktopOne(t, claudeDesktopTestService(home))
		if len(sig.ClaudeDesktop.CoworkPlugins) != 0 || sig.CoverageReason != CoverageReasonParseError {
			t.Fatalf("plugins=%v reason=%q", sig.ClaudeDesktop.CoworkPlugins, sig.CoverageReason)
		}
	})
	// A link at any level must not lead into another account's data. The
	// victim's folder has every fact; the attacker's own folder holds only the
	// link, so any leaked fact shows in the block.
	for _, tc := range []struct {
		name string
		link string // relative to the data folder
		to   string // relative to the victim's data folder
		real func(t *testing.T, data string)
		part string // CoverageReason expected when the scan hit the link
	}{
		{name: "claude-code", link: "claude-code", to: "claude-code", part: CoverageReasonReadError},
		{name: "vm_bundles", link: "vm_bundles", to: "vm_bundles", part: CoverageReasonReadError},
		{name: "the bundle itself", link: "vm_bundles/claudevm.bundle", to: "vm_bundles/claudevm.bundle"},
		{name: "a folder inside the bundle", link: "vm_bundles/claudevm.bundle/nested", to: "vm_bundles/claudevm.bundle/nested",
			real: func(t *testing.T, data string) {
				mustWrite(t, filepath.Join(data, "vm_bundles", "claudevm.bundle", "own.img"), "12345")
			}},
		{name: "local-agent-mode-sessions", link: "local-agent-mode-sessions", to: "local-agent-mode-sessions", part: CoverageReasonReadError},
		{name: "the account folder", link: "local-agent-mode-sessions/acct-1", to: "local-agent-mode-sessions/acct-1"},
		{name: "the organization folder", link: "local-agent-mode-sessions/acct-1/org-1", to: "local-agent-mode-sessions/acct-1/org-1"},
		{name: "the plugin folder", link: "local-agent-mode-sessions/acct-1/org-1/rpm", to: "local-agent-mode-sessions/acct-1/org-1/rpm",
			real: func(t *testing.T, data string) {
				mustWrite(t, filepath.Join(data, "local-agent-mode-sessions", "acct-1", "org-1", "scheduled-tasks.json"), "{}")
			}},
	} {
		t.Run("a link is not followed: "+tc.name, func(t *testing.T) {
			victim := filepath.Join(t.TempDir(), "victim")
			seedClaudeDesktopData(t, victim)
			home := t.TempDir()
			data := filepath.Join(home, "Library", "Application Support", "Claude")
			if tc.real != nil {
				tc.real(t, data)
			}
			link := filepath.Join(data, filepath.FromSlash(tc.link))
			if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(victim, filepath.FromSlash(tc.to)), link); err != nil {
				t.Fatal(err)
			}
			sig := claudeDesktopOne(t, claudeDesktopTestService(home))
			info := sig.ClaudeDesktop
			ownBundle := tc.name == "a folder inside the bundle" // its own file is real evidence
			if info.EngineVersion != "" || len(info.CoworkPlugins) != 0 || (info.CoworkEnabled != nil) != ownBundle {
				t.Fatalf("another account's data came through the link: %+v", info)
			}
			if ownBundle {
				if info.VMBundleBytes != 5 {
					t.Fatalf("bundle bytes = %d, want only the account's own file", info.VMBundleBytes)
				}
			} else if info.VMBundlePresent || info.VMBundleBytes != 0 {
				t.Fatalf("another account's VM bundle came through the link: %+v", info)
			}
			if tc.part != "" && sig.CoverageReason != tc.part {
				t.Fatalf("coverage = %q/%v, want %q", sig.CoverageReason, sig.Partial, tc.part)
			}
		})
	}
	t.Run("a linked data folder is not a data folder", func(t *testing.T) {
		outside := t.TempDir()
		linked := t.TempDir()
		linkedData := filepath.Join(linked, "Library", "Application Support", "Claude")
		if err := os.MkdirAll(filepath.Dir(linkedData), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, linkedData); err != nil {
			t.Fatal(err)
		}
		if got := claudeDesktopTestService(linked).detectClaudeDesktop(); len(got) != 0 {
			t.Fatalf("a linked data folder produced %+v", got)
		}
	})
	t.Run("a linked folder above the data folder is not followed", func(t *testing.T) {
		outside := t.TempDir()
		seedClaudeDesktopData(t, filepath.Join(outside, "Claude"))
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, "Library"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(home, "Library", "Application Support")); err != nil {
			t.Fatal(err)
		}
		if got := claudeDesktopTestService(home).detectClaudeDesktop(); len(got) != 0 {
			t.Fatalf("a data folder below a linked Application Support produced %+v", got)
		}
	})
	t.Run("a folder swapped for a link after the check is refused", func(t *testing.T) {
		victim := filepath.Join(t.TempDir(), "victim")
		seedClaudeDesktopData(t, victim)
		dir := filepath.Join(t.TempDir(), "claude-code")
		if err := os.Symlink(filepath.Join(victim, "claude-code"), dir); err != nil {
			t.Fatal(err)
		}
		if _, _, err := claudeDesktopReadDir(dir, 8); !errors.Is(err, errClaudeDesktopLink) {
			t.Fatalf("listing a link: %v, want errClaudeDesktopLink", err)
		}
	})
}

func TestClaudeDesktopChangeIsAChangedSignalNotANewOne(t *testing.T) {
	claudeDesktopTestOS(t, "darwin")
	home := t.TempDir()
	data := filepath.Join(home, "Library", "Application Support", "Claude")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	before := claudeDesktopOne(t, claudeDesktopTestService(home))
	mustWrite(t, filepath.Join(data, "vm_bundles", "claudevm.bundle", "rootfs.img"), "x")
	after := claudeDesktopOne(t, claudeDesktopTestService(home))
	if before.Fingerprint != after.Fingerprint {
		t.Fatal("Cowork turning on changed the fingerprint: it would read as gone and new")
	}
	if before.EvidenceHash == after.EvidenceHash {
		t.Fatal("Cowork turning on left the evidence hash alone: no changed state")
	}
	// The image's size moves without anything having changed.
	mustWrite(t, filepath.Join(data, "vm_bundles", "claudevm.bundle", "rootfs.img"), "xxxxxxxx")
	grown := claudeDesktopOne(t, claudeDesktopTestService(home))
	if grown.EvidenceHash != after.EvidenceHash || grown.ClaudeDesktop.VMBundleBytes == after.ClaudeDesktop.VMBundleBytes {
		t.Fatal("the size of the VM image must update the block but not the evidence hash")
	}
}

func TestClaudeDesktopSandboxScanSkipsTheDetector(t *testing.T) {
	if !(&ContinuousDiscoveryService{sandbox: &sandboxFacts{}}).hostOnlyDetector(claudeDesktopDetector) {
		t.Fatal("a sandbox scan runs the claude_desktop detector")
	}
	if (&ContinuousDiscoveryService{}).hostOnlyDetector(claudeDesktopDetector) {
		t.Fatal("a host scan skips the claude_desktop detector")
	}
}

func TestClaudeDesktopBlockValidation(t *testing.T) {
	yes := true
	ok := AISignal{Detector: claudeDesktopDetector, Category: SignalDesktopApp, ClaudeDesktop: &ClaudeDesktopInfo{
		Installed: true, InstalledSource: ClaudeDesktopInstalledAppBundle, Version: "4.4212.0",
		CoworkEnabled: &yes, CoworkEnabledSource: ClaudeDesktopCoworkSessions, EngineVersion: "2.1.309",
		VMBundlePresent: true, VMBundleBytes: 12, CoworkPlugins: []string{"sales-tools"},
	}}
	if err := validateClaudeDesktopInfo(ok); err != nil {
		t.Fatalf("a good block was refused: %v", err)
	}
	for name, mutate := range map[string]func(*AISignal){
		"another detector":         func(s *AISignal) { s.Detector = "config" },
		"another category":         func(s *AISignal) { s.Category = SignalMCPServer },
		"a path as the version":    func(s *AISignal) { s.ClaudeDesktop.Version = "/Applications/Claude.app" },
		"a bad engine":             func(s *AISignal) { s.ClaudeDesktop.EngineVersion = "latest" },
		"an unknown install":       func(s *AISignal) { s.ClaudeDesktop.InstalledSource = "registry" },
		"an unknown cowork source": func(s *AISignal) { s.ClaudeDesktop.CoworkEnabledSource = "guess" },
		"a source without install": func(s *AISignal) { s.ClaudeDesktop.Installed = false },
		"enabled without source":   func(s *AISignal) { s.ClaudeDesktop.CoworkEnabledSource = "" },
		"source without enabled":   func(s *AISignal) { s.ClaudeDesktop.CoworkEnabled = nil },
		"negative bytes":           func(s *AISignal) { s.ClaudeDesktop.VMBundleBytes = -1 },
		"bytes without a bundle": func(s *AISignal) {
			s.ClaudeDesktop.VMBundlePresent = false
		},
		"a control character": func(s *AISignal) { s.ClaudeDesktop.CoworkPlugins = []string{"a\x00b"} },
		"an empty plugin":     func(s *AISignal) { s.ClaudeDesktop.CoworkPlugins = []string{""} },
		"a long plugin name": func(s *AISignal) {
			s.ClaudeDesktop.CoworkPlugins = []string{strings.Repeat("p", claudeDesktopTextMax+1)}
		},
		"too many plugins": func(s *AISignal) {
			s.ClaudeDesktop.CoworkPlugins = make([]string, claudeDesktopMaxPlugins+1)
			for i := range s.ClaudeDesktop.CoworkPlugins {
				s.ClaudeDesktop.CoworkPlugins[i] = "p"
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			sig := ok
			block := *ok.ClaudeDesktop
			sig.ClaudeDesktop = &block
			mutate(&sig)
			if err := validateClaudeDesktopInfo(sig); err == nil {
				t.Fatal("a bad block was accepted")
			}
		})
	}
}

// The block crosses the per-user spool: the worker's report must pass the
// gateway's checks, decode strictly, and keep its change detection after the
// gateway re-derives the hashes.
func TestClaudeDesktopBlockSurvivesAPerUserScanRecord(t *testing.T) {
	claudeDesktopTestOS(t, "darwin")
	home := t.TempDir()
	seedClaudeDesktopData(t, filepath.Join(home, "Library", "Application Support", "Claude"))
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	stubProcessSnapshotSource(t, func() ([]processInfo, error) { return nil, nil })
	report := ScanUserHome(context.Background(), home, "alice", 1001, UserScanOptions{}, catalog)
	if err := SanitizeUserScanReport(&report, catalog, false, false); err != nil {
		t.Fatalf("SanitizeUserScanReport: %v", err)
	}
	if err := ValidateUserScanReport(report, catalog); err != nil {
		t.Fatalf("ValidateUserScanReport: %v", err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded AIDiscoveryReport
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	var sig *AISignal
	for i := range decoded.Signals {
		if decoded.Signals[i].Detector == claudeDesktopDetector {
			sig = &decoded.Signals[i]
		}
	}
	if sig == nil || sig.ClaudeDesktop == nil || sig.ClaudeDesktop.EngineVersion != "2.1.309" {
		t.Fatalf("claude_desktop signal missing from the record: %+v", decoded.Signals)
	}
	svc := claudeDesktopTestService(home)
	attributed := svc.attributeUserScanSignal(*sig, "1001", "alice")
	if attributed.EvidenceHash != claudeDesktopEvidenceHash(hashEvidence(attributed.Evidence), attributed.ClaudeDesktop) {
		t.Fatal("the gateway's re-derived evidence hash dropped the block")
	}
	other := *sig
	block := *sig.ClaudeDesktop
	block.EngineVersion = "2.1.400"
	other.ClaudeDesktop = &block
	if svc.attributeUserScanSignal(other, "1001", "alice").EvidenceHash == attributed.EvidenceHash {
		t.Fatal("a new engine version is not a changed signal for a per-user record")
	}
	// An external report may carry the block only on claude_desktop signals.
	decoded.Signals[0].ClaudeDesktop = sig.ClaudeDesktop
	if decoded.Signals[0].Detector != claudeDesktopDetector {
		if err := ValidateSanitizedAIDiscoveryReport(decoded); err == nil {
			t.Fatal("the block was accepted on another detector's signal")
		}
	}
}

// claudeDesktopRootData is root's data folder under home on goos, with an
// MSIX "*" filled in; it names the Windows folders through the environment
// like claudeDesktopTestOS expects.
func claudeDesktopRootData(t *testing.T, goos, home string, root claudedesktop.Root) string {
	t.Helper()
	f := claudedesktop.FoldersForHome(goos, home)
	if goos == "windows" {
		t.Setenv("APPDATA", f.AppData)
		t.Setenv("LOCALAPPDATA", f.LocalAppData)
		t.Setenv("PROGRAMFILES", filepath.Join(home, "Program Files"))
	}
	return strings.Replace(root.Pattern(f), "*", "pzs8sxrjxfjjc", 1)
}

// Every data root of every OS (internal/claudedesktop) is scanned and the
// signal says which deployment it is (cowork-1-0-8 GAP-0024: the
// third-party inference folder Claude-3p was never scanned).
func TestClaudeDesktopReportsTheDeploymentOfEveryDataRoot(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "windows"} {
		for _, root := range claudedesktop.Roots(goos) {
			t.Run(goos+"/"+root.Path, func(t *testing.T) {
				claudeDesktopTestOS(t, goos)
				home := t.TempDir()
				data := claudeDesktopRootData(t, goos, home, root)
				seedClaudeDesktopData(t, data)
				sig := claudeDesktopOne(t, claudeDesktopTestService(home))
				info := sig.ClaudeDesktop
				if info.Deployment != string(root.Deployment) || info.EngineVersion != "2.1.309" || !info.VMBundlePresent ||
					info.CoworkEnabled == nil || !*info.CoworkEnabled || sig.Evidence[0].PathHash != hashPath(data) {
					t.Fatalf("%s: block = %+v evidence %+v", data, info, sig.Evidence)
				}
				if err := validateClaudeDesktopInfo(sig); err != nil {
					t.Fatalf("the block does not validate: %v", err)
				}
			})
		}
	}
}

// One account with both deployments (the measured Mac and Windows test
// machines) reports one signal per data folder.
func TestClaudeDesktopBothDeploymentsAreTwoSignals(t *testing.T) {
	claudeDesktopTestOS(t, "darwin")
	home := t.TempDir()
	seedClaudeDesktopData(t, filepath.Join(home, "Library", "Application Support", "Claude"))
	thirdParty := filepath.Join(home, "Library", "Application Support", "Claude-3p")
	mustWrite(t, filepath.Join(thirdParty, "claude_desktop_config.json"), `{"deploymentMode":"3p"}`)
	if err := os.MkdirAll(filepath.Join(thirdParty, "claude-code", "2.1.317", "91184d3d9ba3"), 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(claudeDesktopSystemAppRoots[0], "Claude.app", "Contents", "Info.plist"), claudeDesktopTestPlist)
	signals := claudeDesktopTestService(home).detectClaudeDesktop()
	got := map[string]*ClaudeDesktopInfo{}
	for _, sig := range signals {
		got[sig.ClaudeDesktop.Deployment] = sig.ClaudeDesktop
	}
	if len(signals) != 2 || got["1p"] == nil || got["3p"] == nil || got["1p"].EngineVersion != "2.1.309" ||
		got["3p"].EngineVersion != "2.1.317" || !got["3p"].Installed || got["3p"].InstalledSource != ClaudeDesktopInstalledAppBundle ||
		got["3p"].CoworkEnabled != nil {
		t.Fatalf("signals = %+v", got)
	}
	if signals[0].Fingerprint == signals[1].Fingerprint {
		t.Fatal("the two data folders share a fingerprint")
	}
	raw, err := json.Marshal(got["3p"])
	if err != nil || !strings.HasSuffix(string(raw), `,"deployment":"3p"}`) {
		t.Fatalf("3p block JSON = %s (%v)", raw, err)
	}
}

func TestClaudeDesktopDeploymentIsValidated(t *testing.T) {
	sig := AISignal{Detector: claudeDesktopDetector, Category: SignalDesktopApp, ClaudeDesktop: &ClaudeDesktopInfo{Deployment: "3p"}}
	if err := validateClaudeDesktopInfo(sig); err != nil {
		t.Fatalf("3p refused: %v", err)
	}
	sig.ClaudeDesktop.Deployment = "/Users/alice/Library/Application Support/Claude-3p"
	if err := validateClaudeDesktopInfo(sig); err == nil {
		t.Fatal("a path was accepted as the deployment")
	}
}

// The catalog's Claude Desktop config and MCP paths name every data root,
// the MSIX ones with their "*" too, so the next root is not missed there
// either (cowork-1-0-8 GAP-0024 review 1).
func TestClaudeDesktopCatalogPathsFollowTheDataRoots(t *testing.T) {
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	var sig *AISignature
	for i := range catalog {
		if catalog[i].ID == claudeDesktopSignatureID {
			sig = &catalog[i]
		}
	}
	if sig == nil {
		t.Fatal("no claude-desktop signature")
	}
	var want []string
	for _, goos := range []string{"darwin", "linux", "windows"} {
		for _, root := range claudedesktop.Roots(goos) {
			want = append(want, root.Candidate()+"/claude_desktop_config.json")
		}
	}
	for name, paths := range map[string][]string{"config_paths": sig.ConfigPaths, "mcp_paths": sig.MCPPaths} {
		if strings.Join(paths, "|") != strings.Join(want, "|") {
			t.Errorf("claude-desktop %s = %q, want %q", name, paths, want)
		}
	}
	// The measured MSIX first-party config is read, with its MCP servers.
	claudeDesktopTestOS(t, "windows")
	home := t.TempDir()
	data := claudeDesktopRootData(t, "windows", home, claudedesktop.Roots("windows")[1])
	config := filepath.Join(data, "claude_desktop_config.json")
	mustWrite(t, config, `{"mcpServers":{"files":{"command":"files-server"}}}`)
	svc := &ContinuousDiscoveryService{catalog: []AISignature{*sig}, opts: AIDiscoveryOptions{HomeDir: home, HomeDirs: []string{home}}}
	for name, signals := range map[string][]AISignal{"config": svc.detectConfigPaths(), "mcp": svc.detectMCPPaths()} {
		found := false
		for _, signal := range signals {
			for _, ev := range signal.Evidence {
				found = found || ev.PathHash == hashPath(config)
			}
		}
		if !found {
			t.Errorf("%s signals miss the MSIX config %s: %+v", name, config, signals)
		}
	}
}

// The measured MSIX machine: Packages\Claude_<id>\LocalCache\Roaming\Claude
// holds only the migration marker next to the real Claude-Data folder. It is
// no deployment of its own, so the account reports one first-party signal.
func TestClaudeDesktopMSIXMarkerFolderIsNoDeployment(t *testing.T) {
	claudeDesktopTestOS(t, "windows")
	home := t.TempDir()
	roots := claudedesktop.Roots("windows")
	seedClaudeDesktopData(t, claudeDesktopRootData(t, "windows", home, roots[1]))
	marker := claudeDesktopRootData(t, "windows", home, roots[2])
	mustWrite(t, filepath.Join(marker, claudedesktop.MigrationMarkerPrefix+"claude_pzs8sxrjxfjjc"), "")
	sig := claudeDesktopOne(t, claudeDesktopTestService(home))
	if sig.Evidence[0].PathHash != hashPath(claudeDesktopRootData(t, "windows", home, roots[1])) || sig.ClaudeDesktop.Deployment != "1p" {
		t.Fatalf("signal = %+v", sig)
	}
	// A folder with the marker and real data is still a data folder.
	mustWrite(t, filepath.Join(marker, "config.json"), "{}")
	if got := claudeDesktopTestService(home).detectClaudeDesktop(); len(got) != 2 {
		t.Fatalf("marker plus data: %d signals", len(got))
	}
}

// More Claude-Data folders than are read: the signals say the scan is
// partial (cap exceeded), and the installed package's folder is not crowded
// out by the ones the user made (cowork-1-0-8 GAP-0024 review 1).
func TestClaudeDesktopMSIXGlobOverflowIsPartial(t *testing.T) {
	claudeDesktopTestOS(t, "windows")
	home := t.TempDir()
	f := claudedesktop.FoldersForHome("windows", home)
	claudeDesktopRootData(t, "windows", home, claudedesktop.Roots("windows")[0])
	for i := 0; i < claudedesktop.MaxGlobMatches; i++ {
		if err := os.MkdirAll(filepath.Join(f.LocalAppData, "Claude-Data", "claude_"+strconv.Itoa(i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	genuine := filepath.Join(f.LocalAppData, "Claude-Data", "claude_pzs8sxrjxfjjc")
	seedClaudeDesktopData(t, genuine)
	reported := func() (bool, []AISignal) {
		signals := claudeDesktopTestService(home).detectClaudeDesktop()
		found := false
		for _, sig := range signals {
			if !sig.Partial || sig.CoverageReason != CoverageReasonCapExceeded {
				t.Fatalf("signal %+v is not partial (cap exceeded)", sig)
			}
			found = found || sig.Evidence[0].PathHash == hashPath(genuine)
		}
		return found, signals
	}
	if found, signals := reported(); found || len(signals) != claudedesktop.MaxGlobMatches {
		t.Fatalf("without the package folder: genuine reported %v, %d signals", found, len(signals))
	}
	if err := os.MkdirAll(filepath.Join(f.LocalAppData, "Packages", "Claude_pzs8sxrjxfjjc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if found, _ := reported(); !found {
		t.Fatal("with the package folder the genuine Claude-Data folder was not reported")
	}
}
