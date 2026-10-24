// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A package root reached through a link into ~/Documents is not walked
// without Full Disk Access, though its own path names no protected folder
// (GAP-1201). The privacy exclusion applies to the path the links resolve
// to: a relative link below a linked folder resolves from the folder the
// first link leads to, and /System/Volumes/Data is the same home seen
// through the Data volume's firmlink (GAP-0637).
func TestPackageRootThroughALinkIntoAProtectedFolderIsSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("macOS privacy rule; symbolic links need privileges on Windows")
	}
	restoreGOOS, restoreAccess := discoveryGOOS, macOSFullDiskAccess
	t.Cleanup(func() { discoveryGOOS, macOSFullDiskAccess = restoreGOOS, restoreAccess })
	discoveryGOOS = "darwin"
	macOSFullDiskAccess = func() bool { return false }

	for _, tc := range []struct {
		name  string
		links func(home string) [][2]string // link, target
		root  string
	}{
		{"absolute link", func(home string) [][2]string {
			return [][2]string{{"work/link", filepath.Join(home, "Documents")}}
		}, "work/link/project"},
		{"relative link below a linked folder", func(home string) [][2]string {
			return [][2]string{{"work/alias", filepath.Join(home, "stuff")}, {"stuff/docs", "../Documents"}}
		}, "work/alias/docs/project"},
		{"link through the Data volume", func(home string) [][2]string {
			return [][2]string{{"work/data", "/System/Volumes/Data" + filepath.Join(home, "Documents")}}
		}, "work/data/project"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(home, "Documents", "project", "package.json"), `{"dependencies": {"ai": "^3.0.0"}}`)
			mustWrite(t, filepath.Join(home, "work", "real", "package.json"), `{"dependencies": {"ai": "^3.0.0"}}`)
			if err := os.MkdirAll(filepath.Join(home, "stuff"), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, link := range tc.links(home) {
				if err := os.Symlink(link[1], filepath.Join(home, link[0])); err != nil {
					t.Fatal(err)
				}
			}
			catalog, err := LoadAISignatures()
			if err != nil {
				t.Fatalf("LoadAISignatures: %v", err)
			}
			svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
				Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
				ScanRoots:       []string{filepath.Join(home, tc.root), filepath.Join(home, "work", "real")},
				MaxFilesPerScan: 100, MaxFileBytes: 1 << 20,
			}, catalog)
			cleanupPreparedDiscoveryService(t, svc)
			signals, _, err := svc.detectPackageManifests(context.Background())
			if err != nil {
				t.Fatalf("detectPackageManifests: %v", err)
			}
			projects := 0
			for _, sig := range signals {
				if sig.Component != nil && sig.Component.Name == "ai" {
					projects++
				}
			}
			if projects != 1 || !svc.tccSkipped {
				t.Fatalf("%d manifest projects, privacy skip recorded %v; want only work/real and a recorded skip", projects, svc.tccSkipped)
			}
		})
	}
}

// A per-user install that also scans another folder keeps its account on
// the findings in its own home; a finding in the other folder gets none, and
// no raw path is kept when raw paths are not stored (GAP-1278).
func TestPerUserFindingsInTheOwnHomeKeepTheirOwnerBesideAnExtraFolder(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, extra := filepath.Join(root, "home"), filepath.Join(root, "shared")
	mustWrite(t, filepath.Join(home, ".codex", "config.toml"), "model = \"x\"\n")
	mustWrite(t, filepath.Join(extra, ".claude", "settings.json"), "{}")
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("LoadAISignatures: %v", err)
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(root, "data"), HomeDir: home,
		HomeDirs: []string{home, extra}, MaxFilesPerScan: 100, MaxFileBytes: 1 << 20,
	}, catalog)
	cleanupPreparedDiscoveryService(t, svc)
	svc.account = ideOwner{id: "1001", name: "alice"}
	signals, _ := svc.scanSignals(context.Background(), "scan-1", &aiDiscoveryScanObservation{}, true, nil)
	var codex, claude *AISignal
	for i := range signals {
		sig := &signals[i]
		for _, ev := range sig.Evidence {
			if ev.RawPath != "" {
				t.Fatalf("signal %s kept raw path %q with raw paths off", sig.SignatureID, ev.RawPath)
			}
		}
		if sig.Detector != "config" {
			continue
		}
		switch sig.SupportedConnector {
		case "codex":
			codex = sig
		case "claudecode":
			claude = sig
		}
	}
	if codex == nil || claude == nil {
		t.Fatalf("config signals codex=%v claude=%v, want both", codex != nil, claude != nil)
	}
	if codex.UserID != svc.account.id || codex.UserName != svc.account.name {
		t.Fatalf("own-home codex finding owner = %q/%q, want %q/%q", codex.UserID, codex.UserName, svc.account.id, svc.account.name)
	}
	if claude.UserID != "" {
		t.Fatalf("extra-folder claude finding owner = %q, want none", claude.UserID)
	}
}
