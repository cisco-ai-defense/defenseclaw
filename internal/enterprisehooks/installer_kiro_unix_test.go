//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func kiroStandaloneInstallOptions(home, version string) InstallOptions {
	return InstallOptions{
		ConnectorName: "kiro",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      "test-token",
		OTLPPathToken: strings.Repeat("d", 64),
		GuardrailMode: "action",
		HookFailMode:  "closed",
		AgentVersion:  version,
		Registry:      connector.NewDefaultRegistry(),
		// Protected before: repair may rewrite the existing hook config.
		AllowMissingHookConfigRepair: true,
	}
}

// Kiro's hook contract is not version-gated, so it never resolves to a known
// contract. The standalone guardian only followed an agent upgrade to a
// known contract, so every kiro-cli self-update left the user's row refusing
// its repair with "hook contract drift detected". It now follows an upgrade
// at or above the certified minimum and refuses anything below it.
func TestStandaloneKiroFollowsCLIUpgradesAtOrAboveTheFloor(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)

	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.24.1")); err != nil {
		t.Fatalf("first install at the certified version: %v", err)
	}
	hooks := filepath.Join(home, ".kiro", "hooks", "defenseclaw.json")
	if _, err := os.Stat(hooks); err != nil {
		t.Fatalf("global Kiro hook file missing: %v", err)
	}

	upgraded, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.25.0"))
	if err != nil {
		t.Fatalf("repair after a kiro-cli self-update: %v", err)
	}
	if upgraded.AgentVersion != "kiro-cli 2.25.0" {
		t.Fatalf("repair recorded %q, want the new version", upgraded.AgentVersion)
	}
	if _, err := Verify(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.25.0")); err != nil {
		t.Fatalf("verify after the repair: %v", err)
	}

	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.20.0")); err == nil ||
		!strings.Contains(err.Error(), "below the certified minimum 2.24.1") {
		t.Fatalf("install below the floor = %v, want the certified-minimum refusal", err)
	}
}

// Outside the standalone profile nothing changes: the floor does not apply
// and a version change is still refused as drift.
func TestKiroFloorIsStandaloneOnly(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	setStandaloneProfileForTest(t, false)
	home := newTestHome(t)
	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.20.0")); err != nil {
		t.Fatalf("install below the standalone floor outside the standalone profile: %v", err)
	}
	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.25.0")); err == nil ||
		!strings.Contains(err.Error(), "hook contract drift detected") {
		t.Fatalf("version change outside the standalone profile = %v, want the drift refusal", err)
	}
}

// The enumerator's decision and the guardian's install must agree for a row
// enrolled below the floor whose user moves to another version below it.
// The row used to follow the new version, and Install then refused it as
// hook contract drift on every cycle, so the user's hooks were no longer
// repaired and nothing was reported. The row now stays at its enrolled
// version, which Install keeps repairing, and the installed version is
// reported as unprotected.
func TestEnumerateUnixKeepsABelowFloorKiroRowThatInstallCanRepair(t *testing.T) {
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	const enrolled, installed = "2.22.0", "2.23.0"
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	alice := makeHome(t, homes, "alice")

	// An earlier release, which had no floor, enrolled and installed alice.
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "1")
	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(alice, enrolled)); err != nil {
		t.Fatalf("earlier install: %v", err)
	}
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")

	info, err := os.Stat(alice)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	manifestPath := filepath.Join(root, "targets.yaml")
	data, err := MarshalUnixTargetsManifest(Manifest{Version: 1, Targets: []ManifestTarget{{
		User: "alice", UserHome: alice, UID: intPointer(uid), GID: intPointer(gid), Connector: "kiro",
		DataDir: filepath.Join(alice, ".defenseclaw"), AgentVersion: enrolled, Enabled: &enabled, HomeInode: statInode(t, info),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := UnixEnumerateOptions{
		ExistingManifestPath: manifestPath,
		Resolver: &fakeResolver{
			accounts: map[string]unixidentity.Account{"alice": {Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}},
			listed:   []string{"alice"},
		},
		HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
		State: &UnixEnumeratorState{Version: 1},
		Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			return map[string]string{"kiro": installed}, nil, nil
		},
	}
	manifest, report, err := EnumerateUnix(context.Background(), enumeratorConfig("kiro"), connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].AgentVersion != enrolled {
		t.Fatalf("rows = %+v, want alice's kiro row kept at %s", manifest.Targets, enrolled)
	}
	if len(report.Unprotected) != 1 || report.Unprotected[0].Connector != "kiro" || report.Unprotected[0].Version != installed ||
		!strings.Contains(report.Unprotected[0].Reason, "below the certified minimum 2.24.1") ||
		!strings.Contains(report.Unprotected[0].Reason, "the row stays enrolled at "+enrolled) {
		t.Fatalf("unprotected = %+v, want the installed version reported", report.Unprotected)
	}

	// The guardian installs the row the enumerator wrote.
	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(alice, manifest.Targets[0].AgentVersion)); err != nil {
		t.Fatalf("install of the enumerated row: %v", err)
	}
	if _, err := Verify(context.Background(), kiroStandaloneInstallOptions(alice, manifest.Targets[0].AgentVersion)); err != nil {
		t.Fatalf("verify of the enumerated row: %v", err)
	}

	// A known Kiro row does not follow its user to a version below the floor;
	// the enumerator keeps it at its last enrolled version and reports the
	// installed one. That holds for a row an earlier release enrolled below the
	// floor too: the guardian keeps repairing it at its own version, and Install
	// refuses a change to another version below the floor as drift.
	t.Run("known row version", func(t *testing.T) {
		if refused := unixKnownRowVersionRefused("kiro", "kiro-cli 2.24.1", "kiro-cli 2.25.0"); refused != "" {
			t.Fatalf("upgrade refused: %s", refused)
		}
		if refused := unixKnownRowVersionRefused("kiro", "kiro-cli 2.24.1", "kiro-cli 2.20.0"); !strings.Contains(refused, "below the certified minimum 2.24.1") {
			t.Fatalf("downgrade below the floor = %q, want the certified-minimum reason", refused)
		}
		if refused := unixKnownRowVersionRefused("kiro", "kiro-cli 2.19.0", "kiro-cli 2.20.0"); !strings.Contains(refused, "below the certified minimum 2.24.1") {
			t.Fatalf("a change between two versions below the floor = %q, want the certified-minimum reason", refused)
		}
		if refused := unixKnownRowVersionRefused("kiro", "kiro-cli 2.19.0", "kiro-cli 2.24.1"); refused != "" {
			t.Fatalf("an upgrade from below the floor to the floor refused: %s", refused)
		}
	})

	// A Kiro user enrolled by an earlier release below the certified minimum
	// (there was no floor then) keeps a hook contract lock. The floor gates new
	// enrollments only: the guardian keeps repairing that user's hooks at the
	// same version instead of refusing the row, which would make the gateway
	// refuse the user's hook calls. A version change below the floor is still
	// refused as drift, and an upgrade to the floor is followed.
	t.Run("repair at the enrolled version", func(t *testing.T) {
		skipIfRoot(t)
		t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
		setStandaloneProfileForTest(t, true)
		home := newTestHome(t)

		// The earlier release's install: no floor applied, so it wrote a lock.
		earlier := kiroStandaloneInstallOptions(home, "kiro-cli 2.22.0")
		t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "1")
		if _, err := Install(context.Background(), earlier); err != nil {
			t.Fatalf("earlier install: %v", err)
		}
		t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")

		if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.22.0")); err != nil {
			t.Fatalf("repair of a row enrolled below the floor: %v", err)
		}
		if _, err := Verify(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.22.0")); err != nil {
			t.Fatalf("verify of a row enrolled below the floor: %v", err)
		}
		if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.23.0")); err == nil ||
			!strings.Contains(err.Error(), "hook contract drift detected") {
			t.Fatalf("a version change below the floor = %v, want the drift refusal", err)
		}
		if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.24.1")); err != nil {
			t.Fatalf("upgrade to the floor: %v", err)
		}

		// A new enrollment below the floor is still refused.
		fresh := newTestHome(t)
		if _, err := Install(context.Background(), kiroStandaloneInstallOptions(fresh, "kiro-cli 2.22.0")); err == nil ||
			!strings.Contains(err.Error(), "below the certified minimum 2.24.1") {
			t.Fatalf("new enrollment below the floor = %v, want the certified-minimum refusal", err)
		}
	})
}

// Kiro reads ~/.kiro/hooks but does not create it, and a first install
// refused every account that had not created that folder itself ("hook
// config parent missing: ~/.kiro"), so with kiro-cli installed machine-wide
// every account was a failed target. The standalone install now creates the
// missing folders as the user, owner-only, and writes its own hook file
// there. A link or a file in their place is still refused, and the Secure
// Client profile is unchanged.
func TestStandaloneKiroFirstInstallCreatesItsHookFolders(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	setStandaloneProfileForTest(t, true)
	firstInstall := func(home string) InstallOptions {
		opts := kiroStandaloneInstallOptions(home, "kiro-cli 2.24.1")
		opts.AllowMissingHookConfigRepair = false
		return opts
	}

	for name, prepare := range map[string]func(home string){
		"no ~/.kiro":       func(string) {},
		"no ~/.kiro/hooks": func(home string) { mustMkdir(t, filepath.Join(home, ".kiro"), 0o700) },
	} {
		home := newTestHome(t)
		prepare(home)
		if _, err := Install(context.Background(), firstInstall(home)); err != nil {
			t.Fatalf("%s: first install: %v", name, err)
		}
		requirePerm(t, filepath.Join(home, ".kiro"), 0o700)
		requirePerm(t, filepath.Join(home, ".kiro", "hooks"), 0o700)
		hookFile := filepath.Join(home, ".kiro", "hooks", "defenseclaw.json")
		if _, err := os.Lstat(hookFile); err != nil {
			t.Fatalf("%s: Kiro hook file: %v", name, err)
		}
		if _, err := Verify(context.Background(), firstInstall(home)); err != nil {
			t.Fatalf("%s: verify after the first install: %v", name, err)
		}
		if err := RemoveUserHooks(context.Background(), firstInstall(home)); err != nil {
			t.Fatalf("%s: remove: %v", name, err)
		}
		if _, err := os.Lstat(hookFile); !os.IsNotExist(err) {
			t.Fatalf("%s: removal left the Kiro hook file: %v", name, err)
		}
	}

	// A link in place of ~/.kiro is refused and nothing is created behind it.
	home := newTestHome(t)
	elsewhere := filepath.Join(home, "elsewhere")
	mustMkdir(t, elsewhere, 0o700)
	if err := os.Symlink(elsewhere, filepath.Join(home, ".kiro")); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), firstInstall(home)); err == nil || !strings.Contains(err.Error(), "refusing symlink") {
		t.Fatalf("install through a linked ~/.kiro = %v, want the symlink refusal", err)
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, "hooks")); !os.IsNotExist(err) {
		t.Fatalf("install created a folder behind the link: %v", err)
	}
	// A file in place of ~/.kiro/hooks is refused.
	home = newTestHome(t)
	mustMkdir(t, filepath.Join(home, ".kiro"), 0o700)
	if err := os.WriteFile(filepath.Join(home, ".kiro", "hooks"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), firstInstall(home)); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("install with a file at ~/.kiro/hooks = %v, want the not-a-directory refusal", err)
	}

	// Outside the standalone profile a first install still needs the folder.
	setStandaloneProfileForTest(t, false)
	home = newTestHome(t)
	if _, err := Install(context.Background(), firstInstall(home)); err == nil || !strings.Contains(err.Error(), "parent missing") {
		t.Fatalf("Secure Client first install = %v, want the parent-missing refusal", err)
	}
	if _, err := os.Lstat(filepath.Join(home, ".kiro")); !os.IsNotExist(err) {
		t.Fatalf("Secure Client install created ~/.kiro: %v", err)
	}

	// An install the hook contract refuses (a new Kiro enrollment below the
	// certified floor) leaves the home as it was: the missing ~/.kiro folders
	// are created only once the install can go ahead.
	t.Run("refused install", func(t *testing.T) {
		skipIfRoot(t)
		t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
		setStandaloneProfileForTest(t, true)
		home := newTestHome(t)
		opts := kiroStandaloneInstallOptions(home, "kiro-cli 2.22.0")
		opts.AllowMissingHookConfigRepair = false
		if _, err := Install(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "below the certified minimum") {
			t.Fatalf("install below the floor = %v, want the certified-minimum refusal", err)
		}
		if _, err := os.Lstat(filepath.Join(home, ".kiro")); !os.IsNotExist(err) {
			t.Fatalf("a refused install created ~/.kiro (err=%v)", err)
		}
	})
}

func mustMkdir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(dir, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
}
