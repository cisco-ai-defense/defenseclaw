// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hermespath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func useAccountTestRegistry(t *testing.T) (profiles, hives, machine string) {
	t.Helper()
	base := fmt.Sprintf(`Software\DefenseClawTest-hermes-account-%d-%d`, os.Getpid(), time.Now().UnixNano())
	profiles, hives, machine = base+`\profiles`, base+`\hives`, base+`\machine`
	previousProfiles, previousHives, previousMachine := accountProfileList, accountUserHives, accountMachineEnvironment
	accountProfileList = accountRegistryPath{root: registry.CURRENT_USER, path: profiles}
	accountUserHives = accountRegistryPath{root: registry.CURRENT_USER, path: hives}
	accountMachineEnvironment = accountRegistryPath{root: registry.CURRENT_USER, path: machine}
	t.Cleanup(func() {
		accountProfileList, accountUserHives, accountMachineEnvironment = previousProfiles, previousHives, previousMachine
		if err := deleteAccountTestTree(base); err != nil {
			t.Errorf("remove the scratch registry tree HKCU\\%s: %v", base, err)
		}
	})
	return profiles, hives, machine
}

func deleteAccountTestTree(path string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, path, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := key.ReadSubKeyNames(0)
	key.Close()
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := deleteAccountTestTree(path + `\` + name); err != nil {
			return err
		}
	}
	return registry.DeleteKey(registry.CURRENT_USER, path)
}

func writeAccountTestKey(t *testing.T, path string, values ...accountEnvValue) {
	t.Helper()
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	for _, value := range values {
		set := key.SetStringValue
		if value.expand {
			set = key.SetExpandStringValue
		}
		if err := set(value.name, value.value); err != nil {
			t.Fatal(err)
		}
	}
}

// GAP-0499: the managed guardian, running as LocalSystem, resolves the
// Hermes home from the account's loaded hive; a signed-out account, or a
// home no profile names, cannot be resolved and is never given the default.
func TestConfigPathForAccountReadsTheAccountHive(t *testing.T) {
	profiles, hives, machine := useAccountTestRegistry(t)
	const sid = "S-1-5-21-1-2-3-1001"
	const signedOut = "S-1-5-21-1-2-3-1002"
	alice := filepath.Join(t.TempDir(), "alice")
	bob := filepath.Join(t.TempDir(), "bob")
	writeAccountTestKey(t, profiles+`\`+sid, accountEnvValue{name: "ProfileImagePath", value: alice})
	writeAccountTestKey(t, profiles+`\`+signedOut, accountEnvValue{name: "ProfileImagePath", value: bob})
	writeAccountTestKey(t, machine, accountEnvValue{name: "HERMES_HOME", value: `C:\machine\hermes`})
	writeAccountTestKey(t, hives+`\`+sid+`\Environment`, accountEnvValue{name: "HERMES_HOME", value: `%USERPROFILE%\hermes-work`, expand: true})

	got, err := ConfigPathForAccount(alice)
	if want := filepath.Join(alice, "hermes-work", "config.yaml"); err != nil || got != want {
		t.Fatalf("ConfigPathForAccount(alice) = %q, %v; want %q", got, err, want)
	}
	if got, err := ConfigPathForAccount(bob); !errors.Is(err, ErrAccountEnvironmentUnavailable) || !errors.Is(err, ErrAccountSignedOut) ||
		!strings.Contains(err.Error(), "is not loaded while it is signed out") {
		t.Fatalf("a signed-out account = %q, %v; want ErrAccountEnvironmentUnavailable and ErrAccountSignedOut, never the default", got, err)
	}
	if got, err := ConfigPathForAccount(filepath.Join(t.TempDir(), "nobody")); !errors.Is(err, ErrAccountEnvironmentUnavailable) || errors.Is(err, ErrAccountSignedOut) {
		t.Fatalf("a home no profile names = %q, %v; want ErrAccountEnvironmentUnavailable without ErrAccountSignedOut", got, err)
	}

	// Without the account's own variable the machine's applies.
	if err := registry.DeleteKey(registry.CURRENT_USER, hives+`\`+sid+`\Environment`); err != nil {
		t.Fatal(err)
	}
	if got, err := ConfigPathForAccount(alice); err != nil || got != `C:\machine\hermes\config.yaml` {
		t.Fatalf("ConfigPathForAccount(alice) without a user variable = %q, %v; want the machine HERMES_HOME", got, err)
	}
}
