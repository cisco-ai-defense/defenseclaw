// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func TestUserPathAddRetriesConcurrentExternalEdit(t *testing.T) {
	key, keyPath := createUserPathTestKey(t)
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	original := `C:\WindowsApps`
	external := `C:\UserTools`
	if err := key.SetExpandStringValue("Path", original); err != nil {
		t.Fatal(err)
	}

	calls := 0
	mutation, err := mutateRegistryUserPath(
		registry.CURRENT_USER,
		keyPath,
		func(current userPathSnapshot) (userPathMutation, error) {
			calls++
			if calls == 1 {
				if err := key.SetExpandStringValue("Path", original+";"+external); err != nil {
					return userPathMutation{}, err
				}
			}
			return addUserPathMutation(commandDir)(current)
		},
	)
	if err != nil {
		t.Fatalf("add user PATH after concurrent edit: %v", err)
	}
	if calls < 2 {
		t.Fatalf("PATH mutation transform calls = %d, want a transactional retry", calls)
	}
	if !mutation.Changed || mutation.ValueCreated {
		t.Fatalf("PATH ownership = changed:%t value-created:%t", mutation.Changed, mutation.ValueCreated)
	}
	assertUserPathValue(t, key, commandDir+";"+original+";"+external, registry.EXPAND_SZ)
}

func TestUserPathRemovalRetriesConcurrentExternalEdit(t *testing.T) {
	key, keyPath := createUserPathTestKey(t)
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	original := `C:\WindowsApps`
	external := `C:\UserTools`
	if err := key.SetExpandStringValue("Path", commandDir+";"+original); err != nil {
		t.Fatal(err)
	}

	calls := 0
	_, err := mutateRegistryUserPath(
		registry.CURRENT_USER,
		keyPath,
		func(current userPathSnapshot) (userPathMutation, error) {
			calls++
			if calls == 1 {
				if err := key.SetExpandStringValue(
					"Path",
					commandDir+";"+original+";"+external,
				); err != nil {
					return userPathMutation{}, err
				}
			}
			return removeUserPathMutation(commandDir, false, false)(current)
		},
	)
	if err != nil {
		t.Fatalf("remove user PATH after concurrent edit: %v", err)
	}
	if calls < 2 {
		t.Fatalf("PATH mutation transform calls = %d, want a transactional retry", calls)
	}
	assertUserPathValue(t, key, original+";"+external, registry.EXPAND_SZ)
}

func TestUserPathMutationBoundsContinuousExternalChurn(t *testing.T) {
	key, keyPath := createUserPathTestKey(t)
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`
	if err := key.SetStringValue("Path", `C:\WindowsApps`); err != nil {
		t.Fatal(err)
	}

	calls := 0
	_, err := mutateRegistryUserPath(
		registry.CURRENT_USER,
		keyPath,
		func(current userPathSnapshot) (userPathMutation, error) {
			calls++
			if err := key.SetStringValue("Path", fmt.Sprintf(`C:\UserTools%d`, calls)); err != nil {
				return userPathMutation{}, err
			}
			return addUserPathMutation(commandDir)(current)
		},
	)
	if err == nil || !strings.Contains(err.Error(), "changed concurrently") {
		t.Fatalf("continuous PATH churn error = %v", err)
	}
	if calls != userPathMutationMaxAttempts {
		t.Fatalf("PATH mutation transform calls = %d, want %d", calls, userPathMutationMaxAttempts)
	}
	assertUserPathValue(t, key, fmt.Sprintf(`C:\UserTools%d`, calls), registry.SZ)
}

func TestUserPathTransactionRestoresMissingValue(t *testing.T) {
	key, keyPath := createUserPathTestKey(t)
	commandDir := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw\bin`

	mutation, err := mutateRegistryUserPath(
		registry.CURRENT_USER,
		keyPath,
		addUserPathMutation(commandDir),
	)
	if err != nil {
		t.Fatalf("add initially missing user PATH: %v", err)
	}
	if !mutation.Changed || !mutation.ValueCreated {
		t.Fatalf("PATH ownership = changed:%t value-created:%t", mutation.Changed, mutation.ValueCreated)
	}
	assertUserPathValue(t, key, commandDir, registry.SZ)

	if _, err := mutateRegistryUserPath(
		registry.CURRENT_USER,
		keyPath,
		removeUserPathMutation(commandDir, mutation.ReusedSeparator, mutation.ValueCreated),
	); err != nil {
		t.Fatalf("remove setup-created user PATH: %v", err)
	}
	if value, _, err := key.GetStringValue("Path"); err != registry.ErrNotExist {
		t.Fatalf("setup-created PATH still exists as %q: %v", value, err)
	}
}

func createUserPathTestKey(t *testing.T) (registry.Key, string) {
	t.Helper()
	keyPath := fmt.Sprintf(
		`Software\DefenseClawSetupTests\path-cas-%d-%d`,
		os.Getpid(),
		time.Now().UnixNano(),
	)
	key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = key.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, keyPath)
	})
	return key, keyPath
}

func assertUserPathValue(t *testing.T, key registry.Key, want string, wantType uint32) {
	t.Helper()
	got, gotType, err := key.GetStringValue("Path")
	if err != nil {
		t.Fatal(err)
	}
	if got != want || gotType != wantType {
		t.Fatalf("user PATH = %q type %d, want %q type %d", got, gotType, want, wantType)
	}
}
