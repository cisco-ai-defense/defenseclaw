//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// leftoverUserStateProfiles makes three account homes: one that keeps its
// %USERPROFILE%\.defenseclaw folder, one without it, and one where the name
// is a plain file.
func leftoverUserStateProfiles(t *testing.T) (kept string) {
	t.Helper()
	root := t.TempDir()
	keptHome := filepath.Join(root, "dcw-std2")
	cleanHome := filepath.Join(root, "dcw-std1")
	fileHome := filepath.Join(root, "dcw-std3")
	for _, home := range []string{keptHome, cleanHome, fileHome} {
		if err := os.MkdirAll(home, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	kept = filepath.Join(keptHome, ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(kept, "connector_backups"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileHome, ".defenseclaw"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalHomes := windowsEnterpriseProfileHomes
	originalName := windowsPrincipalName
	t.Cleanup(func() {
		windowsEnterpriseProfileHomes = originalHomes
		windowsPrincipalName = originalName
	})
	windowsEnterpriseProfileHomes = func() []windowsEnterpriseProfileHome {
		return []windowsEnterpriseProfileHome{
			{SID: "S-1-5-21-1-2-3-1017", Home: cleanHome},
			{SID: "S-1-5-21-1-2-3-1018", Home: keptHome},
			{SID: "S-1-5-21-1-2-3-1019", Home: fileHome},
		}
	}
	windowsPrincipalName = func(sid string) string {
		if sid == "S-1-5-21-1-2-3-1018" {
			return `DCLAB\dcw-std2`
		}
		return ""
	}
	return kept
}

// A PURGE=1 that finds no deployment (a killed purge whose machine purge
// Setup's recovery finished) named nothing and returned a silent noop while
// a signed-out account's %USERPROFILE%\.defenseclaw stayed (GAP-2094).
func TestWindowsEnterpriseStandalonePurgeWithNothingInstalledNamesLeftoverUserState(t *testing.T) {
	kept := leftoverUserStateProfiles(t)
	originalFootprint := windowsEnterpriseStandaloneFootprint
	originalRunner := windowsEnterpriseStandaloneRunner
	originalObserver := windowsEnterpriseStandaloneObserver
	t.Cleanup(func() {
		windowsEnterpriseStandaloneFootprint = originalFootprint
		windowsEnterpriseStandaloneRunner = originalRunner
		windowsEnterpriseStandaloneObserver = originalObserver
	})
	windowsEnterpriseStandaloneFootprint = func() (bool, error) { return false, nil }
	windowsEnterpriseStandaloneRunner = func(context.Context, *cobra.Command, string, []string) (windowsEnterpriseStandaloneRun, error) {
		return windowsEnterpriseStandaloneRun{}, errors.New("installer must not run on a clean host")
	}
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
	run := func(purge bool) enterprisestatus.Result {
		t.Helper()
		command := &cobra.Command{}
		var stdout bytes.Buffer
		command.SetOut(&stdout)
		opts := &windowsEnterpriseLifecycleOptions{resolvedProfile: "standalone", jsonOutput: true, purge: purge}
		if err := runWindowsEnterpriseStandaloneAction(context.Background(), command, "uninstall", opts, `C:\x\install-enterprise.ps1`, nil); err != nil {
			t.Fatal(err)
		}
		var result enterprisestatus.Result
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if !result.OK || !result.Noop || result.NoopReason != "not_installed" || result.ExitCode != 0 || len(result.Errors) != 0 {
			t.Fatalf("purge=%v result %+v", purge, result)
		}
		return result
	}

	purged := run(true)
	if len(purged.Warnings) != 1 || purged.Warnings[0].Code != "per_user_state_remaining" {
		t.Fatalf("PURGE=1 with nothing installed did not name the leftover per-user folder: %+v", purged.Warnings)
	}
	message := purged.Warnings[0].Message
	for _, want := range []string{
		"1 account(s)",
		`DCLAB\dcw-std2 (S-1-5-21-1-2-3-1018): ` + kept,
		"/uninstall PURGE=1",
		"delete the folder as an administrator",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("warning lacks %q: %s", want, message)
		}
	}
	for _, unwanted := range []string{"1017", "1019", "recovery finished"} {
		if strings.Contains(message, unwanted) {
			t.Fatalf("warning names %q: %s", unwanted, message)
		}
	}

	// A plain uninstall keeps the per-user folders by design: no warning.
	if plain := run(false); len(plain.Warnings) != 0 {
		t.Fatalf("plain uninstall with nothing installed warned: %+v", plain.Warnings)
	}
}

// The recovery that finishes a killed PURGE=1 names what stays, as the
// killed run would have (GAP-2094), and says it was the recovery.
func TestWindowsEnterpriseRecoveredPurgeNamesLeftoverUserState(t *testing.T) {
	kept := leftoverUserStateProfiles(t)
	result := enterprisestatus.New("recover", "standalone", "windows", "1.0.5")
	addWindowsEnterpriseLeftoverUserStateWarning(result, true)
	if len(result.Errors) != 0 || len(result.Warnings) != 1 || result.Warnings[0].Code != "per_user_state_remaining" {
		t.Fatalf("result %+v", result)
	}
	if message := result.Warnings[0].Message; !strings.Contains(message, "the recovery finished the interrupted /uninstall PURGE=1") ||
		!strings.Contains(message, kept) {
		t.Fatalf("warning %s", message)
	}

	// Nothing left: no warning.
	windowsEnterpriseProfileHomes = func() []windowsEnterpriseProfileHome { return nil }
	clean := enterprisestatus.New("recover", "standalone", "windows", "1.0.5")
	addWindowsEnterpriseLeftoverUserStateWarning(clean, true)
	if len(clean.Warnings) != 0 {
		t.Fatalf("warned with no leftover folder: %+v", clean.Warnings)
	}
}
