// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0856. The guardian recreates a missing Codex machine-policy folder, and
// the vendor parent above it, through the install-time creator; a link on the
// path is named once and nothing is created; an unconfigured connector is not
// this function concern (the caller gates it), and Secure Client is unchanged.

type codexFolderEvents struct {
	sync.Mutex
	boundary []map[string]string
	repair   []map[string]string
}

func captureCodexFolderEvents(t *testing.T) *codexFolderEvents {
	t.Helper()
	events := &codexFolderEvents{}
	previous := managed.ReportResilienceEvent
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		events.Lock()
		defer events.Unlock()
		switch marker {
		case managed.MarkerBoundary:
			events.boundary = append(events.boundary, fields)
		case managed.MarkerRepair:
			events.repair = append(events.repair, fields)
		}
	}
	t.Cleanup(func() { managed.ReportResilienceEvent = previous })
	return events
}

func TestEnsureWindowsStandaloneCodexMachineFolderRecreatesAMissingVendorParent(t *testing.T) {
	for _, name := range []string{"vendor parent and folder missing", "folder missing, vendor parent there"} {
		t.Run(name, func(t *testing.T) {
			f := useKeptFixture(t, true, nil)
			events := captureCodexFolderEvents(t)
			parent := filepath.Dir(f.selectorDir)
			if err := os.MkdirAll(filepath.Dir(parent), 0o700); err != nil {
				t.Fatal(err)
			}
			want := []string{parent, f.selectorDir}
			if name == "folder missing, vendor parent there" {
				if err := ensureWindowsManagedPolicyDirectory(parent); err != nil {
					t.Fatal(err)
				}
				want = []string{f.selectorDir}
				*f.recorded = nil
			}
			result, err := EnsureWindowsStandaloneCodexMachineFolder()
			if err != nil {
				t.Fatalf("the missing folder was not recreated: %v", err)
			}
			if !slices.Equal(result.Created, want) {
				t.Fatalf("created = %q, want %q", result.Created, want)
			}
			for _, folder := range want {
				if err := validateWindowsManagedPolicyDirectoryProtection(folder); err != nil {
					t.Fatalf("%s was not created with the protection of the install-time creator: %v", folder, err)
				}
			}
			if len(*f.recorded) != 1 || !slices.Equal((*f.recorded)[0], want) {
				t.Fatalf("created folders recorded = %q, want one record of %q", *f.recorded, want)
			}
			if len(events.repair) != 1 {
				t.Fatalf("repair events = %d, want one", len(events.repair))
			}
			// A second pass finds the folder and does nothing.
			result, err = EnsureWindowsStandaloneCodexMachineFolder()
			if err != nil || len(result.Created) != 0 {
				t.Fatalf("second ensure created %q err=%v, want nothing", result.Created, err)
			}
			if len(*f.recorded) != 1 || len(events.repair) != 1 {
				t.Fatalf("second ensure recorded or reported again: %q %d", *f.recorded, len(events.repair))
			}
		})
	}
}

func TestEnsureWindowsStandaloneCodexMachineFolderKeepsAndNamesALink(t *testing.T) {
	for _, shape := range []string{"link at the vendor parent", "link at the folder", "file at the folder"} {
		t.Run(shape, func(t *testing.T) {
			f := useKeptFixture(t, true, func(fixture keptFixture) []string {
				switch shape {
				case "link at the folder":
					return []string{fixture.selectorDir}
				case "link at the vendor parent":
					return []string{filepath.Dir(fixture.selectorDir)}
				}
				return nil
			})
			events := captureCodexFolderEvents(t)
			parent := filepath.Dir(f.selectorDir)
			link := parent
			if shape != "link at the vendor parent" {
				link = f.selectorDir
			}
			if shape == "file at the folder" {
				if err := os.MkdirAll(parent, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.selectorDir, []byte("not a folder"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for pass := 0; pass < 3; pass++ {
				result, err := EnsureWindowsStandaloneCodexMachineFolder()
				if err == nil || !errors.Is(err, ErrWindowsCodexMachineFolderUnavailable) {
					t.Fatalf("pass %d: a link on the path was not refused: %v", pass, err)
				}
				if len(result.Created) != 0 {
					t.Fatalf("pass %d: created %q behind a link", pass, result.Created)
				}
				if !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), "rmdir") {
					t.Fatalf("pass %d: the error does not name the link and the fix: %v", pass, err)
				}
			}
			if len(*f.recorded) != 0 {
				t.Fatalf("a folder was recorded as created behind a link: %q", *f.recorded)
			}
			if shape != "file at the folder" {
				if _, err := os.Lstat(f.selectorDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("the folder exists after a refused ensure: %v", err)
				}
			}
			if len(events.boundary) != 1 {
				t.Fatalf("the link was named %d times in three passes, want once", len(events.boundary))
			}
			if events.boundary[0]["fix"] == "" || len(events.repair) != 0 {
				t.Fatalf("warning without a fix, or a repair reported: %v %d", events.boundary[0], len(events.repair))
			}
		})
	}
}

func TestEnsureWindowsStandaloneCodexMachineFolderNamesAFailedCreation(t *testing.T) {
	f := useKeptFixture(t, true, nil)
	events := captureCodexFolderEvents(t)
	previous := windowsCodexMachineFolderCreator
	windowsCodexMachineFolderCreator = func(string) error { return errors.New("access is denied") }
	t.Cleanup(func() { windowsCodexMachineFolderCreator = previous })
	for pass := 0; pass < 2; pass++ {
		_, err := EnsureWindowsStandaloneCodexMachineFolder()
		if err == nil || !errors.Is(err, ErrWindowsCodexMachineFolderUnavailable) ||
			!strings.Contains(err.Error(), "access is denied") || !strings.Contains(err.Error(), "Setup /repair") {
			t.Fatalf("pass %d: the failure is not named with its fix: %v", pass, err)
		}
	}
	if len(events.boundary) != 1 || len(*f.recorded) != 0 {
		t.Fatalf("warnings = %d recorded = %q, want one warning and no record", len(events.boundary), *f.recorded)
	}
}

func TestEnsureWindowsStandaloneCodexMachineFolderIsStandaloneOnly(t *testing.T) {
	f := useKeptFixture(t, false, nil)
	result, err := EnsureWindowsStandaloneCodexMachineFolder()
	if err != nil || len(result.Created) != 0 || result.Folder != "" {
		t.Fatalf("Secure Client: result %+v err %v, want nothing", result, err)
	}
	if _, statErr := os.Lstat(f.selectorDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Secure Client created the Codex folder: %v", statErr)
	}
	if len(*f.recorded) != 0 {
		t.Fatalf("Secure Client recorded a created folder: %q", *f.recorded)
	}
}
