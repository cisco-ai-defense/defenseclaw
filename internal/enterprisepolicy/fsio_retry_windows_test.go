//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestReadPolicyFileRetriesWholeValidatedRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte("initial"), 0o600); err != nil {
		t.Fatal(err)
	}
	const replacements = 8
	changed := 0
	validate := func(Options, string) error {
		if changed == replacements {
			return nil
		}
		changed++
		stage := filepath.Join(filepath.Dir(path), "next-policy")
		if err := os.WriteFile(stage, []byte("published"), 0o600); err != nil {
			return err
		}
		return os.Rename(stage, path)
	}
	data, exists, err := readPolicyFileWith(Options{GOOS: "windows"}, path, validate)
	if err != nil || !exists || string(data) != "published" || changed != replacements {
		t.Fatalf("data=%q exists=%v changes=%d err=%v", data, exists, changed, err)
	}
	// The stable file must still read normally.
	data, exists, err = readPolicyFileWith(Options{GOOS: "windows"}, path, func(Options, string) error { return nil })
	if err != nil || !exists || string(data) != "published" {
		t.Fatalf("stable data=%q exists=%v err=%v", data, exists, err)
	}
}

func TestReadPolicyFileRetriesFirstMissingName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	created := false
	var publishErr error
	t.Cleanup(safefile.SetTransientRetrySleepForTest(func(time.Duration) {
		if !created {
			created = true
			publishErr = os.WriteFile(path, []byte("published"), 0o600)
		}
	}))
	data, exists, err := readPolicyFileWith(Options{GOOS: "windows", SkipTrustChecks: true}, path, nil)
	if publishErr != nil || err != nil || !exists || string(data) != "published" {
		t.Fatalf("data=%q exists=%v created=%v publication=%v err=%v", data, exists, created, publishErr, err)
	}
}

func TestOpenNoFollowRetriesIdentityChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	stage := filepath.Join(filepath.Dir(path), "next-policy")
	if err := os.WriteFile(path, []byte("initial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed := false
	var publishErr error
	restore := pathidentity.SetPinnedStatHookForTest(func(checked string) {
		if checked == path && !changed {
			changed = true
			publishErr = os.Rename(stage, path)
		}
	})
	t.Cleanup(restore)
	file, err := openNoFollow(path)
	if publishErr != nil || err != nil || !changed {
		t.Fatalf("changed=%v publication=%v open=%v", changed, publishErr, err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil || string(data) != "published" {
		t.Fatalf("data=%q err=%v", data, err)
	}
}

func TestOpenNoFollowRetriesFirstWindowsNameLookup(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		name := "present"
		if delayed {
			name = "appears during read"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			var created bool
			var writeErr error
			if delayed {
				t.Cleanup(safefile.SetTransientRetrySleepForTest(func(time.Duration) {
					if !created {
						created = true
						writeErr = os.WriteFile(path, []byte("policy"), 0o600)
					}
				}))
			} else if err := os.WriteFile(path, []byte("policy"), 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := openNoFollow(path)
			if delayed && (!created || writeErr != nil) {
				t.Fatalf("retry did not publish the fixture: created = %v, err = %v", created, writeErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			data, err := io.ReadAll(file)
			if err != nil || string(data) != "policy" {
				t.Fatalf("body = %q, err = %v", data, err)
			}
		})
	}
}
