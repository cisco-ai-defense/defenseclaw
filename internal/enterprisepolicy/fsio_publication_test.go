// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadPolicyFileRetriesRepeatedPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte("initial"), 0o600); err != nil {
		t.Fatal(err)
	}
	const replacements = 3
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
}

func TestReadPolicyFileReadsStablePublishedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, exists, err := readPolicyFileWith(Options{GOOS: "windows"}, path, func(Options, string) error { return nil })
	if err != nil || !exists || string(data) != "published" {
		t.Fatalf("data=%q exists=%v err=%v", data, exists, err)
	}
}

func TestReadPolicyFileKeepsTrustRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, exists, err := readPolicyFileWith(Options{GOOS: "windows"}, path, func(Options, string) error { return os.ErrNotExist })
	var untrusted *untrustedPolicyFileError
	if exists || !errors.As(err, &untrusted) {
		t.Fatalf("exists=%v err=%v; want a trust refusal", exists, err)
	}
}

func TestReadPolicyFileKeepsUnixIdentityRefusal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Unix reader retains its original single-read behavior")
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	stage := filepath.Join(filepath.Dir(path), "next-policy")
	if err := os.WriteFile(path, []byte("initial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, exists, err := readPolicyFileWith(Options{GOOS: "linux"}, path, func(Options, string) error {
		return os.Rename(stage, path)
	})
	if exists || err == nil || !strings.Contains(err.Error(), "changed while it was opened") {
		t.Fatalf("exists=%v err=%v; want the original identity refusal", exists, err)
	}
}
