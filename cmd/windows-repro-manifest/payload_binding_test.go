// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/setuppayload"
)

func TestPayloadBindingHashesThePayloadDirectory(t *testing.T) {
	dir := t.TempDir()
	want := map[string]string{}
	for name, body := range map[string]string{"defenseclaw.exe": "cli", "install-enterprise.ps1": "script", "policy_compiler.py": "compiler"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(body))
		want[name] = hex.EncodeToString(digest[:])
	}
	commit := strings.Repeat("ab", 20)
	identity := []string{"--distribution-flavor", "standalone-unsigned", "--version", "1.0.3", "--source-commit", commit}
	var out bytes.Buffer
	if err := runPayloadBinding(append([]string{"--payload-dir", dir}, identity...), &out); err != nil {
		t.Fatal(err)
	}
	expected := setuppayload.PayloadBinding(setuppayload.PayloadIdentity{
		DistributionFlavor: "standalone-unsigned", Version: "1.0.3", SourceCommit: commit,
	}, want)
	if got := strings.TrimSpace(out.String()); got != expected {
		t.Fatalf("payload-binding printed %q", got)
	}
	for _, args := range [][]string{
		identity,
		{"--payload-dir", dir, "--version", "1.0.3", "--source-commit", commit},
		{"--payload-dir", dir, "--distribution-flavor", "standalone", "--source-commit", commit},
		{"--payload-dir", dir, "--distribution-flavor", "standalone", "--version", "1.0.3"},
		{"--payload-dir", dir, "--distribution-flavor", "standalone", "--version", "1.0.3", "--source-commit", "HEAD"},
		append([]string{"--payload-dir", t.TempDir()}, identity...),
		append(append([]string{"--payload-dir", dir}, identity...), "extra"),
	} {
		if err := runPayloadBinding(args, &bytes.Buffer{}); err == nil {
			t.Errorf("payload-binding %v succeeded", args)
		}
	}
}
