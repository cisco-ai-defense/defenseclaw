// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// The unmanaged startup contract includes the installed Windows hook binary.
// Its digest must have the same value as the former whole-file computation
// without allocating a slice proportional to the binary's size.
func TestGAP0332HookScriptDigestStreamsLargeArtifact(t *testing.T) {
	const artifactSize = 32 << 20
	path := filepath.Join(t.TempDir(), "artifact.bin")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(artifactSize); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	want := "sha256:" + hex.EncodeToString(sum[:])
	data = nil
	conn := &memoArtifactConnector{
		stubConnector: stubConnector{name: "testartifact"},
		artifacts:     []string{path},
	}
	opts := SetupOpts{DataDir: t.TempDir()}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got := HookScriptDigests(opts, conn)
	runtime.ReadMemStats(&after)
	if got[filepath.Base(path)] != want {
		t.Fatalf("digest = %q, want %q", got[filepath.Base(path)], want)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("digest allocated %d bytes for a %d-byte artifact", allocated, artifactSize)
	if allocated > 4<<20 {
		t.Fatalf("digest allocated %d bytes for a %d-byte artifact", allocated, artifactSize)
	}
}

func TestGAP0332HookScriptDigestSmallArtifactTwin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.bin")
	modified := time.Unix(1_700_000_000, 0)
	conn := &memoArtifactConnector{
		stubConnector: stubConnector{name: "testartifact"},
		artifacts:     []string{path},
	}
	opts := SetupOpts{DataDir: t.TempDir()}
	for _, content := range []string{"first version", "later version"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(content))
		want := "sha256:" + hex.EncodeToString(sum[:])
		if got := HookScriptDigests(opts, conn)[filepath.Base(path)]; got != want {
			t.Fatalf("digest = %q, want %q", got, want)
		}
	}
}
