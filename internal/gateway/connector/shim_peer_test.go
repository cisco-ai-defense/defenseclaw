// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPerUserShimsKeepTokenAndArgumentsOffAnUnverifiedGateway(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required by the shim templates")
	}
	var received atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			received.Add(1)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer peer.Close()
	shimDir := t.TempDir()
	if err := WriteShimScriptsWithToken(shimDir, strings.TrimPrefix(peer.URL, "http://"), "private-shim-token"); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(home, "native-called")
	stub := "#!/bin/sh\nprintf '%s' x > \"$DC_NATIVE_MARKER\"\ncat >/dev/null\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, "defenseclaw-gateway"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range shimBinaries {
		t.Run(name, func(t *testing.T) {
			before := received.Load()
			_ = os.Remove(marker)
			cmd := exec.Command(systemBashForTest(t), filepath.Join(shimDir, name), "--version", "private-tool-arguments")
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "PATH="+shimDir+":/usr/local/bin:/usr/bin:/bin", "DC_NATIVE_MARKER="+marker)
			_, runErr := cmd.CombinedOutput()
			if runErr == nil {
				t.Fatal("unverified gateway let the shim start its real tool")
			}
			if received.Load() != before {
				t.Fatal("unverified gateway received the shim bearer")
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("shim skipped the native connected-peer post: %v", err)
			}
		})
	}
}

func TestPerUserShimsRejectSymlinkedNativeHelperPath(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required by the shim templates")
	}
	var received atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer peer.Close()
	shimDir := t.TempDir()
	if err := WriteShimScriptsWithToken(shimDir, strings.TrimPrefix(peer.URL, "http://"), "private-shim-token"); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	outside := t.TempDir()
	binDir := filepath.Join(outside, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, ".local")); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(home, "native-called")
	stub := "#!/bin/sh\nprintf '%s' x > \"$DC_NATIVE_MARKER\"\ncat >/dev/null\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, "defenseclaw-gateway"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range shimBinaries {
		t.Run(name, func(t *testing.T) {
			before := received.Load()
			cmd := exec.Command(systemBashForTest(t), filepath.Join(shimDir, name), "--version", "private-tool-arguments")
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "PATH="+shimDir+":/usr/local/bin:/usr/bin:/bin", "DC_NATIVE_MARKER="+marker)
			_, runErr := cmd.CombinedOutput()
			if runErr == nil || received.Load() != before {
				t.Fatalf("shim ran the tool or sent %d requests through an untrusted helper path: %v", received.Load()-before, runErr)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("shim invoked a native helper through a symlinked path")
			}
		})
	}
}
