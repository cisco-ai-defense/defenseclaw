// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var nativeGatewayForHookTests struct {
	sync.Once
	dir  string
	path string
	err  error
}

var nativeHookPostForHookTests struct {
	sync.Once
	dir  string
	path string
	err  error
}

func installNativeHookPostForHookTest(t *testing.T, home string) {
	t.Helper()
	nativeHookPostForHookTests.Do(func() {
		var err error
		nativeHookPostForHookTests.dir, err = os.MkdirTemp("", "defenseclaw-hook-post-test-")
		if err != nil {
			nativeHookPostForHookTests.err = err
			return
		}
		nativeHookPostForHookTests.path = filepath.Join(nativeHookPostForHookTests.dir, "defenseclaw-hook-post")
		cmd := exec.Command("go", "build", "-o", nativeHookPostForHookTests.path, "./cmd/defenseclaw-hook-post")
		cmd.Dir = filepath.Join("..", "..", "..")
		if output, buildErr := cmd.CombinedOutput(); buildErr != nil {
			nativeHookPostForHookTests.err = fmt.Errorf("build hook-post for test: %w: %s", buildErr, output)
		}
	})
	if nativeHookPostForHookTests.err != nil {
		t.Fatal(nativeHookPostForHookTests.err)
	}
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(nativeHookPostForHookTests.path, filepath.Join(binDir, "defenseclaw-hook-post")); err != nil {
		t.Fatal(err)
	}
}

// installNativeGatewayForHookTest runs the same account-bound hook-post
// command as a shipped per-user shell hook. A curl stub bypasses that command
// and cannot exercise the connected listener proof.
func installNativeGatewayForHookTest(t *testing.T, home string, hookDirs ...string) {
	t.Helper()
	nativeGatewayForHookTests.Do(func() {
		var err error
		nativeGatewayForHookTests.dir, err = os.MkdirTemp("", "defenseclaw-hook-native-test-")
		if err != nil {
			nativeGatewayForHookTests.err = err
			return
		}
		nativeGatewayForHookTests.path = filepath.Join(nativeGatewayForHookTests.dir, "defenseclaw-gateway")
		if prebuilt := os.Getenv("DC_TEST_NATIVE_GATEWAY"); filepath.IsAbs(prebuilt) {
			body, readErr := os.ReadFile(prebuilt)
			if readErr == nil {
				readErr = os.WriteFile(nativeGatewayForHookTests.path, body, 0o700)
			}
			nativeGatewayForHookTests.err = readErr
			return
		}
		cmd := exec.Command("go", "build", "-o", nativeGatewayForHookTests.path, "./cmd/defenseclaw")
		cmd.Dir = filepath.Join("..", "..", "..")
		if output, buildErr := cmd.CombinedOutput(); buildErr != nil {
			nativeGatewayForHookTests.err = fmt.Errorf("build native gateway for hook test: %w: %s", buildErr, output)
		}
	})
	if nativeGatewayForHookTests.err != nil {
		t.Fatal(nativeGatewayForHookTests.err)
	}
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(nativeGatewayForHookTests.path, filepath.Join(binDir, "defenseclaw-gateway")); err != nil {
		t.Fatal(err)
	}
	for _, hookDir := range hookDirs {
		linkGatewayBinaryToHookDirForTest(t, hookDir, nativeGatewayForHookTests.path)
	}
}

// A rendered hook selects its POST helper from its physical data directory.
// Tests with a separate HOME must place their fixture binary there as well;
// inherited HOME must never select the helper that receives a bearer.
func linkGatewayBinaryToHookDirForTest(t *testing.T, hookDir, binary string) {
	t.Helper()
	dataDir := filepath.Dir(hookDir)
	trustedHome := dataDir
	if filepath.Base(dataDir) == ".defenseclaw" {
		trustedHome = filepath.Dir(dataDir)
	}
	binDir := filepath.Join(trustedHome, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(binDir, "defenseclaw-gateway")
	if err := os.Link(binary, target); err != nil {
		if !os.IsExist(err) {
			t.Fatal(err)
		}
		installed, installedErr := os.Stat(target)
		source, sourceErr := os.Stat(binary)
		if installedErr != nil || sourceErr != nil {
			t.Fatalf("inspect hook helper %s and fixture %s: %v, %v", target, binary, installedErr, sourceErr)
		}
		if !os.SameFile(installed, source) {
			// A test may render another hook beside this one with a different
			// stub. Each call is sequential; replace the previous fixture.
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(binary, target); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".gateway-helper"), []byte(target+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
