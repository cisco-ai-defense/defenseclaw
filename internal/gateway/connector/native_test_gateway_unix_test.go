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
func installNativeGatewayForHookTest(t *testing.T, home string) {
	t.Helper()
	nativeGatewayForHookTests.Do(func() {
		var err error
		nativeGatewayForHookTests.dir, err = os.MkdirTemp("", "defenseclaw-hook-native-test-")
		if err != nil {
			nativeGatewayForHookTests.err = err
			return
		}
		nativeGatewayForHookTests.path = filepath.Join(nativeGatewayForHookTests.dir, "defenseclaw-gateway")
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
}
