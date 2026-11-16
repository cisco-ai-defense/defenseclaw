// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

type windowsKeptConfigConnector struct {
	*windowsGenericCodexTestConnector
	fail bool
}

func (c windowsKeptConfigConnector) Teardown(context.Context, connector.SetupOpts) error {
	if c.fail {
		return errors.New("test teardown failed")
	}
	return nil // an unchanged agent config keeps its bytes and DACL
}

func TestWindowsTeardownReturnsKeptPatchedFilesToTheirOwner(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "failed"}[fail], func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "hermes", "config.yaml")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			const body = "{}\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			owner := windowsRelaxTestOwner(t, path)
			windowsRelaxTestSetDACL(t, path, windowsRelaxTestFormat(windowsRelaxTestHardenedFile, owner))
			before := windowsRelaxTestDACL(t, path)
			conn := windowsKeptConfigConnector{windowsGenericCodexTestConnector: &windowsGenericCodexTestConnector{
				name: "hermes", configPath: path,
			}, fail: fail}
			target := windowsGenericManagedTarget{home: home, dataDir: filepath.Join(home, ".defenseclaw"), sid: owner, conn: conn}
			err := teardownWindowsGenericManagedTarget(t.Context(), target, []string{path}, connector.AgentPaths{PatchedFiles: []string{path}})
			if (err != nil) != fail {
				t.Fatalf("teardown error = %v, want failure %v", err, fail)
			}
			after := windowsRelaxTestDACL(t, path)
			if fail && after != before {
				t.Fatalf("failed teardown changed the config DACL: %s -> %s", before, after)
			}
			if !fail && (strings.Contains(after, windowsGuardianHardenedOwnerRightsACE) || !strings.Contains(after, "(A;;FA;;;OW)")) {
				t.Fatalf("completed teardown kept the guardian's restriction: %s", after)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != body {
				t.Fatalf("config bytes changed: %q, %v", got, err)
			}
		})
	}
}

func TestWindowsPatchedFileReturnRefusesUnsafePaths(t *testing.T) {
	for _, kind := range []string{"outside home", "hard link", "directory"} {
		t.Run(kind, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "config.yaml")
			if kind == "outside home" {
				path = filepath.Join(t.TempDir(), "config.yaml")
			}
			if kind == "directory" {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("user data"), 0o600); err != nil {
				t.Fatal(err)
			}
			if kind == "hard link" {
				if err := os.Link(path, filepath.Join(home, "second-name")); err != nil {
					t.Fatal(err)
				}
			}
			owner := windowsRelaxTestOwner(t, path)
			before := windowsRelaxTestDACL(t, path)
			target := windowsGenericManagedTarget{home: home, sid: owner, dataDir: filepath.Join(home, ".defenseclaw")}
			if err := returnWindowsStandalonePatchedFilesToOwner(target, []string{path}, connector.AgentPaths{}); err == nil {
				t.Fatal("unsafe file return succeeded")
			}
			if after := windowsRelaxTestDACL(t, path); after != before {
				t.Fatalf("unsafe file DACL changed: %s -> %s", before, after)
			}
		})
	}
}
