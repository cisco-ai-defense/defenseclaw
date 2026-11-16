// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// stageLegacyBootstrap puts OpenShell 0.1.3's bootstrap files of the Docker
// sandbox id under stateHome, as its docker driver wrote them.
func stageLegacyBootstrap(t *testing.T, stateHome, id string) string {
	t.Helper()
	dir := filepath.Join(stateHome, "openshell", "docker-sandbox-tokens", "defenseclaw-managed", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"boundary-bootstrap.json", "runtime-descriptor.json"} {
		data, err := os.ReadFile(filepath.Join("..", "openshell", "testdata", "docker-bootstrap", "0.1.3", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func bootstrapMoved(t *testing.T, dir string) bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "runtime-descriptor.json"))
	if err != nil {
		t.Fatal(err)
	}
	return !strings.Contains(string(data), "outer_fence")
}

// TestTheBootstrapMigrationLooksWhereTheGatewayKeepsItsState: a managed
// daemon whose own environment has XDG_STATE_HOME (a session or user
// manager that sets it) scanned that folder, but the exec shim starts the
// account's OpenShell gateway with HOME and no XDG_STATE_HOME, so the
// gateway keeps its Docker sandboxes in ~/.local/state: the migration found
// nothing there, and a sandbox made before OpenShell 0.1.5 could not start
// on 0.1.5. It moves the gateway's files now, and leaves the daemon's
// folder alone. The per-user gateway's OpenShell, which the person started
// with or without XDG_STATE_HOME, is looked for in both.
func TestTheBootstrapMigrationLooksWhereTheGatewayKeepsItsState(t *testing.T) {
	const id = "173db0f1-f401-4104-b94b-aaec75789fc3"
	home, xdg := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", xdg)
	restore := sandboxAccountHomeDir
	t.Cleanup(func() { sandboxAccountHomeDir = restore })
	sandboxAccountHomeDir = func() string { return home }

	gatewayDir := stageLegacyBootstrap(t, filepath.Join(home, ".local", "state"), id)
	daemonDir := stageLegacyBootstrap(t, xdg, id)
	moved, err := dockerBootstrapMigrator(true)(id)
	if err != nil || len(moved) != 2 || !bootstrapMoved(t, gatewayDir) {
		t.Fatalf("managed: moved %v, %v", moved, err)
	}
	if bootstrapMoved(t, daemonDir) {
		t.Fatal("managed: the daemon's own XDG_STATE_HOME, which its gateway never reads, was rewritten")
	}

	// The per-user gateway: wherever the person's OpenShell kept them.
	for _, stateHome := range []string{xdg, filepath.Join(home, ".local", "state")} {
		if err := os.RemoveAll(filepath.Join(home, ".local")); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(xdg, "openshell")); err != nil {
			t.Fatal(err)
		}
		dir := stageLegacyBootstrap(t, stateHome, id)
		moved, err := dockerBootstrapMigrator(false)(id)
		if err != nil || len(moved) != 2 || !bootstrapMoved(t, dir) {
			t.Fatalf("per-user, state in %s: moved %v, %v", stateHome, moved, err)
		}
	}

	// A managed account with no home is an error, not a silent no-op.
	sandboxAccountHomeDir = func() string { return "" }
	if _, err := dockerBootstrapMigrator(true)(id); err == nil {
		t.Fatal("a managed account with no home migrated nothing and said nothing")
	}
}

// unreadable makes dir one its owner cannot list until the test ends.
func unreadable(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

// TestAStateFolderTheMigrationCannotListNeverRefusesAStart: the per-user
// gateway's migration also looked in ~/.local/state, and a docker-sandbox-
// tokens folder there it could not list refused the start of every Docker
// sandbox, even one kept in a healthy $XDG_STATE_HOME, or none at all; the
// release, which had no migration, started them. A folder that cannot be
// listed is not known to keep the sandbox: the migration passes over it,
// in whichever folder it is and on a managed account too, moves the files
// where the sandbox is kept, and reads no other folder once one keeps it.
// A file of the sandbox's own that cannot be moved still refuses it.
func TestAStateFolderTheMigrationCannotListNeverRefusesAStart(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any folder")
	}
	const id = "173db0f1-f401-4104-b94b-aaec75789fc3"
	setup := func(t *testing.T) (home, xdg, def string) {
		home, xdg = t.TempDir(), t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_STATE_HOME", xdg)
		restore := sandboxAccountHomeDir
		t.Cleanup(func() { sandboxAccountHomeDir = restore })
		sandboxAccountHomeDir = func() string { return home }
		return home, xdg, filepath.Join(home, ".local", "state")
	}
	tokens := func(stateHome string) string {
		return filepath.Join(stateHome, "openshell", "docker-sandbox-tokens")
	}
	migrates := func(t *testing.T, managed bool, dir string) {
		t.Helper()
		moved, err := dockerBootstrapMigrator(managed)(id)
		if err != nil || len(moved) != 2 || !bootstrapMoved(t, dir) {
			t.Fatalf("moved %v, %v", moved, err)
		}
	}
	startsAsBefore := func(t *testing.T, managed bool) {
		t.Helper()
		if moved, err := dockerBootstrapMigrator(managed)(id); err != nil || len(moved) != 0 {
			t.Fatalf("moved %v, %v", moved, err)
		}
	}

	t.Run("the fallback cannot be listed, XDG keeps the sandbox", func(t *testing.T) {
		_, xdg, def := setup(t)
		dir := stageLegacyBootstrap(t, xdg, id)
		unreadable(t, tokens(def), 0)
		migrates(t, false, dir)
	})
	t.Run("the fallback cannot be listed, XDG keeps nothing", func(t *testing.T) {
		_, _, def := setup(t)
		unreadable(t, tokens(def), 0)
		startsAsBefore(t, false)
	})
	t.Run("XDG cannot be listed, the fallback keeps the sandbox", func(t *testing.T) {
		_, xdg, def := setup(t)
		dir := stageLegacyBootstrap(t, def, id)
		unreadable(t, tokens(xdg), 0)
		migrates(t, false, dir)
	})
	t.Run("a namespace cannot be searched, another keeps the sandbox", func(t *testing.T) {
		_, xdg, def := setup(t)
		dir := stageLegacyBootstrap(t, def, id)
		unreadable(t, filepath.Join(tokens(xdg), "defenseclaw-u1000"), 0o600)
		migrates(t, false, dir)
	})
	t.Run("the fallback keeps a copy that cannot be moved", func(t *testing.T) {
		_, xdg, def := setup(t)
		dir := stageLegacyBootstrap(t, xdg, id)
		stale := stageLegacyBootstrap(t, def, id)
		bad := []byte(`{"outer_fence":`)
		if err := os.WriteFile(filepath.Join(stale, "runtime-descriptor.json"), bad, 0o600); err != nil {
			t.Fatal(err)
		}
		migrates(t, false, dir)
		if got, _ := os.ReadFile(filepath.Join(stale, "runtime-descriptor.json")); string(got) != string(bad) {
			t.Fatalf("the fallback, read after XDG kept the sandbox, changed: %s", got)
		}
	})
	t.Run("a managed account's state cannot be listed", func(t *testing.T) {
		_, _, def := setup(t)
		unreadable(t, tokens(def), 0)
		startsAsBefore(t, true)
	})
	t.Run("the sandbox's own file cannot be moved", func(t *testing.T) {
		_, xdg, def := setup(t)
		dir := stageLegacyBootstrap(t, xdg, id)
		if err := os.WriteFile(filepath.Join(dir, "runtime-descriptor.json"), []byte(`{"outer_fence":`), 0o600); err != nil {
			t.Fatal(err)
		}
		unreadable(t, tokens(def), 0)
		if _, err := dockerBootstrapMigrator(false)(id); !errors.Is(err, openshell.ErrDockerBootstrap) {
			t.Fatalf("a bootstrap of the sandbox that cannot be moved: %v", err)
		}
	})
}
