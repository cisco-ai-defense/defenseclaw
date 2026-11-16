//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// On macOS the os/user resolver gives no login shell, so the nologin/false
// enrollment skip never applied there: an account with UserShell
// /usr/bin/false stayed enrolled (GAP-2483). The enumerator now asks the
// platform for the shell of an account whose resolver left it empty.
func TestEnumerateUnixSkipsAFalseLoginShellTheResolverDidNotGive(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	alice := makeHome(t, homes, "alice")
	svc := makeHome(t, homes, "svc")
	kept := makeHome(t, homes, "kept")
	given := makeHome(t, homes, "given")
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{
			// No Shell: what the macOS os/user resolver returns.
			"alice": {Name: "alice", UID: uid, GID: gid, Home: alice},
			"svc":   {Name: "svc", UID: uid, GID: gid, Home: svc},
			"kept":  {Name: "kept", UID: uid, GID: gid, Home: kept},
			// A resolver that gives a shell is trusted as before.
			"given": {Name: "given", UID: uid, GID: gid, Home: given, Shell: "/bin/zsh"},
		},
		listed: []string{"alice", "svc", "kept", "given"},
	}
	asked := map[string]int{}
	previous := unixLoginShell
	unixLoginShell = func(_ context.Context, name string) string {
		asked[name]++
		switch name {
		case "svc", "kept", "given":
			return "/usr/bin/false"
		case "alice":
			return "/bin/zsh"
		}
		return ""
	}
	t.Cleanup(func() { unixLoginShell = previous })
	opts := UnixEnumerateOptions{
		Resolver:  resolver,
		HomeRoots: []string{homes},
		UIDMin:    uid, UIDMax: uid + 1,
		DiscoverSurfaces: func(context.Context, unixidentity.Account, []string) (UnixDiscovery, error) {
			return UnixDiscovery{Versions: map[string]string{"codex": "0.150.0"}}, nil
		},
	}
	cfg := enumeratorConfig("codex")
	cfg.Enterprise.Enrollment.IncludeUsers = []string{"kept"}
	manifest, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, target := range manifest.Targets {
		got = append(got, target.User+"/"+target.Connector)
	}
	// kept is in include_users, so its false shell does not skip it, as on
	// Linux; given keeps the shell its resolver gave.
	if want := "alice/codex,given/codex,kept/codex"; strings.Join(got, ",") != want {
		t.Fatalf("rows = %v, want %s (skipped: %v)", got, want, report.Skipped)
	}
	found := false
	for _, skipped := range report.Skipped {
		if skipped == "svc: non-interactive login shell /usr/bin/false" {
			found = true
		}
	}
	if !found {
		t.Fatalf("svc must be skipped for its /usr/bin/false login shell: %v", report.Skipped)
	}
	if asked["given"] != 0 || asked["kept"] != 0 {
		t.Fatalf("the platform shell is asked only for a not-included account without a shell: %v", asked)
	}
}
