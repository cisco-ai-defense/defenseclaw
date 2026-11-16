//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// On Linux and macOS OpenCode is a machine-policy connector: no row, every
// account loads the plugin. When the account runs OpenCode V1 (the version
// probe answers 1.x), the published record names it OpenCode V1 for that
// account, so status and verify warn (rel-1-0-6 GAP-0037).
func TestEnumerateUnixMachinePolicyOpenCodeV1IsReported(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	alice := makeHome(t, homes, "alice")
	cfg := enumeratorConfig("opencode")
	opts := UnixEnumerateOptions{
		Resolver: &fakeResolver{
			accounts: map[string]unixidentity.Account{"alice": {Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}},
			listed:   []string{"alice"},
		},
		HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1, MachinePolicyConnectors: []string{"opencode"},
		Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			return map[string]string{"opencode": "1.18.34"}, nil, nil
		},
	}
	manifest, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalUnprotectedAgents(report.Unprotected)
	if err != nil {
		t.Fatal(err)
	}
	record, err := ParseUnprotectedAgents(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 0 || len(record) != 1 || record[0].User != "alice" || record[0].Connector != "opencode" ||
		record[0].Version != "1.18.34" || record[0].Code != UnprotectedCodeOpenCodeV1 {
		t.Fatalf("rows = %+v, record = %+v", manifest.Targets, record)
	}

	// OpenCode V2 within the contract reports nothing.
	opts.Discover = func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
		return map[string]string{"opencode": "2.2.3"}, nil, nil
	}
	if _, report, err = EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts); err != nil || len(report.Unprotected) != 0 {
		t.Fatalf("OpenCode V2: unprotected = %+v, %v", report.Unprotected, err)
	}
}
