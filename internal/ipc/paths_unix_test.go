// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package ipc

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestResolveManagedSocketPathUnix(t *testing.T) {
	t.Setenv(SocketEnvVar, "/tmp/attacker.sock")
	cases := []struct {
		name    string
		dataDir string
		want    string
	}{
		{
			name:    "environment override is ignored",
			dataDir: "/opt/dc/runtime",
			want:    filepath.Join("/opt/dc", "ipc", SocketFileName),
		},
		{
			name:    "macOS installer layout",
			dataDir: "/opt/cisco/secureclient/defenseclaw/runtime",
			want: filepath.Join(
				"/opt/cisco/secureclient/defenseclaw",
				"ipc",
				SocketFileName,
			),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				DataDir:        tc.dataDir,
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
			}
			if got := ResolveSocketPath(cfg); got != tc.want {
				t.Fatalf("ResolveSocketPath: got %q, want %q", got, tc.want)
			}
		})
	}
}
