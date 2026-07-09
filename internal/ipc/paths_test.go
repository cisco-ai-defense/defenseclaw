// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestResolveSocketPath(t *testing.T) {
	// Clear the env override for every subtest so table ordering is
	// deterministic regardless of what earlier tests may have set.
	origEnv, hadEnv := os.LookupEnv(SocketEnvVar)
	t.Cleanup(func() {
		if hadEnv {
			_ = os.Setenv(SocketEnvVar, origEnv)
		} else {
			_ = os.Unsetenv(SocketEnvVar)
		}
	})

	cases := []struct {
		name string
		cfg  *config.Config
		env  string
		want string
	}{
		{
			name: "nil config returns empty",
			cfg:  nil,
			want: "",
		},
		{
			name: "explicit config path wins over env and mode",
			cfg: &config.Config{
				DataDir:        "/opt/dc/runtime",
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
				Managed:        config.ManagedIPCConfig{SocketPath: "/custom/socket.sock"},
			},
			env:  "/tmp/wrong.sock",
			want: "/custom/socket.sock",
		},
		{
			name: "env var overrides default in unmanaged mode",
			cfg: &config.Config{
				DataDir: "/home/user/.defenseclaw",
			},
			env:  "/tmp/env.sock",
			want: "/tmp/env.sock",
		},
		{
			name: "env var IGNORED in managed_enterprise (fail-closed)",
			cfg: &config.Config{
				DataDir:        "/opt/dc/runtime",
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
			},
			env:  "/tmp/attacker.sock",
			want: "/opt/dc/ipc/" + SocketFileName,
		},
		{
			name: "managed_enterprise falls back to dirname(data_dir)/ipc/… (macOS installer layout)",
			cfg: &config.Config{
				// Matches packaging/macos/install.sh:
				//   SUPPORT_DIR = /opt/cisco/secureclient/defenseclaw
				//   data_dir    = ${SUPPORT_DIR}/runtime
				// so the socket lands at ${SUPPORT_DIR}/ipc/<file>.
				DataDir:        "/opt/cisco/secureclient/defenseclaw/runtime",
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
			},
			want: "/opt/cisco/secureclient/defenseclaw/ipc/" + SocketFileName,
		},
		{
			name: "unmanaged falls back to data_dir/ipc/…",
			cfg: &config.Config{
				DataDir: "/home/user/.defenseclaw",
			},
			want: filepath.Join("/home/user/.defenseclaw", "ipc", SocketFileName),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env == "" {
				_ = os.Unsetenv(SocketEnvVar)
			} else {
				_ = os.Setenv(SocketEnvVar, tc.env)
			}
			got := ResolveSocketPath(tc.cfg)
			if got != tc.want {
				t.Errorf("ResolveSocketPath: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveSocketMode(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *config.Config
		want    os.FileMode
		wantErr bool
	}{
		{
			name:    "nil config errors",
			cfg:     nil,
			wantErr: true,
		},
		{
			name: "empty mode + managed_enterprise → 0666",
			cfg:  &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise},
			want: 0o666,
		},
		{
			name: "empty mode + unmanaged → 0600",
			cfg:  &config.Config{},
			want: 0o600,
		},
		{
			name: "explicit 0600 always valid",
			cfg: &config.Config{
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
				Managed:        config.ManagedIPCConfig{SocketMode: "0600"},
			},
			want: 0o600,
		},
		{
			name: "explicit 0660 valid in managed_enterprise",
			cfg: &config.Config{
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
				Managed:        config.ManagedIPCConfig{SocketMode: "0660"},
			},
			want: 0o660,
		},
		{
			name: "explicit 0666 valid in managed_enterprise",
			cfg: &config.Config{
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
				Managed:        config.ManagedIPCConfig{SocketMode: "0666"},
			},
			want: 0o666,
		},
		{
			name: "explicit 0666 rejected in unmanaged",
			cfg: &config.Config{
				Managed: config.ManagedIPCConfig{SocketMode: "0666"},
			},
			wantErr: true,
		},
		{
			name: "explicit 0777 rejected everywhere",
			cfg: &config.Config{
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
				Managed:        config.ManagedIPCConfig{SocketMode: "0777"},
			},
			wantErr: true,
		},
		{
			name: "non-octal string is a parse error",
			cfg: &config.Config{
				Managed: config.ManagedIPCConfig{SocketMode: "rw-rw-rw-"},
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveSocketMode(tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got mode %#o", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("ResolveSocketMode: got %#o, want %#o", got, tc.want)
			}
		})
	}
}
