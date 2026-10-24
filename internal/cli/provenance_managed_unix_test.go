// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestManagedProvenanceShowsTheRunningGatewaySnapshot(t *testing.T) {
	layout := withManagedStandaloneDeployment(t, 991)
	withManagedHostCallerUID(t, 0)
	t.Setenv(managed.ConfigPathEnv, "/personal/config.yaml")
	previous := managedProvenanceHealth
	t.Cleanup(func() { managedProvenanceHealth = previous })
	called := false
	managedProvenanceHealth = func(_ context.Context, actual managed.StandaloneLayout, uid int, answer any) error {
		called = true
		if actual.ConfigPath != layout.ConfigPath || uid != 991 {
			t.Fatalf("managed provenance read another deployment: %+v, uid %d", actual, uid)
		}
		return json.Unmarshal([]byte(fmt.Sprintf(`{"provenance":{"schema_version":7,"content_hash":%q,"generation":42,"binary_version":"1.0.4-live"}}`, strings.Repeat("a", 64))), answer)
	}
	var out strings.Builder
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runProvenanceShow(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if !called || !strings.Contains(out.String(), "content_hash: "+strings.Repeat("a", 64)+"\n") ||
		!strings.Contains(out.String(), "generation: 42\n") || !strings.Contains(out.String(), "binary_version: 1.0.4-live\n") {
		t.Fatalf("provenance used this short-lived CLI's empty snapshot: %s", out.String())
	}
}

func TestManagedProvenanceHealthUsesTheVerifiedSocketConnection(t *testing.T) {
	path := filepath.Join(testenv.PrivateTempDir(t), "hook.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" || r.Header.Get("Authorization") != "" || r.Header.Get("X-DefenseClaw-Token") != "" {
			t.Errorf("unexpected credential or route on provenance request: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"provenance":{"generation":42}}`))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	layout := managed.StandaloneLayout{HookSocketPath: path}
	var answer struct{ Provenance struct{ Generation int } }
	if err := managedProvenanceHealth(t.Context(), layout, os.Geteuid(), &answer); err != nil || answer.Provenance.Generation != 42 {
		t.Fatalf("socket health = %+v, %v", answer, err)
	}
	if os.Geteuid() != 0 {
		if err := managedProvenanceHealth(t.Context(), layout, os.Geteuid()+1, &answer); err == nil {
			t.Fatal("accepted a listener belonging to another account")
		}
	}
}

func TestManagedProvenanceRefusesStandardUsersAndIncompleteHealth(t *testing.T) {
	withManagedStandaloneDeployment(t, 991)
	previous := managedProvenanceHealth
	t.Cleanup(func() { managedProvenanceHealth = previous })
	called := false
	managedProvenanceHealth = func(_ context.Context, _ managed.StandaloneLayout, _ int, answer any) error {
		called = true
		return json.Unmarshal([]byte(`{"provenance":{"schema_version":7,"binary_version":"1.0.4"}}`), answer)
	}
	withManagedHostCallerUID(t, 1000)
	t.Setenv(managed.ConfigPathEnv, "/personal/config.yaml")
	if err := runProvenanceShow(&cobra.Command{}, nil); err == nil || called {
		t.Fatalf("standard user read managed provenance: err=%v called=%v", err, called)
	}
	withManagedHostCallerUID(t, 0)
	if err := runProvenanceShow(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), "enterprise "+managedHostPlatform()+" status") {
		t.Fatalf("incomplete provenance did not name the real next command: %v", err)
	}
}
