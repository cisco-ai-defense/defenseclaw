// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0135: in a cluster, the chart-mounted config (a read-only regular
// file, root-owned, in a root-owned directory) is the activated config. A
// symlink, a writable file, another owner or other bytes are refused, and
// without the registered check a host keeps refusing unrecorded boot bytes.
func TestSubstrateClusterActivation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "action")
	raw, _ := os.ReadFile(path)
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	asRoot := func(os.FileInfo) (uint32, bool) { return 0, true }
	asUser := func(os.FileInfo) (uint32, bool) { return 1000, true }
	accept := SubstrateMountedConfigActivation(asRoot)
	if err := accept(path, raw); err != nil {
		t.Fatalf("chart-mounted layout refused: %v", err)
	}
	if err := SubstrateMountedConfigActivation(asUser)(path, raw); err == nil {
		t.Fatal("a config owned by the gateway account was accepted")
	}
	if err := accept(path, append([]byte("# edited\n"), raw...)); err == nil {
		t.Fatal("boot bytes that differ from the mount were accepted")
	}
	_ = os.Chmod(path, 0o644)
	if err := accept(path, raw); err == nil {
		t.Fatal("a writable config was accepted")
	}
	_ = os.Chmod(path, 0o444)
	// A ConfigMap mounted as a directory: config.yaml is a ..data symlink.
	link := filepath.Join(t.TempDir(), config.DefaultConfigName)
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := accept(link, raw); err == nil {
		t.Fatal("a symlinked config was accepted")
	}

	// Host managed mode: no check registered, the unrecorded boot bytes
	// stay refused (the laptop lifecycle rule). With the cluster check
	// registered, the same mounted bytes start.
	mgr := &ConfigManager{path: path}
	SetSubstrateClusterActivation(nil)
	if refusal := mgr.startupActivationRefusal(raw); refusal == nil {
		t.Fatal("host managed mode admitted an unrecorded config")
	}
	SetSubstrateClusterActivation(accept)
	t.Cleanup(func() { SetSubstrateClusterActivation(nil) })
	if refusal := mgr.startupActivationRefusal(raw); refusal != nil {
		t.Fatalf("cluster managed mode refused the mounted config: %v", refusal)
	}
	// The symlink stays refused in cluster mode too (falls through to the
	// host rules).
	if refusal := (&ConfigManager{path: link}).startupActivationRefusal(raw); refusal == nil {
		t.Fatal("cluster mode admitted a symlinked config")
	}
}
