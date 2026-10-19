// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package backend

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
	"golang.org/x/sys/unix"
)

// Ordinary synthetic host files only: no image sealing, child, namespace,
// mount, filter, Git subprocess, broker, credential or runtime is started.
func TestPolicyHostStageLinuxUsesActualSanitizerAndOwnedAssets(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "operator-home")
	project, data := filepath.Join(home, "project"), filepath.Join(base, "private-data")
	for _, name := range []string{project, data} {
		if err := os.MkdirAll(name, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{"public.txt": "fixed public policy capture", ".env": "fixed-name-withheld", ".env.allowed": "fixed explicitly unmasked public fixture"} {
		if err := os.WriteFile(filepath.Join(project, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, spec := resolved(t, "")
	cfg := &config.Config{OpenShell: config.OpenShellConfig{Enabled: true, LLM: config.OpenShellLLMNone,
		Workdir: config.OpenShellWorkdirConfig{Mode: config.OpenShellWorkdirCopy, Masks: []string{".env*"}, Unmask: []string{".env.allowed"}, MaxUploadMB: 1, GitDepth: 3}}}
	policy, _, err := sandboxruntime.ResolveExecutionPolicy(cfg, packs.Flags{Harness: spec.Harness, Project: project, ProjectReal: project},
		sandboxruntime.PolicyOptions{Harness: spec.HarnessIdentity, Offline: true, Authority: sandboxruntime.PolicyAuthorityBinding{SnapshotID: "inert-linux-policy-owner", Generation: 1}})
	if err != nil {
		t.Fatal(err)
	}
	inputs := bridgeprocess.Inputs{Peer: &bridgeprocess.Image{}, Bubblewrap: &bridgeprocess.Image{}, Payload: &bridgeprocess.Image{}, Write: []*os.File{nil}}
	assets, err := PreparePolicyHostStageAssets(context.Background(), policy, spec, HostStageLocation{DataDir: data, Home: home}, inputs, nil, []string{"/work"})
	if assets != nil {
		t.Cleanup(func() {
			if err := assets.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	prepared := assets.workspacePreparation
	if prepared == nil || prepared.policy != policy || prepared.identity != spec.Identity || prepared.summary.Project != project ||
		!slices.Contains(prepared.summary.HeldBack, ".env") || !slices.Contains(prepared.summary.Unmasked, ".env.allowed") {
		t.Fatal("actual sanitized stage lost its policy, source, session or secret-selection association")
	}
	if err := validateWorkspacePreparation(policy, spec, assets); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"public.txt", ".env.allowed"} {
		fd, err := unix.Openat(int(assets.inputs.CWD.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		file := os.NewFile(uintptr(fd), "fixed-policy-stage-child")
		bytes, readErr := io.ReadAll(io.LimitReader(file, 256))
		if err := errors.Join(readErr, file.Close()); err != nil || len(bytes) == 0 {
			t.Fatal("admitted public fixture bytes were lost")
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(int(assets.inputs.CWD.Fd()), ".env", &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		t.Fatal("policy-withheld source entered the held sanitized tree")
	}
	if err := assets.Close(); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(data); err != nil || len(entries) != 0 {
		t.Fatal("policy-bound assets lost their concrete stage cleanup owner")
	}
	if bytes, err := os.ReadFile(filepath.Join(project, ".env")); err != nil || string(bytes) != "fixed-name-withheld" {
		t.Fatal("capture changed the original source")
	}
}
