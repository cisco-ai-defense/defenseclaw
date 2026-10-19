// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package manager

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestCreateUsesOneOwnedPolicyConfiguration(t *testing.T) {
	e := newEnv(t, func(cfg *config.Config) {
		cfg.OpenShell.TokenDelivery = config.OpenShellTokenDeliveryProvider
		cfg.OpenShell.Image.Base = "example.invalid/original:fixed"
		cfg.OpenShell.Image.HarnessVersions = map[string]string{"claudecode": "2.1.156"}
		cfg.OpenShell.Workdir.UndoIgnored = config.OpenShellUndoIgnoredConfig{
			Enabled: true, MaxMB: 64, Dirs: []string{"vendor"},
		}
	})
	original := e.config()
	next, err := original.DeepCopy()
	must(t, err)
	next.OpenShell.Profile = "strict"
	next.OpenShell.Workdir.Mode = config.OpenShellWorkdirCopy
	next.OpenShell.TokenDelivery = config.OpenShellTokenDeliveryEnv
	next.OpenShell.Image.Base = "example.invalid/replacement:fixed"
	next.OpenShell.Image.HarnessVersions["claudecode"] = "replacement-version"
	next.OpenShell.Workdir.UndoIgnored = config.OpenShellUndoIgnoredConfig{
		Enabled: true, MaxMB: 1, Dirs: []string{"replacement"},
	}
	// Model publication immediately after Create takes its input snapshot.
	// Other live manager operations may read the new config, but provisioning
	// cannot combine it with the policy resolved from the original snapshot.
	var reads atomic.Uint64
	e.m.opts.Config = func() *config.Config {
		if reads.Add(1) == 1 {
			return original
		}
		return next
	}
	sb := e.create(sandboxapi.CreateRequest{Name: "owned-resolution"})
	// The normal live-policy refresh may already apply the newer profile to
	// status. The original workspace layout is fixed at creation.
	if sb.WorkdirMode != config.OpenShellWorkdirMount {
		t.Fatal("initial workspace layout changed during provisioning")
	}
	e.images.mu.Lock()
	builds := slices.Clone(e.images.resolved)
	e.images.mu.Unlock()
	if len(builds) != 1 || builds[0].BaseImage != original.OpenShell.Image.Base || builds[0].HarnessVersion != "2.1.156" {
		t.Fatalf("image settings came from another configuration: %+v", builds)
	}
	if rec := loadRecord(t, e, sb.Name); rec.TokenDelivery != config.OpenShellTokenDeliveryProvider {
		t.Fatalf("token delivery changed during provisioning: %s", rec.TokenDelivery)
	}
	e.ws.mu.Lock()
	snapshot := e.ws.lastSnapshot
	e.ws.mu.Unlock()
	if !slices.Equal(snapshot.KeepIgnored, []string{"vendor"}) || snapshot.KeepIgnoredBytes != 64<<20 {
		t.Fatalf("undo snapshot settings changed: %v, %d", snapshot.KeepIgnored, snapshot.KeepIgnoredBytes)
	}
}

type resolutionImages struct {
	Images
	before func()
}

func (f resolutionImages) Resolve(ctx context.Context, spec image.BuildSpec, build bool) (image.Record, error) {
	f.before()
	return f.Images.Resolve(ctx, spec, build)
}

func TestCreateOwnsRecordedAndWorkspaceFlagsBeforeProvisioning(t *testing.T) {
	e := newEnv(t, nil)
	contextDir := e.otherProject("context")
	unmask, ports, contexts := []string{".env"}, []int{5432}, []string{contextDir}
	e.m.opts.Images = resolutionImages{Images: e.images, before: func() {
		unmask[0], ports[0], contexts[0] = "replacement", 9999, "replacement"
	}}
	sb := e.create(sandboxapi.CreateRequest{Name: "owned-flags", Unmask: unmask, HostPorts: ports, Context: contexts})
	rec := loadRecord(t, e, sb.Name)
	if !slices.Equal(rec.Flags.Unmask, []string{".env"}) || !slices.Equal(rec.Flags.HostPorts, []int{5432}) || !slices.Equal(rec.Flags.Context, []string{contextDir}) {
		t.Fatalf("recorded flags changed after resolution: %+v", rec.Flags)
	}
	e.ws.mu.Lock()
	mount := e.ws.lastMount
	e.ws.mu.Unlock()
	if !slices.Equal(mount.Context, []string{contextDir}) || !slices.Contains(mount.Unmask, ".env") || slices.Contains(mount.Unmask, "replacement") {
		t.Fatalf("workspace flags changed after resolution: %+v", mount)
	}
}
