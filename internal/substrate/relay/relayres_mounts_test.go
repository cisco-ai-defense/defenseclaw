// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"encoding/json"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest/kitspec"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// builtConfig is the kit configuration the template build writes into a
// connector's image (kitspec, as template build runs it).
func builtConfig(t *testing.T, connector string) (kit.Config, []string) {
	t.Helper()
	h, ok := harness.Get(connector)
	if !ok {
		t.Fatalf("no harness %s", connector)
	}
	art, err := kit.SubstrateArtifacts(h.Provider, h.DefaultVersion, kit.DefaultConfig())
	if err != nil {
		t.Fatalf("%s: artifacts: %v", connector, err)
	}
	ov, err := kit.ActorOverlay(art, kit.OverlayOptions{Config: kit.DefaultConfig(), Home: kitspec.Home, Workdir: kitspec.Workdir})
	if err != nil {
		t.Fatalf("%s: overlay: %v", connector, err)
	}
	var cfg kit.Config
	var settings []string
	for _, f := range ov.Files {
		if f.Path == kit.ConfigPath {
			if err := json.Unmarshal(f.Data, &cfg); err != nil {
				t.Fatalf("%s: the kit configuration (%d bytes): %v", connector, len(f.Data), err)
			}
		}
		// The connector's own root-owned settings below /etc (not the kit's).
		if !f.User && strings.HasPrefix(f.Path, "/etc/") && !strings.HasPrefix(f.Path, "/etc/defenseclaw/") && path.Dir(f.Path) != "/etc" {
			settings = append(settings, f.Path)
		}
	}
	if cfg.Relay.Connector == "" {
		t.Fatalf("%s: no kit configuration in the layer", connector)
	}
	return cfg, settings
}

const mountBase = "1 0 0:1 / / rw - overlay overlay rw\n"

func mountLine(mp string) string { return "36 1 0:36 / " + mp + " rw,relatime - tmpfs tmpfs rw\n" }

// GAP-0439: in every connector's image, a mount at a folder that holds the
// connector's attested managed settings (as a data mount through a symlink
// in the image or an image volume lands there), at the file or above the
// folder, refuses the agent; so does a mount at or above a guarded HOME
// folder (HOME itself for Antigravity). The ordinary mounts of an actor do
// not.
func TestRelayRefusesAMountOverTheConnectorsSettings(t *testing.T) {
	ordinary := mountBase + mountLine("/proc") + mountLine("/dev") + mountLine("/dev/shm") + mountLine("/etc/hosts") +
		mountLine("/etc/resolv.conf") + mountLine("/etc/hostname") + mountLine("/run/ate") + mountLine("/tmp") + mountLine("/work") + mountLine("/work/cache")
	covered := map[string]bool{}
	for _, c := range kit.Connectors() {
		cfg, settings := builtConfig(t, c)
		guard := kit.GuardedDirs(c, kit.ActorHome)
		var mps []string
		for _, f := range settings {
			mps = append(mps, f, path.Dir(f))
			covered[path.Dir(f)] = true
		}
		for _, g := range guard {
			mps = append(mps, g, path.Dir(g), path.Join(g, "hooks"))
		}
		for _, mp := range mps {
			s, _, _ := testServer(t, []string{"sh"})
			s.opts.Config = cfg
			s.opts.Config.Relay.Interactive = []string{"sh"}
			gem := filepath.Join(t.TempDir(), ".gemini")
			s.opts.Guard = []string{gem}
			if len(guard) > 0 {
				// The guarded folder as the image has it.
				s.opts.Guard = guard
			}
			table := ordinary + mountLine(mp)
			s.opts.mountinfo = func() ([]byte, error) { return []byte(table), nil }
			err := s.init()
			if err == nil || !strings.Contains(err.Error(), "mounted at, above or below") {
				t.Errorf("%s: a mount at %s: the relay starts the agent (%v)", c, mp, err)
			}
		}
	}
	for _, want := range []string{"/etc/claude-code", "/etc/claude-code/managed-settings.d", "/etc/codex", "/etc/opencode", "/etc/hermes"} {
		found := false
		for d := range covered {
			if d == want || strings.HasPrefix(d, want+"/") {
				found = true
			}
		}
		if !found {
			t.Errorf("no connector's settings are in %s: the test does not cover it", want)
		}
	}
}

// GAP-0443: a mount table without the root mount (empty, or not the
// actor's) is not one DefenseClaw can trust: the relay refuses the agent as
// for an unreadable one.
func TestRelayRefusesAMountTableWithoutTheRootMount(t *testing.T) {
	for name, table := range map[string]string{"empty": "", "no root line": mountLine("/work") + mountLine("/proc")} {
		s, _, _ := testServer(t, []string{"sh"})
		s.opts.Guard = []string{}
		s.opts.mountinfo = func() ([]byte, error) { return []byte(table), nil }
		err := s.init()
		if err == nil || !strings.Contains(err.Error(), "cannot read the actor's mounts") {
			t.Errorf("%s mount table: the relay starts the agent (%v)", name, err)
		}
	}
}
