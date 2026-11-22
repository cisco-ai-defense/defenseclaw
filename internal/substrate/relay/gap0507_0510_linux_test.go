// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"path"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/attest/kitspec"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0507: relay.protected names every root-owned file the template build
// writes and attests in every connector's image: the kit overlay, the empty
// /etc/machine-id, the hook and relay binaries, and the connector's pinned
// agent build. A mount at such a file or at a folder holding it refuses the
// agent; the ordinary mounts of an actor still do not.
func TestGAP0507EveryAttestedRootFileIsProtected(t *testing.T) {
	ordinary := mountBase + mountLine("/proc") + mountLine("/dev") + mountLine("/dev/shm") + mountLine("/dev/pts") + mountLine("/sys") +
		mountLine("/etc/hosts") + mountLine("/etc/resolv.conf") + mountLine("/etc/hostname") + mountLine("/run/ate") + mountLine("/tmp") +
		mountLine("/work") + mountLine("/work/cache")
	shared := map[string]bool{"/": true, "/etc": true, "/opt": true, "/usr/bin": true, "/usr/local/bin": true, "/usr/local/etc": true,
		"/usr/local/lib": true, "/usr/local/share": true, kitspec.Home: true}
	for _, c := range kit.Connectors() {
		spec, _, err := kitspec.Spec(kitspec.Options{Connector: c, KitVersion: "1.0.10", HookBinary: []byte("x"), RelayBinary: []byte("x"),
			MetadataOnly: true})
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		var attested []string
		for _, f := range spec.Files {
			if !spec.UserFiles[f.Path] && !f.Dir && f.Symlink == "" {
				attested = append(attested, f.Path)
			}
		}
		// A metadata spec leaves the pinned agent build out; the build adds it.
		if r, pinned := kit.AgentReleases[c]; pinned {
			attested = append(attested, r.Path)
		}
		cfg, _ := builtConfig(t, c)
		guard := kit.GuardedDirs(c, kit.ActorHome)
		if got := mountRefusal(t, []byte(ordinary), cfg.Relay.Protected, guard); got != "" {
			t.Errorf("%s: the ordinary mounts of an actor are refused (%s)", c, got)
		}
		for _, p := range attested {
			mps := []string{p, path.Dir(p)}
			if d := path.Dir(p); !shared[d] {
				mps = append(mps, path.Join(d, "x"))
			}
			for _, mp := range mps {
				if got := mountRefusal(t, []byte(ordinary+mountLine(mp)), cfg.Relay.Protected, guard); got == "" {
					t.Errorf("%s: a mount at %s (the attested %s) is not refused; relay.protected = %v", c, mp, p, cfg.Relay.Protected)
				}
			}
		}
	}
}

// GAP-0510: a second mount at / (an image volume reached through a symlink
// to /) lies over the image and hides every attested file: the relay
// refuses it, however the mount point is spelled. The one root mount, the
// image, is not refused.
func TestGAP0510ASecondMountAtRootIsRefused(t *testing.T) {
	cfg, _ := builtConfig(t, "claudecode")
	if got := mountRefusal(t, []byte(mountBase+mountLine("/work")), cfg.Relay.Protected, nil); got != "" {
		t.Fatalf("the image's own root mount is refused (%s)", got)
	}
	for name, info := range map[string]string{
		"a second / after the data mounts": mountBase + mountLine("/work") + mountLine("/"),
		"a second / right after the image": mountBase + mountLine("/"),
		"a second / spelled /.":            mountBase + mountLine("/."),
		"a second / spelled //":            mountBase + mountLine("//"),
	} {
		if got := mountRefusal(t, []byte(info), cfg.Relay.Protected, nil); got != "/" {
			t.Errorf("%s: kitMountRefusal = %q, want the mount over / refused", name, got)
		}
	}
}
