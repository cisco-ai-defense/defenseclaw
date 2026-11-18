// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// mountRefusal is kitMountRefusal for a table that must parse.
func mountRefusal(t *testing.T, info []byte, protected, guarded []string) string {
	t.Helper()
	got, err := kitMountRefusal(info, protected, guarded)
	if err != nil {
		t.Fatalf("mount table refused as unreadable: %v", err)
	}
	return got
}

// GAP-0439: the protected paths of every connector's image leave the
// ordinary mounts of an actor alone (the runtime's /proc, /dev, /etc/hosts,
// /etc/resolv.conf, /etc/hostname, /run/ate, /tmp and data mounts below the
// WORKDIR).
func TestProtectedPathsLeaveTheOrdinaryMountsAlone(t *testing.T) {
	ordinary := mountBase + mountLine("/proc") + mountLine("/dev") + mountLine("/dev/shm") + mountLine("/dev/pts") + mountLine("/sys") +
		mountLine("/etc/hosts") + mountLine("/etc/resolv.conf") + mountLine("/etc/hostname") + mountLine("/run/ate") + mountLine("/tmp") +
		mountLine("/work") + mountLine("/work/cache")
	for _, c := range kit.Connectors() {
		cfg, _ := builtConfig(t, c)
		if len(cfg.Relay.Protected) < 3 {
			t.Errorf("%s: relay.protected %v names too little", c, cfg.Relay.Protected)
		}
		if got := mountRefusal(t, []byte(ordinary), cfg.Relay.Protected, kit.GuardedDirs(c, kit.ActorHome)); got != "" {
			t.Errorf("%s: the ordinary mounts of an actor are refused (%s)", c, got)
		}
	}
}
