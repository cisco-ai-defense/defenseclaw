// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package assetfacts

import (
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"testing"
	"time"
)

func TestOnNetworkShareNamesEveryUNCSpellingAndNoLocalPath(t *testing.T) {
	for path, want := range map[string]bool{
		`\\server\share\a`:           true,
		`//server/share/a`:           true,
		`\\?\UNC\server\share\a`:     true,
		`\\.\unc\server\share\a`:     true,
		`C:\Users\a`:                 false,
		`\\?\C:\Users\a`:             false,
		`\\.\pipe\name`:              false,
		`\\?\`:                       false,
		`\rooted\a`:                  false,
		`relative\a`:                 false,
		`C:\Users\a\skills\ordinary`: false,
	} {
		if got := onNetworkShare(path); got != want {
			t.Errorf("onNetworkShare(%q) = %t, want %t", path, got, want)
		}
	}
}

// A path on a share that does not answer (RFC 5737 TEST-NET-1) comes back as
// spelled at once: no link on it is examined, so the hook is not held for the
// system connect timeout.
func TestResolveLinksDoesNotExamineAPathOnANetworkShare(t *testing.T) {
	host := 10 + rand.IntN(200)
	for i, path := range []string{
		fmt.Sprintf(`//192.0.2.%d/share/skills/a/../b/SKILL.md`, host),
		fmt.Sprintf(`\\?\UNC\192.0.2.%d\share\skills\b\SKILL.md`, host+1),
		fmt.Sprintf(`\\192.0.2.%d\share\skills\b\SKILL.md`, host+2),
	} {
		start := time.Now()
		got := ResolveLinks(path)
		if took := time.Since(start); took > time.Second {
			t.Errorf("spelling %d: ResolveLinks took %v, want no wait for the share", i, took)
		}
		if want := filepath.Clean(path); got != want {
			t.Errorf("spelling %d: ResolveLinks = %q, want %q", i, got, want)
		}
	}
}
