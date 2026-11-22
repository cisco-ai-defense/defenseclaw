// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// On Windows, with the real share probe (os.Stat of the share), the real
// spelling of shares and the real split of this machine's shares from
// others', no reader opens a session to another machine: the probe never
// runs for a remote server, and the hook call spends none of its share wait
// (a probe of a server that does not answer, such as one in TEST-NET, holds
// the call for its answer wait) (rel-1-0-10:GAP-1074).
func TestRemoteShareOpensNoSessionNatively(t *testing.T) {
	var probes atomic.Int64
	oldProbe := probeNetworkShare
	stat := oldProbe
	probeNetworkShare = func(root string) {
		probes.Add(1)
		stat(root)
	}
	networkShares.mu.Lock()
	oldProbes := networkShares.probes
	networkShares.probes = nil
	networkShares.mu.Unlock()
	t.Cleanup(func() {
		probeNetworkShare = oldProbe
		networkShares.mu.Lock()
		networkShares.probes = oldProbes
		networkShares.mu.Unlock()
	})
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, s := range remoteShareSpellings {
		for _, reader := range remoteShareReaders {
			for _, template := range reader.templates {
				rows++
				command := strings.ReplaceAll(template, "{P}", remoteShareRow(s.root, rows)+`\`+remoteShareTails[1])
				end := HookCall()
				call := currentHookCall()
				left := call.waitLeft
				start := time.Now()
				_ = ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, reader.dialect, nil)
				took := time.Since(start)
				spent := left - call.waitLeft
				end()
				if spent != 0 {
					t.Errorf("%s %s %q: the call waited %v for a share (decision took %v)", s.name, reader.dialect, template, spent, took)
				}
			}
		}
	}
	if n := probes.Load(); n != 0 {
		t.Errorf("%d share probe(s) of another machine", n)
	}
	t.Logf("GAP1074 native rows %d probes %d", rows, probes.Load())
}
