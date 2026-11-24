// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

const (
	gap2073Current = openshell.GatewayAgentBase + ".b28adac7654b"
	gap2073Earlier = openshell.GatewayAgentBase + ".e109ee598011"
)

// gap2073Rig is a Mac account whose OpenShell gateway runs under an
// earlier DefenseClaw's LaunchAgent label after a package upgrade, with the
// installed label not loaded.
func gap2073Rig(t *testing.T) *openShellRig {
	t.Helper()
	dir := t.TempDir()
	prev := openShellLaunchAgentsDir
	openShellLaunchAgentsDir = dir
	t.Cleanup(func() { openShellLaunchAgentsDir = prev })
	if err := os.WriteFile(filepath.Join(dir, gap2073Current+".plist"), []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := newOpenShellRig(t, "darwin")
	inner := r.o.run
	booted := false
	r.o.run = func(ctx context.Context, name string, args, env []string) (string, error) {
		out, err := inner(ctx, name, args, env)
		line := filepath.Base(name) + " " + strings.Join(args, " ")
		switch line {
		case "launchctl print gui/5001":
			if booted {
				return "services = {\n}\n", nil
			}
			return "services = {\n\t0\t-\t" + gap2073Earlier + "\n}\n", nil
		case "launchctl print gui/5001/" + gap2073Earlier:
			if booted {
				return "Could not find service", errors.New("exit status 113")
			}
			return "state = running\n", nil
		case "launchctl print gui/5001/" + gap2073Current:
			return "Could not find service", errors.New("exit status 113")
		case "launchctl bootout gui/5001/" + gap2073Earlier:
			booted = true
		}
		if strings.HasPrefix(line, "launchctl print user/") {
			return "", errors.New("exit status 113")
		}
		return out, err
	}
	return r
}

// rel-1-0-10:GAP-2073: a managed Mac upgraded while a MicroVM sandbox ran
// kept its OpenShell gateway under the earlier DefenseClaw's LaunchAgent
// label. After that sandbox stopped, the first run said "Sandboxes are
// paused ... Ask IT to repair them" (the earlier job runs the earlier
// settings), and only `enterprise macos repair` replaced the job, though
// the lifecycle's pending entry says the first start after the sandboxes
// stop reloads it. The daemon's stop now boots out the earlier job (after
// the MicroVM sync), so the next start loads the installed label.
func TestGAP2073MacStopReplacesAnEarlierDefenseClawGatewayJob(t *testing.T) {
	r := gap2073Rig(t)
	if !r.o.Stop(context.Background(), prerequisiteSettings()) {
		t.Fatalf("stop of the earlier job: %v", r.ran())
	}
	sync, boot := -1, -1
	for i, c := range r.ran() {
		switch {
		case strings.HasPrefix(c, "stop-sync"):
			sync = i
		case c == "launchctl bootout gui/5001/"+gap2073Earlier:
			boot = i
		}
	}
	if boot < 0 || sync < 0 || sync > boot {
		t.Fatalf("want the MicroVM sync, then the bootout of the earlier job: %v", r.ran())
	}
	// The next start loads the installed label: nothing of the earlier
	// job is left loaded.
	for _, c := range r.ran()[boot+1:] {
		if strings.Contains(c, gap2073Earlier) && !strings.HasPrefix(c, "launchctl print ") {
			t.Fatalf("the earlier job was touched again after its bootout: %v", r.ran())
		}
	}
}

// The run waits, in words that send no one to IT, while a sandbox of the
// account still runs on the earlier job; with none, the earlier job is
// stopped first and the run goes on.
func TestGAP2073RunWaitsForTheSandboxesThenReplacesTheEarlierJob(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.relay.resolve = floorResolve
	f.os.earlier = "gui/5001/" + gap2073Earlier
	f.os.drift = []openshell.SettingDrift{{Field: "compute driver", Want: "vm", Have: "docker"}}
	f.os.dropDriftOnStop = true
	f.d.opts.countMicroVMs = func(context.Context) (int, error) { return 0, nil }
	f.running.Store(1)
	f.run(t)
	client := sandboxapi.NewUnixClient(f.socket)
	_, err := client.Create(context.Background(), sandboxapi.CreateRequest{Harness: "claudecode"})
	if err == nil || !strings.Contains(err.Error(), "DefenseClaw was updated while your sandboxes ran") || strings.Contains(err.Error(), "Ask IT") || f.os.stopped.Load() != 0 {
		t.Fatalf("while a sandbox runs: %v (stopped %d)", err, f.os.stopped.Load())
	}
	f.running.Store(0)
	_, err = client.Create(context.Background(), sandboxapi.CreateRequest{Harness: "claudecode"})
	if f.os.stopped.Load() != 1 || f.os.prepared.Load() != 1 || err != nil && (strings.Contains(err.Error(), "paused") || strings.Contains(err.Error(), "DefenseClaw was updated while your sandboxes ran")) {
		t.Fatalf("with no sandbox running: %v (stopped %d, prepared %d)", err, f.os.stopped.Load(), f.os.prepared.Load())
	}
}
