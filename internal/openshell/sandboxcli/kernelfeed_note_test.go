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

//go:build !windows

package sandboxcli

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// `sandbox ps` names its source: the sample, or the kernel feed's records,
// and why the feed is not used when it is installed but not read.
func TestPsNamesTheKernelFeedSource(t *testing.T) {
	procs := []sandboxapi.Process{{PID: 1, Comm: "init"}, {PID: 7, PPID: 1, Comm: "bash", Source: "tetragon", HostPID: 9100}}
	for name, c := range map[string]struct {
		kernel      *sandboxapi.ProcessKernelFeed
		want, never []string
	}{
		"connected": {
			kernel: &sandboxapi.ProcessKernelFeed{Source: "tetragon", Connected: true, Tetragon: "connected", Execs: 120, Pinned: 9, Dropped: 2},
			want:   []string{"source: kernel", "120 so far (9 with their pid in the sandbox)", "lost 2 records"},
			never:  []string{"sampled every"},
		},
		"older feed": {
			kernel: &sandboxapi.ProcessKernelFeed{Source: "tetragon", Connected: true, Tetragon: "connected", UpdateCommand: "sudo /x/defenseclaw-gateway sandbox kernel-feed install"},
			want:   []string{"source: kernel", "update it: sudo /x/defenseclaw-gateway sandbox kernel-feed install"},
		},
		"skew": {
			kernel: &sandboxapi.ProcessKernelFeed{Source: "tetragon", Reason: "kernel_feed_version_skew", UpdateCommand: "sudo /x/defenseclaw-gateway sandbox kernel-feed install"},
			want:   []string{"not used (kernel_feed_version_skew); update it: sudo", "sampled every 5s"},
			never:  []string{"source: kernel"},
		},
		"tetragon down": {
			kernel: &sandboxapi.ProcessKernelFeed{Source: "tetragon", Connected: true, Tetragon: "unavailable", TetragonReason: "tetragon_unavailable"},
			want:   []string{"its Tetragon is not (tetragon_unavailable)", "sampled every 5s"},
		},
		"no feed": {want: []string{"sampled every 5s"}, never: []string{"kernel"}},
	} {
		app, out := inventoryApp(t, sandboxapi.ProcessList{Name: "box", Enabled: true, IntervalSeconds: 5, Processes: procs, Kernel: c.kernel},
			sandboxapi.DiscoveryResult{})
		if err := app.Ps(context.Background(), PsOptions{Name: "box", Tree: true}); err != nil {
			t.Fatal(err)
		}
		for _, want := range c.want {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%s: output lacks %q:\n%s", name, want, out)
			}
		}
		for _, never := range c.never {
			if strings.Contains(out.String(), never) {
				t.Errorf("%s: output has %q:\n%s", name, never, out)
			}
		}
	}
}
