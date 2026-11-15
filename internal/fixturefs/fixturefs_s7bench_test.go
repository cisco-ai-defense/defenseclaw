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

//go:build s7bench

package fixturefs

import "testing"

func TestMapAndUnmap(t *testing.T) {
	root = "/fx/rootfs"
	t.Cleanup(func() { root = "" })
	cases := map[string]string{
		"/tmp":                "/fx/rootfs/tmp",
		"/tmp/a-*.log":        "/fx/rootfs/tmp/a-*.log",
		"/var/tmp/x":          "/fx/rootfs/var/tmp/x",
		"/dev/shm/s7bench-1":  "/fx/rootfs/dev/shm/s7bench-1",
		"/private/var/tmp/y":  "/fx/rootfs/private/var/tmp/y",
		"/tmpfoo/x":           "/tmpfoo/x",
		"/home/alice/tmp/x":   "/home/alice/tmp/x",
		"/etc/profile.d/a.sh": "/etc/profile.d/a.sh",
		"relative/tmp/x":      "relative/tmp/x",
	}
	for in, want := range cases {
		if got := Map(in); got != want {
			t.Errorf("Map(%q) = %q, want %q", in, got, want)
		}
		if got := Unmap(Map(in)); got != in {
			t.Errorf("Unmap(Map(%q)) = %q", in, got)
		}
	}
	root = ""
	if got := Map("/tmp/x"); got != "/tmp/x" {
		t.Errorf("Map without a root = %q", got)
	}
}
