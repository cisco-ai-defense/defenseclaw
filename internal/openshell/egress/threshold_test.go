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

package egress

import (
	"net/netip"
	"testing"
)

// TestCounterPerPrincipalThreshold pins that each sandbox's large-upload
// threshold is its own: a principal's LargeUploadBytes overrides the
// counter's, negative turns the signal (and the block) off for it alone,
// and zero keeps the counter's.
func TestCounterPerPrincipalThreshold(t *testing.T) {
	c := NewCounter(CounterOptions{LargeUploadBytes: 1000, BlockLargeUploads: true})
	strict := Principal{BindingID: "b-strict", LargeUploadBytes: 100}
	off := Principal{BindingID: "b-off", LargeUploadBytes: -1}
	dflt := Principal{BindingID: "b-default"}

	s, _ := c.open(strict, "drop.example", netip.Addr{})
	if v := s.addUp(101, false); !v.signal || !v.cut {
		t.Fatalf("the sandbox's own 100-byte threshold did not apply: %+v", v)
	}
	if !c.uploadBlocked(strict, "drop.example") {
		t.Fatal("the strict sandbox's block did not apply")
	}
	d, _ := c.open(dflt, "drop.example", netip.Addr{})
	if v := d.addUp(101, false); v.signal || v.cut {
		t.Fatalf("another sandbox got the strict threshold: %+v", v)
	}
	if v := d.addUp(1000, false); !v.signal {
		t.Fatalf("the counter's threshold did not apply to a principal without one: %+v", v)
	}
	o, _ := c.open(off, "drop.example", netip.Addr{})
	if v := o.addUp(1<<30, false); v.signal || v.cut || c.uploadBlocked(off, "drop.example") {
		t.Fatalf("a sandbox with the signal off was signalled or blocked: %+v", v)
	}
}

// TestProxyLargeUploadReasonNamesTheSandboxThreshold pins that a
// large-upload refusal quotes the threshold of the sandbox it refused.
func TestProxyLargeUploadReasonNamesTheSandboxThreshold(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.counter = &CounterOptions{BlockLargeUploads: true} })
	pr := Principal{BindingID: "b-small", LargeUploadBytes: 3 << 20}
	if got := h.proxy.largeUploadReason(pr); got != "More than 3 MiB was sent to a destination this sandbox had not contacted before." {
		t.Fatalf("reason = %q", got)
	}
}
