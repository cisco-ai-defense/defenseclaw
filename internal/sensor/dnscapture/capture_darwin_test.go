// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package dnscapture

import "testing"

// TestBPFHeaderMinimumMatchesDarwin pins the bound that silently disabled
// DNS capture on macOS for the life of every process that ran it.
//
// Darwin declares bh_tstamp as a 32-bit timeval for 64-bit userland, so
// struct bpf_hdr is 18 bytes of members. The walk compared the kernel's
// reported bh_hdrlen against 20 -- the padded size -- as a minimum, so
// every record failed and the decoder returned on the first packet of every
// read. Capture reported itself healthy and observed nothing.
func TestBPFHeaderMinimumMatchesDarwin(t *testing.T) {
	t.Parallel()
	// 8 timeval + 4 caplen + 4 datalen + 2 hdrlen.
	const darwinReportedHeaderLen = 18
	if bpfHdrMin > darwinReportedHeaderLen {
		t.Fatalf("bpfHdrMin = %d, but Darwin reports bh_hdrlen = %d; every "+
			"record would be rejected and capture would observe nothing",
			bpfHdrMin, darwinReportedHeaderLen)
	}
}
