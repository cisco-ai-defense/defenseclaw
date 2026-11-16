// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestGAP0456StaticFunctionProjectionBound(t *testing.T) {
	var command strings.Builder
	for i := 0; i < 7; i++ {
		fmt.Fprintf(&command, "f%d() { f%d", i, i+1)
		for range 8 {
			command.WriteString(` "$@"`)
		}
		command.WriteString("; }; ")
	}
	command.WriteString("f7() { printf c >> ~/.defenseclaw/config.yaml; }; f0 seed")
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	readings := StaticFunctionCallReadings(command.String(), "/home/fixture")
	runtime.ReadMemStats(&after)
	if len(readings) != 0 {
		t.Fatalf("projection exceeded its work bound: %d readings", len(readings))
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 2<<20 {
		t.Fatalf("projection allocated %d bytes", allocated)
	}
}
