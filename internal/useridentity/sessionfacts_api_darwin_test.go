// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package useridentity

import (
	"syscall"
	"testing"
)

func TestAPIPrincipalMissingCacheSettles(t *testing.T) {
	principal, settled := readAPIPrincipal("r108-perf100m-empty-cache")
	if principal != "" || !settled {
		t.Fatalf("missing API cache = %q, %v; want a settled empty result", principal, settled)
	}
}

func TestAPIPrincipalColdReadDoesNotSpawn(t *testing.T) {
	var before, after syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &before); err != nil {
		t.Fatal(err)
	}
	if principal, settled := readAPIPrincipal("r108-perf100m-uncached"); principal != "" || !settled {
		t.Fatalf("cold API cache = %q, %v; want a settled empty result", principal, settled)
	}
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &after); err != nil {
		t.Fatal(err)
	}
	if before.Utime != after.Utime || before.Stime != after.Stime {
		t.Fatalf("cold session facts used child CPU: before=%v/%v after=%v/%v",
			before.Utime, before.Stime, after.Utime, after.Stime)
	}
}
