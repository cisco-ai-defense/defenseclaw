// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package useridentity

import (
	"encoding/json"
	"os/exec"
	"syscall"
	"testing"
)

func TestAPIPrincipalMatchesPopulatedDefaultKlist(t *testing.T) {
	output, err := exec.Command("/usr/bin/klist", "--json").Output()
	if err != nil {
		t.Skip("no populated default cache")
	}
	var cache struct {
		Cache     string `json:"cache"`
		Principal string `json:"principal"`
	}
	if err := json.Unmarshal(output, &cache); err != nil {
		t.Fatal(err)
	}
	kind, residual := SplitCCacheName(cache.Cache)
	if kind != CCacheAPI || residual == "" || cache.Principal == "" {
		t.Skip("no populated API default cache")
	}
	want := NormalizePrincipal(cache.Principal)
	if principal, settled := readAPIPrincipal(""); !settled || principal != want {
		t.Fatal("default API cache principal differs from klist")
	}
	if principal, settled := readAPIPrincipal(residual); !settled || principal != want {
		t.Fatal("named API cache principal differs from klist")
	}
}

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
