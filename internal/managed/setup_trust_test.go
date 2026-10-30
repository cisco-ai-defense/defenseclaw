// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"testing"
	"time"
)

func TestIsSetupLeftoverNameAcceptsOnlyCapabilityNames(t *testing.T) {
	prefixes := SetupLeftoverPrefixes()
	const capability = "0123456789abcdef0123456789abcdef"
	for name, want := range map[string]bool{
		SetupStagePrefix + capability:                         true,
		SetupPowerShellTempPrefix + capability:                true,
		SetupInstallerStagePrefix + capability:                true,
		SetupStagePrefix + capability[:31]:                    false,
		SetupStagePrefix + capability + "0":                   false,
		SetupStagePrefix + "0123456789ABCDEF0123456789ABCDEF": false,
		SetupStagePrefix + "0123456789abcdef0123456789abcdeg": false,
		"DefenseClaw-Other-" + capability:                     false,
		"defenseclaw-enterprise-setup-" + capability:          false,
		"": false,
	} {
		if got := IsSetupLeftoverName(name, prefixes); got != want {
			t.Fatalf("IsSetupLeftoverName(%q) = %t, want %t", name, got, want)
		}
	}
	if IsSetupLeftoverName(SetupStagePrefix+capability, []string{SetupPowerShellTempPrefix}) {
		t.Fatal("a prefix outside the requested set matched")
	}
}

func TestSetupLeftoverExpiredUsesNewestTimestamp(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	old := now.Add(-SetupLeftoverMaxAge - time.Minute)
	young := now.Add(-time.Hour)
	if !SetupLeftoverExpired(old, old, now) {
		t.Fatal("a leftover older than the maximum run was not expired")
	}
	if SetupLeftoverExpired(old, young, now) {
		t.Fatal("a stage still being written to was expired by its creation time")
	}
	if SetupLeftoverExpired(young, young, now) {
		t.Fatal("a young stage was expired")
	}
	if SetupLeftoverExpired(time.Time{}, time.Time{}, now) {
		t.Fatal("unknown timestamps expired a stage")
	}
	if SetupLeftoverMaxAge <= 2*time.Hour {
		t.Fatalf("max age %s does not exceed the 2 h lifecycle timeout", SetupLeftoverMaxAge)
	}
}

func TestIsBenignFileReparseTag(t *testing.T) {
	for tag, want := range map[uint32]bool{
		0x80000017: true,  // WOF
		0x80000013: true,  // dedup
		0x80000023: true,  // AF_UNIX
		0x9000001A: true,  // cloud files
		0x9000101A: true,  // cloud files variant
		0x9000F01A: true,  // cloud files variant
		0xA000000C: false, // symbolic link
		0xA0000003: false, // mount point
		0x8000001B: false, // app exec link
		0x00000000: false,
		0x9000001B: false,
	} {
		if got := IsBenignFileReparseTag(tag); got != want {
			t.Fatalf("IsBenignFileReparseTag(0x%08x) = %t, want %t", tag, got, want)
		}
	}
}
