// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// enterpriseSetupDiskSpaceMargin covers the journal, logs, configuration and
// other small files written around the payload.
const enterpriseSetupDiskSpaceMargin = 256 << 20

// enterpriseSetupFreeDiskBytes reports the free space of the volume holding
// dir; ok is false where it is unknown. Replaceable in tests.
var enterpriseSetupFreeDiskBytes = platformFreeDiskBytes

// enterpriseSetupSpaceNeeded bounds what one Setup run writes: every action
// stages the payload, and an action that installs or changes the deployment
// also copies it into InstallRoot and keeps the release it replaces for
// rollback.
func enterpriseSetupSpaceNeeded(payload enterprisePayload, action string) uint64 {
	var size uint64
	for _, file := range payload.Files {
		if file.Size > 0 {
			size += uint64(file.Size)
		}
	}
	copies := uint64(1)
	if enterpriseSetupMutation(action, payload.Standalone()) {
		copies = 3
	}
	return size*copies + enterpriseSetupDiskSpaceMargin
}

// requireEnterpriseSetupFreeSpace refuses, before Setup stages anything,
// when the volume holding dir has less free space than the run needs. Setup
// used to fail with 1603 deep in the lifecycle on a nearly full disk
// (GAP-1070). When the free space is unknown, Setup goes ahead.
func requireEnterpriseSetupFreeSpace(dir string, payload enterprisePayload, action string) error {
	probe := nearestExistingEnterpriseSetupDir(dir)
	free, ok, err := enterpriseSetupFreeDiskBytes(probe)
	if err != nil || !ok {
		return nil
	}
	need := enterpriseSetupSpaceNeeded(payload, action)
	if free >= need {
		return nil
	}
	volume := filepath.VolumeName(probe)
	if volume == "" {
		volume = probe
	}
	return fmt.Errorf("not enough free disk space to %s: %s has %d MB free and about %d MB is needed; free some space and run Setup again",
		action, volume, free>>20, (need+(1<<20)-1)>>20)
}

func nearestExistingEnterpriseSetupDir(dir string) string {
	dir = filepath.Clean(dir)
	for {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return dir
		}
		dir = parent
	}
}
