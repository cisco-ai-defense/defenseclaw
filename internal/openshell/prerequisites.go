// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"encoding/json"
	"fmt"
)

// The prerequisite record. On a standalone managed host the enterprise
// lifecycle checks what the install mode needs for sandboxes to run (OpenShell,
// its MicroVM driver, e2fsprogs, Docker or /dev/kvm) and publishes the result
// as a public, non-secret, root-owned file so the gateway, which runs as a
// service account, can say why a run that needs a sandbox cannot get one
// (openshell_prerequisite_missing) without running any of the checks itself.

const (
	// PrerequisitesFile is the record's name in <ConfigDir>/openshell.
	PrerequisitesFile = "prerequisites.json"
	// PrerequisitesVersion is the schema version of the record.
	PrerequisitesVersion = 1
)

// PrerequisitesRecord is <ConfigDir>/openshell/prerequisites.json.
type PrerequisitesRecord struct {
	Version int `json:"version"`
	// CheckedAt is when the lifecycle last checked, RFC 3339 UTC.
	CheckedAt string `json:"checked_at"`
	// Install and Driver are the enterprise.openshell settings it checked.
	Install string `json:"install"`
	Driver  string `json:"driver"`
	// Ready is true when nothing is missing.
	Ready   bool                  `json:"ready"`
	Missing []PrerequisiteMissing `json:"missing,omitempty"`
	// Fallback is the docker fallback's readiness, when the lifecycle
	// checked one: Linux, driver vm or auto, driver_fallback docker. Ready
	// and Missing above are then the MicroVM driver's.
	Fallback *PrerequisitesFallback `json:"fallback,omitempty"`
}

// PrerequisitesFallback is the readiness of the fallback driver.
type PrerequisitesFallback struct {
	Driver  string                `json:"driver"`
	Ready   bool                  `json:"ready"`
	Missing []PrerequisiteMissing `json:"missing,omitempty"`
}

// PrerequisiteMissing is one prerequisite the host lacks, with what the
// administrator runs or sets.
type PrerequisiteMissing struct {
	Item   string `json:"item"`
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
	// Version is the release an OpenShell part (openshell cli, openshell
	// gateway, microvm driver) is installed in when that release is
	// refused: the gateway then says it is installed and unsupported, or
	// not the pinned release, rather than not installed (GAP-0266). Empty
	// for other items and for a part that is missing.
	Version string `json:"version,omitempty"`
}

// ReadPrerequisites reads the record at path. Like the rendered gateway
// configuration it must be a regular file owned by root and writable by no
// one else, in a directory that is too: a record anyone could write would let
// an account mark a host ready. A missing file is a nil record and no error
// (the lifecycle has not published one).
func ReadPrerequisites(path string) (*PrerequisitesRecord, error) {
	data, _, err := readRenderedFile(path)
	if err != nil || data == nil {
		return nil, err
	}
	var record PrerequisitesRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("openshell: parse %s: %w", path, err)
	}
	if record.Version != PrerequisitesVersion {
		return nil, fmt.Errorf("openshell: %s has version %d, want %d", path, record.Version, PrerequisitesVersion)
	}
	return &record, nil
}
