// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

// Values of OpenShellCapability.DriverAvailable.
const (
	OpenShellDriverVM     = "vm"
	OpenShellDriverDocker = "docker"
	OpenShellDriverNone   = "none"
)

// Reason codes of an OpenShellCapability that the sandbox rows do not
// carry themselves.
const (
	CodeOpenShellDisabled   = "openshell_disabled"
	CodePlatformUnsupported = "platform_unsupported"
)

// OpenShellCapability is the openshell block: whether users on this host can
// run DefenseClaw sandboxes, and on which driver. Codes and a version only;
// the sandbox rows' details (which name paths) are never copied.
type OpenShellCapability struct {
	// Enabled is enterprise.openshell.enabled as last applied.
	Enabled bool `json:"enabled"`
	// Install is prerequisite or setup; absent when disabled.
	Install string `json:"install,omitempty"`
	// Installed (prerequisite mode): the administrator's OpenShell parts
	// are present and pass the root-owned trust check. Absent in setup mode,
	// where each user installs it on first use, and when disabled.
	Installed *bool `json:"installed,omitempty"`
	// Version is the one release every part reports (prerequisite) or the
	// pinned release (setup); absent when unknown or the parts disagree.
	Version string `json:"version,omitempty"`
	// Driver is the configured driver: vm, docker or auto.
	Driver string `json:"driver,omitempty"`
	// DriverAvailable is the driver users get now: vm, docker (the docker
	// driver, or the docker fallback of the MicroVM driver) or none.
	DriverAvailable string `json:"driver_available"`
	// ReasonCode says why DriverAvailable is not the configured driver, or
	// is none; absent when everything is ready.
	ReasonCode string `json:"reason_code,omitempty"`
}

// OpenShellDisabledCapability is the block of a host whose sandboxes are off.
func OpenShellDisabledCapability() *OpenShellCapability {
	return &OpenShellCapability{DriverAvailable: OpenShellDriverNone, ReasonCode: CodeOpenShellDisabled}
}

// OpenShellUnsupportedCapability is the block of a platform without
// enterprise OpenShell (Windows): its presence says this build reports it.
func OpenShellUnsupportedCapability() *OpenShellCapability {
	return &OpenShellCapability{DriverAvailable: OpenShellDriverNone, ReasonCode: CodePlatformUnsupported}
}
