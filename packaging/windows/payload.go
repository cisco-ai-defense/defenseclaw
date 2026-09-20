// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

// Package windowspayload carries the Windows machine-lifecycle PowerShell
// sources inside the binary so a release that ships one defenseclaw.exe can
// install, verify, and remove a deployment with no libexec directory beside it.
package windowspayload

// The entry script resolves its module by this name from its own directory, so
// the two files must always be written out together.
const (
	InstallerName = "install-enterprise.ps1"
	ModuleName    = "DefenseClawEnterprise.psm1"
)

// Available reports whether this build carries the payload. Only Windows
// binaries do; every other platform links the empty variant.
func Available() bool {
	return len(installer) > 0 && len(module) > 0
}

// Installer returns the lifecycle entry script.
func Installer() []byte {
	return append([]byte(nil), installer...)
}

// Module returns the module the entry script imports.
func Module() []byte {
	return append([]byte(nil), module...)
}
