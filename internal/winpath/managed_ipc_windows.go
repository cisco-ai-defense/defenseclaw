// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package winpath

import "path/filepath"

// ManagedIPCRelativeDir is where managed-enterprise local IPC sockets live,
// relative to the trusted Program Files root.
var ManagedIPCRelativeDir = filepath.Join(
	"Cisco", "Cisco Secure Client", "DefenseClaw", "ipc",
)

// ManagedIPCDir is the trusted directory local IPC sockets bind in.
//
// It lives in this leaf package because more than one component needs it
// and the alternative is a second copy. That directory, not the socket
// filename, is the access boundary: its DACL is applied at bind time and
// its parent chain is checked for reparse points. A caller that
// reconstructed the path from %ProgramData% would land outside it and be
// refused, for reasons that look nothing like the mistake.
//
// Returns "" when the trusted root cannot be resolved. A caller must treat
// that as "no managed location", never as licence to improvise one.
func ManagedIPCDir() string {
	programFiles, err := TrustedProgramFiles()
	if err != nil || programFiles == "" {
		return ""
	}
	return filepath.Clean(filepath.Join(programFiles, ManagedIPCRelativeDir))
}
