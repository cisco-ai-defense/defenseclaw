// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package acquire

import (
	"os"
	"path/filepath"
	"runtime"

	winpath "github.com/defenseclaw/defenseclaw/internal/winpath"
)

// SocketFileName is the sensor helper's socket, kept distinct from the UI
// IPC socket so the two access boundaries never share a file.
const SocketFileName = "sensor-helper.sock"

// SocketEnvVar overrides the socket path. Honoured only outside managed
// deployments: in a managed install the path is part of what the installer
// owns, and letting the environment move it would let whoever controls the
// gateway's environment point it at a socket they serve.
const SocketEnvVar = "DEFENSECLAW_SENSOR_HELPER_SOCKET"

// DefaultSocketPath is where the helper listens and the gateway dials.
//
// It sits beside the data directory rather than in a world-writable temp
// path, because the directory's own permissions are half the access control
// and /tmp offers none.
func DefaultSocketPath(dataDir string, managedEnterprise bool) string {
	if !managedEnterprise {
		if override := os.Getenv(SocketEnvVar); override != "" {
			return override
		}
	}
	if managedEnterprise {
		switch runtime.GOOS {
		case "linux":
			return filepath.Join("/run", "defenseclaw", SocketFileName)
		case "darwin":
			return filepath.Join("/var", "run", "defenseclaw", SocketFileName)
		case "windows":
			// The trusted managed IPC directory, resolved the same way the
			// UI IPC socket resolves it. Guessing at ProgramData would
			// place the socket outside the directory whose DACL and
			// reparse checks are the entire access boundary, and the bind
			// would be refused -- correctly, and confusingly.
			if managed := winpath.ManagedIPCDir(); managed != "" {
				return filepath.Join(managed, SocketFileName)
			}
			return ""
		}
	}
	if dataDir == "" {
		dataDir = "."
	}
	return filepath.Join(dataDir, "ipc", SocketFileName)
}
