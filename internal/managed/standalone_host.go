// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

package managed

import (
	"os"
	"runtime"
)

// IsStandaloneManagedHost reports whether this computer is a standalone
// managed deployment: the administrator-owned public runtime descriptor
// exists. It is false wherever the descriptor is absent (every OSS computer)
// and on platforms with no descriptor path. The sandbox CLI and the daemon's
// port-holder text both ask this one question to decide what a user may be
// told about other accounts.
func IsStandaloneManagedHost() bool {
	layout, err := StandaloneLayoutFor(runtime.GOOS)
	if err != nil || layout.DescriptorPath == "" {
		return false
	}
	_, statErr := os.Stat(layout.DescriptorPath)
	return statErr == nil
}

// StandaloneTrustScope reports whether this process judges managed trust
// by the standalone profile's rules: its service environment pins the
// standalone profile, or this computer carries the standalone runtime
// descriptor. The macOS drift handling of the Secure Client profile
// (permission drift accepted and logged, root services repairing their own
// objects in place, `/` and `/opt` as advisory ancestors, ACL entries for
// root, wheel and admin) stays outside that scope, so a standalone install
// keeps its strict verdicts.
func StandaloneTrustScope() bool {
	return IsStandaloneProfile(os.Getenv(EnterpriseProfileEnv)) || IsStandaloneManagedHost()
}
