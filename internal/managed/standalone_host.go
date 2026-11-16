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
	"sync/atomic"
)

// standaloneLifecycleProcess is set by a process that runs a standalone
// Windows lifecycle action (Setup, which runs the lifecycle from a staged
// copy of the CLI, or the installed CLI). Such a process carries no service
// pin and does not sit in the install root, so StandaloneTrustScope and
// WindowsStandaloneInstallExecutable alone judged it by the Secure Client
// rules, and its in-place repairs (the runtime folder, the hook runtime
// folder) restored the access list over what an untrusted account had
// written (GAP-0651). It widens only StandaloneRefusesContentDrift.
var standaloneLifecycleProcess atomic.Bool

// MarkStandaloneLifecycleProcess records that this process runs a standalone
// Windows lifecycle action, so it refuses an in-place repair of a managed
// file or folder another account can write or owns, as the guardian does.
func MarkStandaloneLifecycleProcess() { standaloneLifecycleProcess.Store(true) }

// UnmarkStandaloneLifecycleProcess ends MarkStandaloneLifecycleProcess when
// the lifecycle action returns, so a test binary that runs several actions
// does not carry the mark into the next.
func UnmarkStandaloneLifecycleProcess() { standaloneLifecycleProcess.Store(false) }

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
