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

//go:build !windows

package cli

import (
	"os"
	"syscall"
)

// sidecarSignals returns the set of OS signals the sidecar should listen for.
// On Unix we include SIGHUP, SIGQUIT, SIGPIPE, and optionally USR1/USR2 for
// the diagnostic mode.
func sidecarSignals(diag bool) []os.Signal {
	if diag {
		return []os.Signal{
			syscall.SIGINT, syscall.SIGTERM,
			syscall.SIGHUP, syscall.SIGQUIT,
			syscall.SIGPIPE, syscall.SIGUSR1, syscall.SIGUSR2,
		}
	}
	return []os.Signal{
		syscall.SIGINT, syscall.SIGTERM,
		syscall.SIGHUP, syscall.SIGQUIT,
		syscall.SIGPIPE,
	}
}

// isSigPipe reports whether sig is SIGPIPE.
func isSigPipe(sig os.Signal) bool {
	s, ok := sig.(syscall.Signal)
	return ok && s == syscall.SIGPIPE
}
