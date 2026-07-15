// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package processutil creates noninteractive subprocesses whose standard
// streams are captured by DefenseClaw.
package processutil

import (
	"context"
	"os/exec"
)

// CommandContext is equivalent to exec.CommandContext with platform-specific
// configuration for a captured background process.
func CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	configureCapturedCommand(cmd)
	return cmd
}

// CombinedOutputTree runs cmd inside a platform-managed process-tree lifetime
// boundary. On Windows, cancellation and command completion terminate every
// non-breakaway descendant through a kill-on-close Job Object.
//
// allowManagedBreakaway is reserved for trusted launchers whose separately
// identity-checked daemon must intentionally survive the short-lived command.
func CombinedOutputTree(cmd *exec.Cmd, allowManagedBreakaway bool) ([]byte, error) {
	return combinedOutputTree(cmd, allowManagedBreakaway)
}
