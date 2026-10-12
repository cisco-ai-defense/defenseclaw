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

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
)

// `sandbox setup` on a managed computer ran the per-user setup (Docker group
// advice, an OpenShell install); the organization sets sandboxes up, so it
// answers so and changes nothing (GAP-0249).
func TestSandboxSetupAnswersOnAManagedComputer(t *testing.T) {
	restore := newSandboxApp
	t.Cleanup(func() { newSandboxApp = restore })
	newSandboxApp = func(cmd *cobra.Command) *sandboxcli.App {
		return &sandboxcli.App{Cfg: managedSandboxCommandConfig(), IO: sandboxcli.IO{Out: cmd.OutOrStdout(), Err: cmd.ErrOrStderr()}}
	}
	command := newSandboxSetupCmd()
	command.SilenceUsage = true
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs(nil)
	err := command.Execute()
	var coded *exitCodeError
	if !errors.As(err, &coded) || coded.ExitCode() != 3 {
		t.Fatalf("setup = %v, want exit 3", err)
	}
	if !strings.Contains(stderr.String(), "your organization sets up sandboxes on this computer") || strings.Contains(stderr.String(), "Docker") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("setup printed %q before refusing", stdout.String())
	}
}
