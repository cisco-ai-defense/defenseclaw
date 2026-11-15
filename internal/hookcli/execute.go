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

// Package hookcli is the agent-facing hook command tree: hook, hook-post and
// notify. The gateway binary (internal/cli) registers the same commands, and
// the slim defenseclaw-hook binary runs them through Execute without linking
// the gateway, its servers or its stores.
package hookcli

import (
	"context"
	"errors"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// rootName is the command name cobra prints in usage lines and errors. The
// hook commands ran under the gateway root before the slim binary existed,
// so their help and usage errors keep naming it.
const rootName = "defenseclaw-gateway"

// usageExempt lists the command trees whose flag and argument errors keep
// their own exit status (an agent hook answers with its connector status).
var usageExempt = []string{"hook", "notify"}

// Execute runs the hook command tree of defenseclaw-hook and returns the
// process exit code. It applies what the gateway root applies to these
// commands: the build version, the Secure Client command tree, the usage
// errors of hook-post and the exit codes failures carry.
func Execute(buildVersion string) int {
	version.SetBinaryVersion(buildVersion)
	root := NewRoot()
	return ExitCodeOf(root.ExecuteContext(context.Background()))
}

// NewRoot builds the slim root command with the hook, hook-post and notify
// commands.
func NewRoot() *cobra.Command {
	root := &cobra.Command{Use: rootName, SilenceUsage: true}
	root.AddCommand(NewHookCmd(), NewHookPostCmd(), NewNotifyCmd())
	root.SetFlagErrorFunc(flagError)
	if SecureClientHost() {
		RemoveSecureClientAbsentCommands(root)
	}
	for _, c := range root.Commands() {
		if c.Name() == "hook-post" {
			// A stray argument is a usage error, as on every gateway
			// command outside the hook trees (GAP-1549).
			c.Args = cliusage.UnexpectedArgs
		}
	}
	return root
}

// RemoveSecureClientAbsentCommands removes the commands that a Secure Client
// host does not have (SecureClientAbsentAnnotation) from the tree of root.
func RemoveSecureClientAbsentCommands(root *cobra.Command) {
	for _, c := range root.Commands() {
		if c.Annotations[SecureClientAbsentAnnotation] != "" {
			root.RemoveCommand(c)
			continue
		}
		RemoveSecureClientAbsentCommands(c)
	}
}

// flagError turns a flag error into a usage error with exit status 2,
// except in the hook and notify trees, which keep their own status and only
// name a bad flag value plainly (GAP-1405, GAP-1989).
func flagError(c *cobra.Command, err error) error {
	if c == nil || err == nil {
		return err
	}
	fields := strings.Fields(c.CommandPath())
	for _, f := range fields[min(1, len(fields)):] {
		for _, exempt := range usageExempt {
			if f == exempt {
				if plain := cliusage.PlainFlagValueError(err); plain != err.Error() {
					return &cliusage.DelegatedUsageError{Msg: plain, Err: err}
				}
				return err
			}
		}
	}
	return cliusage.UsageError(c, err)
}

// ExitCodeOf is the process exit code of a command result: 0 for success
// and for cancellation, the code a failure chose, and 1 otherwise.
func ExitCodeOf(err error) int {
	if err == nil || errors.Is(err, context.Canceled) {
		return 0
	}
	return cliusage.ExitCode(err)
}
