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

// Package cliusage holds the exit-code and usage-error shapes the gateway
// command tree (internal/cli) and the slim hook binary (internal/hookcli)
// share. It imports cobra and pflag only, so the hook binary stays light.
package cliusage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// ExitCodeError carries the process exit code a command needs the shell to
// see. Windows deployment systems act on the exact code, so a command that
// chooses one must not be flattened to the generic failure result.
type ExitCodeError struct {
	code int
	err  error
}

func (e *ExitCodeError) Error() string { return e.err.Error() }

func (e *ExitCodeError) Unwrap() error { return e.err }

func (e *ExitCodeError) ExitCode() int { return e.code }

// WithExitCode labels a failure with an exit code, leaving a code an inner
// failure already chose in place.
func WithExitCode(err error, code int) error {
	if err == nil {
		return nil
	}
	var coded *ExitCodeError
	if errors.As(err, &coded) {
		return err
	}
	return &ExitCodeError{code: code, err: err}
}

// UsageError adds the usage line and a --help pointer to err and gives it
// exit status 2, the shape and status the Python defenseclaw CLI uses.
func UsageError(c *cobra.Command, err error) error {
	return WithExitCode(&DelegatedUsageError{Msg: UsageMessage(c, err), Err: err}, 2)
}

// UsageMessage is err with the command's usage line and the --help pointer.
func UsageMessage(c *cobra.Command, err error) string {
	named := func(text string) string { return InvokedCommandText(c, text) }
	use := named(c.UseLine())
	if c.HasAvailableSubCommands() {
		// Show the subcommand form too, as --help does (GAP-1622).
		group := named(c.CommandPath()) + " [command]"
		if c.Runnable() {
			use += "\n       " + group
		} else {
			use = group
		}
	}
	msg := fmt.Sprintf("%s\nUsage: %s\nTry '%s --help' for help.", PlainFlagValueError(err), use, named(c.CommandPath()))
	return DelegatedCommandText(c, msg)
}

// InvokedCommandText names the gateway binary in a command hint as it was
// run, so the hint runs as typed (GAP-2189, GAP-2240). text starts with the
// root command name, as c.CommandPath() and c.UseLine() do.
func InvokedCommandText(c *cobra.Command, text string) string {
	root := c.Root().Name()
	invoked := InvokedGatewayPath(root)
	if invoked == "" || os.Getenv(DelegatedFromEnv) == "defenseclaw" || !strings.HasPrefix(text, root) {
		return text
	}
	return invoked + strings.TrimPrefix(text, root)
}

// InvokedGatewayPath is the absolute path the gateway binary was run by,
// when it was run by one, so a usage hint runs as typed: the enterprise rpm
// installs only /opt/defenseclaw/bin, which is not on root's PATH, and a
// bare "defenseclaw-gateway ... --help" was "command not found" (GAP-2189).
// A seam for tests.
var InvokedGatewayPath = func(rootName string) string {
	if runtime.GOOS == "windows" || len(os.Args) == 0 {
		return ""
	}
	arg0 := os.Args[0]
	if !strings.ContainsRune(arg0, '/') || filepath.Base(arg0) != rootName {
		// A bare name was found on PATH, so it runs as typed.
		return ""
	}
	if !filepath.IsAbs(arg0) {
		// "./defenseclaw-gateway" from /opt/defenseclaw/bin: name the
		// absolute path, which runs from any directory (GAP-2232).
		abs, err := filepath.Abs(arg0)
		if err != nil {
			return ""
		}
		arg0 = abs
	}
	if strings.ContainsAny(arg0, " '\"\\$`") {
		return ""
	}
	return arg0
}

// PlainFlagValueError names what a typed flag takes instead of pflag's
// parser text ('invalid argument "maybe" for "--json" flag:
// strconv.ParseBool: parsing "maybe": invalid syntax'): '--json takes true
// or false, not "maybe"' (GAP-1989).
func PlainFlagValueError(err error) string {
	var invalid *pflag.InvalidValueError
	if !errors.As(err, &invalid) || invalid.GetFlag() == nil {
		return err.Error()
	}
	takes := ""
	if t, ok := invalid.GetFlag().Value.(interface{ FlagTakes() string }); ok {
		// A flag with a narrower range says so (GAP-2329: "1h" was the
		// example and the 15m cap of --lock-wait then refused it).
		return fmt.Sprintf("--%s takes %s, not %q", invalid.GetFlag().Name, t.FlagTakes(), invalid.GetValue())
	}
	switch invalid.GetFlag().Value.Type() {
	case "bool":
		takes = "true or false"
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "count":
		takes = "a whole number"
	case "float32", "float64":
		takes = "a number"
	case "duration":
		takes = "a duration such as 30s, 5m or 1h"
	default:
		return err.Error()
	}
	return fmt.Sprintf("--%s takes %s, not %q", invalid.GetFlag().Name, takes, invalid.GetValue())
}

// DelegatedFromEnv is set by the Python CLI when it runs a gateway command on
// the user's behalf: 'defenseclaw audit export' runs 'defenseclaw-gateway
// audit export'. Usage errors then name the command the user typed
// (GAP-1644). Only the value "defenseclaw" is honored.
const DelegatedFromEnv = "DEFENSECLAW_DELEGATED_FROM"

// DelegatedCommandText replaces the gateway binary name in text with
// "defenseclaw" when the Python CLI delegated the command.
func DelegatedCommandText(c *cobra.Command, text string) string {
	if os.Getenv(DelegatedFromEnv) != "defenseclaw" {
		return text
	}
	return strings.ReplaceAll(text, c.Root().Name()+" ", "defenseclaw ")
}

// DelegatedUsageError keeps the wrapped error for errors.Is/As while its
// text may name the delegating command.
type DelegatedUsageError struct {
	Msg string
	Err error
}

func (e *DelegatedUsageError) Error() string { return e.Msg }
func (e *DelegatedUsageError) Unwrap() error { return e.Err }

// UnexpectedArgs rejects positional arguments on a command that takes none
// (GAP-1549): "status extra-arg" ran status and "watchdog bogus" started the
// foreground watchdog.
func UnexpectedArgs(c *cobra.Command, args []string) error {
	if err := StrayArgumentError(c, args); err != nil {
		return UsageError(c, err)
	}
	return nil
}

// StrayArgumentError is the bare error for positional arguments on a command
// that takes none: "unexpected argument" on a leaf, "unknown command" on a
// group. cobra.NoArgs said "unknown command" on a leaf too (GAP-2330).
func StrayArgumentError(c *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	kind := "unexpected argument"
	if c.HasSubCommands() {
		kind = "unknown command"
	}
	return fmt.Errorf("%s %q for %q%s", kind, args[0], c.CommandPath(), DidYouMean(c, args[0]))
}

// DidYouMean is the "Did you mean X?" line for a mistyped subcommand of c,
// or "". cobra.SuggestionsFor treats an unset minimum distance as 0, so only
// prefixes matched and "acp verfy" got no suggestion; cobra itself defaults
// it to 2 (GAP-2374).
func DidYouMean(c *cobra.Command, typed string) string {
	if c.DisableSuggestions {
		return ""
	}
	if c.SuggestionsMinimumDistance <= 0 {
		c.SuggestionsMinimumDistance = 2
	}
	suggestions := c.SuggestionsFor(typed)
	if len(suggestions) == 0 {
		return ""
	}
	return "\nDid you mean " + strings.Join(suggestions, " or ") + "?"
}

// ExitCode reports the exit code a failure asked for, defaulting to the
// generic failure result.
func ExitCode(err error) int {
	var coded *ExitCodeError
	if errors.As(err, &coded) {
		return coded.ExitCode()
	}
	return 1
}
