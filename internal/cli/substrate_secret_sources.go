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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"github.com/defenseclaw/defenseclaw/internal/substrate/reasons"
)

// substrateSecretMaxBytes is the largest value the gateway takes (56 KiB,
// reason value_required); a source that gives more is refused here.
const substrateSecretMaxBytes = 56 << 10

var (
	// substrateSourceGOOS is runtime.GOOS; tests change it to reach the
	// macOS-only keychain source on any platform.
	substrateSourceGOOS = runtime.GOOS
	// substrateSourceTimeout bounds every source tool (gh, op, security).
	substrateSourceTimeout = 15 * time.Second
)

// substrateSecretSource is the one set of value-source flags of the
// secrets commands that store a value (set, and add). Exactly one source
// may be given; none means the no-echo terminal prompt. A value never
// travels on a command line: the tools get only a host, a service or an
// op:// reference in their arguments and answer on their standard output,
// which is read into memory and never printed or logged.
type substrateSecretSource struct {
	fromGH          bool
	ghHost          string
	keychain        string
	keychainAccount string
	op              string
	file            string
	stdin           bool
	env             string
}

// substrateSourceTool is one optional external tool a source runs.
type substrateSourceTool struct {
	bin  string // looked up on PATH
	name string // what a person calls it
	flag string
	fix  string // how to get it
	goos string // "" = every platform
}

var (
	substrateToolGH = substrateSourceTool{bin: "gh", name: "the GitHub CLI (gh)", flag: "--from-gh",
		fix: "Install it from https://cli.github.com and sign in with: gh auth login"}
	substrateToolOP = substrateSourceTool{bin: "op", name: "the 1Password CLI (op)", flag: "--from-op",
		fix: "Install it from https://developer.1password.com/docs/cli and sign in with: op signin"}
	substrateToolKeychain = substrateSourceTool{bin: "security", name: "the macOS security tool", flag: "--from-keychain",
		fix: "It is part of macOS at /usr/bin/security; put /usr/bin on PATH", goos: "darwin"}
	substrateSourceTools = []substrateSourceTool{substrateToolGH, substrateToolOP, substrateToolKeychain}
)

func (s *substrateSecretSource) add(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVar(&s.fromGH, "from-gh", false, "read the value from the GitHub CLI's sign-in (gh auth token)")
	f.StringVar(&s.ghHost, "gh-host", "", "with --from-gh: the GitHub host to read the sign-in of (default: gh's own)")
	f.StringVar(&s.keychain, "from-keychain", "", "read the value from this macOS keychain item (its service name)")
	f.StringVar(&s.keychainAccount, "account", "", "with --from-keychain: the item's account")
	f.StringVar(&s.op, "from-op", "", "read the value from 1Password (op://vault/item/field)")
	f.StringVar(&s.file, "from-file", "", "read the value from this file")
	f.BoolVar(&s.stdin, "stdin", false, "read the value from standard input")
	f.StringVar(&s.env, "from-env", "", "read the value from this environment variable")
}

// substrateSourceHelp is the source paragraph of a command's long help.
const substrateSourceHelp = `The value comes from exactly one source: the terminal without echo (no flag), --from-gh (the
GitHub CLI's sign-in), --from-keychain SERVICE (macOS keychain), --from-op op://vault/item/field
(1Password CLI), --from-file PATH, --stdin or --from-env VAR. It is never put on a command line
and never printed.`

// read returns the value and the source kind (prompt, gh, keychain,
// 1password, file, stdin, env).
func (s *substrateSecretSource) read(cmd *cobra.Command) (string, string, error) {
	n := 0
	for _, on := range []bool{s.fromGH, s.keychain != "", s.op != "", s.file != "", s.stdin, s.env != ""} {
		if on {
			n++
		}
	}
	if n > 1 {
		return "", "", cliusage.UsageError(cmd, errors.New("use one source: give only one of --from-gh, --from-keychain, --from-op, --from-file, --stdin, --from-env"))
	}
	if s.ghHost != "" && !s.fromGH {
		return "", "", cliusage.UsageError(cmd, errors.New("--gh-host goes with --from-gh"))
	}
	if s.keychainAccount != "" && s.keychain == "" {
		return "", "", cliusage.UsageError(cmd, errors.New("--account goes with --from-keychain"))
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	switch {
	case s.fromGH:
		args := []string{"auth", "token"}
		if s.ghHost != "" {
			if strings.HasPrefix(s.ghHost, "-") || strings.ContainsAny(s.ghHost, " /\t") {
				return "", "", cliusage.UsageError(cmd, fmt.Errorf("--gh-host %q is not a host name", s.ghHost))
			}
			args = append(args, "--hostname", s.ghHost)
		}
		v, err := runSubstrateSourceTool(ctx, substrateToolGH, args...)
		return v, "gh", err
	case s.keychain != "":
		if substrateSourceGOOS != "darwin" {
			return "", "", substrateSourceErr("secret_source_unsupported", "--from-keychain reads the macOS keychain, and this computer is not a Mac")
		}
		args := []string{"find-generic-password", "-s", s.keychain}
		if s.keychainAccount != "" {
			args = append(args, "-a", s.keychainAccount)
		}
		v, err := runSubstrateSourceTool(ctx, substrateToolKeychain, append(args, "-w")...)
		return v, "keychain", err
	case s.op != "":
		if !strings.HasPrefix(s.op, "op://") || strings.Count(strings.TrimPrefix(s.op, "op://"), "/") < 2 {
			return "", "", cliusage.UsageError(cmd, fmt.Errorf("--from-op needs a secret reference op://vault/item/field, not %q", safetext.Line(s.op)))
		}
		v, err := runSubstrateSourceTool(ctx, substrateToolOP, "read", "--no-newline", s.op)
		return v, "1password", err
	case s.file != "":
		v, err := readSubstrateSecretFile(s.file)
		return v, "file", err
	case s.stdin:
		b, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), substrateSecretMaxBytes+1))
		if err != nil {
			return "", "", err
		}
		v, err := substrateSourceValue(string(b), "standard input")
		return v, "stdin", err
	case s.env != "":
		v := os.Getenv(s.env)
		if v == "" {
			return "", "", fmt.Errorf("the environment variable %s is empty or not set", s.env)
		}
		return v, "env", nil
	case term.IsTerminal(int(os.Stdin.Fd())):
		fmt.Fprint(cmd.ErrOrStderr(), "Secret value (not shown): ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			return "", "", err
		}
		if len(b) == 0 {
			return "", "", errors.New("no value entered")
		}
		return string(b), "prompt", nil
	}
	return "", "", errors.New("give the value with a source flag, for example --stdin or --from-file PATH (there is no terminal to ask on)")
}

// substrateSourceErr is a launcher refusal worded from the reason table:
// the detail, the code and the fix.
func substrateSourceErr(code, detail string) error {
	r, _ := reasons.Lookup(reasons.Must(code))
	return fmt.Errorf("%s (%s). %s", detail, r.Code, r.Fix)
}

// substrateSourceValue trims one trailing line end and checks the size.
func substrateSourceValue(v, from string) (string, error) {
	if len(v) > substrateSecretMaxBytes {
		return "", fmt.Errorf("the value from %s is over 56 KiB", from)
	}
	v = strings.TrimRight(v, "\r\n")
	if v == "" {
		return "", fmt.Errorf("%s gave no value", from)
	}
	return v, nil
}

func readSubstrateSecretFile(path string) (string, error) {
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, rest)
		}
	}
	shown := safetext.Path(path)
	st, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", shown, errors.Unwrap(err))
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", shown)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", shown, errors.Unwrap(err))
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, substrateSecretMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", shown, err)
	}
	return substrateSourceValue(string(b), shown)
}

// cappedBuffer keeps the first max bytes written and counts the rest, so a
// tool that floods its output cannot grow the launcher's memory.
type cappedBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room < len(p) {
		c.over = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

// runSubstrateSourceTool runs a source tool with no standard input and a
// timeout, and returns what it printed on standard output. Its arguments
// hold no value (a host, a service name or an op:// reference). What it
// prints on standard error is shown only when it fails, one line, cleaned,
// with anything it also printed on standard output removed.
func runSubstrateSourceTool(ctx context.Context, tool substrateSourceTool, args ...string) (string, error) {
	path, err := exec.LookPath(tool.bin)
	if err != nil {
		return "", fmt.Errorf("%s is not installed or not on PATH, so %s cannot read the value (%s). %s, or give the value another way (--from-file, --stdin or the prompt)",
			tool.name, tool.flag, reasons.Must("secret_source_tool_missing"), tool.fix)
	}
	ctx, cancel := context.WithTimeout(ctx, substrateSourceTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, path, args...)
	c.Stdin = nil // the null device: a tool that wants to ask fails instead of waiting
	out := &cappedBuffer{max: substrateSecretMaxBytes + 1}
	errOut := &cappedBuffer{max: 4 << 10}
	c.Stdout, c.Stderr = out, errOut
	c.WaitDelay = 2 * time.Second
	runErr := c.Run()
	value := out.buf.String()
	if ctx.Err() == context.DeadlineExceeded {
		return "", substrateSourceErr("secret_source_failed", fmt.Sprintf("%s did not answer within %s", tool.name, substrateSourceTimeout))
	}
	if runErr != nil {
		line := strings.TrimSpace(errOut.buf.String())
		if i := strings.IndexByte(line, '\n'); i >= 0 {
			line = line[:i]
		}
		if v := strings.TrimSpace(value); v != "" {
			line = strings.ReplaceAll(line, v, "[value]")
		}
		if line = safetext.Line(line); len(line) > 200 {
			line = line[:200] + "..."
		}
		detail := tool.name + " did not give a value"
		if line != "" {
			detail += ": " + line
		}
		return "", substrateSourceErr("secret_source_failed", detail)
	}
	if out.over {
		return "", fmt.Errorf("the value from %s is over 56 KiB", tool.name)
	}
	v, err := substrateSourceValue(value, tool.name)
	if err != nil {
		return "", substrateSourceErr("secret_source_failed", err.Error())
	}
	return v, nil
}

// doctorSecretSources adds one row per optional source tool: found, or
// not installed with how to get it. A missing tool is not a failure.
func doctorSecretSources(d *doctorRun) {
	for _, t := range substrateSourceTools {
		id := "source_" + t.bin
		if t.goos != "" && t.goos != substrateSourceGOOS {
			d.add(id, doctorSkip, t.flag+" works only on macOS", "")
			continue
		}
		if _, err := exec.LookPath(t.bin); err != nil {
			d.add(id, doctorSkip, t.name+" is not installed, so "+t.flag+" is not available here (optional). "+t.fix, "")
			continue
		}
		d.add(id, doctorOK, t.flag+" can read values with "+t.name, "")
	}
}
