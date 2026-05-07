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
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/tui"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// tuiSkipFirstRunPrompt mirrors the “--skip-first-run-prompt“ flag.
// Default is false so the new pre-TUI gate is opt-out, not opt-in;
// automation that needs the legacy "always drop straight into the
// embedded first-run panel" behavior sets this flag explicitly.
var tuiSkipFirstRunPrompt bool

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch the interactive TUI dashboard",
	Long: `Launch the DefenseClaw unified TUI — a full-screen interactive dashboard
for monitoring, scanning, enforcing, and managing your OpenClaw deployment.

All CLI operations are accessible via the built-in command palette (Ctrl+K or :).

When no config.yaml exists yet, ` + "`defenseclaw tui`" + ` first asks whether you
want to run the canonical ` + "`defenseclaw init`" + ` wizard. Decline (or pass
--skip-first-run-prompt) to drop straight into the TUI's embedded first-run
panel instead.`,
	RunE: runTUI,
}

func init() {
	tuiCmd.PersistentPreRunE = runTUIPre
	// Cobra interprets backticks in flag help as the value placeholder
	// for that flag; for a BoolVar that produces a confusing
	// "--flag defenseclaw init" rendering. Keep this prose
	// backtick-free and reach for plain quotes instead.
	tuiCmd.Flags().BoolVar(&tuiSkipFirstRunPrompt, "skip-first-run-prompt", false,
		"Skip the pre-TUI 'run setup wizard?' question when no config exists "+
			"and drop straight into the embedded first-run panel. Useful for "+
			"automation that wants the legacy behavior or scripts that have "+
			"already run 'defenseclaw init' separately.")
	rootCmd.AddCommand(tuiCmd)
}

func runTUIPre(_ *cobra.Command, _ []string) error {
	loadDotEnvIntoOS(filepath.Join(config.DefaultDataPath(), ".env"))

	var err error
	cfg, err = config.Load()
	if err != nil {
		cfg = nil
		auditStore = nil
		auditLog = nil
		otelProvider = nil
		version.SetBinaryVersion(appVersion)
		return nil
	}
	applyPrivacyConfig(cfg)
	version.SetBinaryVersion(appVersion)

	auditStore, err = audit.NewStore(cfg.AuditDB)
	if err != nil {
		return fmt.Errorf("failed to open audit store: %w", err)
	}
	if err := auditStore.Init(); err != nil {
		return fmt.Errorf("failed to init audit store: %w", err)
	}
	auditLog = audit.NewLogger(auditStore)
	if resolved := filepath.Join(cfg.DataDir, ".env"); resolved != filepath.Join(config.DefaultDataPath(), ".env") {
		loadDotEnvIntoOS(resolved)
	}
	initAuditSinks()
	initOTelProvider()
	return nil
}

func runTUI(_ *cobra.Command, _ []string) error {
	// First-run gate.
	//
	// When no config has been loaded the operator has effectively
	// answered "I haven't run setup yet". We give them a single,
	// clear yes/no question BEFORE bubbletea takes over the screen
	// — three reasons:
	//
	//   1. The CLI wizard (`defenseclaw init`) surfaces every option
	//      the embedded FirstRunPanel does NOT (hook fail-mode, HITL
	//      severity floor, LLM provider/key, Cisco endpoint, …).
	//      Routing first-time installs through it is strictly better
	//      than leaving them with a 6-field shortcut.
	//   2. A bubbletea fullscreen UI is jarring as a first impression
	//      when the operator probably just wanted a yes/no.
	//   3. Operators who DO want the embedded panel can decline (or
	//      pass --skip-first-run-prompt for non-interactive setups).
	//
	// Outcome semantics drive what `tui.Deps.FirstRun` ultimately
	// sees:
	//
	//   firstRunHanded      → init succeeded, cfg reloaded; the
	//                         embedded panel should NOT activate
	//                         because the operator just finished.
	//   firstRunDeclined    → operator typed "n"; respect that and
	//                         open the standard TUI (no panel).
	//   firstRunUnavailable → could not run the prompt (non-tty,
	//                         skip flag, gibberish answer); fall
	//                         back to the legacy embedded-panel
	//                         behavior so we never strand the user.
	firstRunPanelEnabled := cfg == nil
	if cfg == nil {
		ttyOK := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
		outcome, err := promptFirstRunBeforeTUI(
			os.Stdin, os.Stdout,
			tuiSkipFirstRunPrompt, ttyOK,
			spawnFirstRunInit,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
		switch outcome {
		case firstRunHanded:
			// Reload everything PersistentPreRunE just decided
			// it couldn't load. Calling runTUIPre directly is
			// safe because both arguments are unused — see the
			// function signature above. If reload fails we
			// surface the error rather than silently launching
			// a half-initialized TUI.
			if reErr := runTUIPre(nil, nil); reErr != nil {
				return reErr
			}
			firstRunPanelEnabled = cfg == nil
		case firstRunDeclined:
			firstRunPanelEnabled = false
		case firstRunUnavailable:
			// keep legacy behavior: embedded panel handles it
		}
	}

	deps := tui.Deps{
		Store:    auditStore,
		Config:   cfg,
		FirstRun: firstRunPanelEnabled,
		Version:  appVersion,
	}

	model := tui.New(deps)

	p := tea.NewProgram(model)

	model.SetProgram(p)

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	return nil
}

// firstRunOutcome is a three-state enum returned by
// :func:`promptFirstRunBeforeTUI`. It deliberately distinguishes
// "operator declined" (firstRunDeclined) from "we couldn't ask"
// (firstRunUnavailable) so the caller can pick a reasonable
// embedded-panel default for each case — operators who say "n"
// shouldn't see a fullscreen panel a moment later.
type firstRunOutcome int

const (
	// firstRunUnavailable means the prompt didn't run, or the
	// answer was unparseable, or stdin/stdout aren't both TTYs.
	// Caller should fall back to whatever its legacy behavior was
	// for "no answer at all" — for ``runTUI`` that's the embedded
	// FirstRunPanel.
	firstRunUnavailable firstRunOutcome = iota
	// firstRunHanded means ``defenseclaw init`` ran AND exited 0.
	// Caller should reload config and proceed with normal TUI
	// startup; the embedded panel is no longer needed.
	firstRunHanded
	// firstRunDeclined means the operator explicitly answered
	// "n"/"no". Caller should open the standard TUI without the
	// embedded first-run panel — the operator already knows what
	// they want.
	firstRunDeclined
)

// spawnFirstRunInit is a function-pointer indirection so tests can
// stub the actual “defenseclaw init“ exec without spawning real
// subprocesses. Keep this a package-level var rather than passing
// the function through every call: only “runTUI“ ever invokes it
// in production, and tests overwrite the var directly.
var spawnFirstRunInit = func() error {
	bin := resolveDefenseclawBinForFirstRun()
	cmd := exec.Command(bin, "init")
	// The wizard prompts the operator interactively, so it MUST
	// inherit the real terminal fds. ``cmd.Run()`` waits until the
	// child exits, which is what we want — we resume the TUI
	// startup on the next line.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// resolveDefenseclawBinForFirstRun finds the “defenseclaw“ CLI
// binary to exec for the first-run wizard. Mirrors the resolution
// rules in “internal/tui/command.go::resolveSiblingBin“ but is
// duplicated here so “internal/cli“ doesn't need to reach into
// “internal/tui“'s unexported helpers. Order:
//
//  1. “os.Executable()“ — when we're already running as
//     “defenseclaw tui“, exec the same binary so the version
//     served by “init“ matches the version the operator just
//     invoked.
//  2. “exec.LookPath("defenseclaw")“ — classic PATH lookup.
//  3. literal “"defenseclaw"“ — last-resort fallback. “exec.Cmd“
//     surfaces the same NotFound error the legacy code did, so
//     environments that lack the CLI on PATH still fail with a
//     useful message.
func resolveDefenseclawBinForFirstRun() string {
	if self, err := os.Executable(); err == nil {
		// Resolve symlink chains (Linux ``/proc/self/exe``,
		// Homebrew shims, etc.) so the basename check matches
		// what's actually on disk, not what's pointing at it.
		if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
			self = resolved
		}
		if filepath.Base(self) == "defenseclaw" {
			return self
		}
	}
	if path, err := exec.LookPath("defenseclaw"); err == nil {
		return path
	}
	return "defenseclaw"
}

// promptFirstRunBeforeTUI asks the operator whether to run the
// canonical CLI setup wizard before the bubbletea TUI takes over
// the screen. See :type:`firstRunOutcome` for the three-state
// return contract.
//
// Inputs are explicit so tests can pump deterministic answers and
// verify spawn behavior:
//
//   - “in“     : stdin source (real “os.Stdin“ in production).
//   - “out“    : prompt destination (real “os.Stdout“ in
//     production).
//   - “skip“   : honors “--skip-first-run-prompt“.
//   - “ttyOK“  : true iff both stdin and stdout look like TTYs.
//     Computed by the caller because tests want to
//     short-circuit the real “term.IsTerminal“ check.
//   - “spawn“  : function that actually execs the wizard. Returns
//     any subprocess error verbatim; non-zero exit
//     status surfaces as “*exec.ExitError“ per
//     “cmd.Run()“ semantics.
//
// Default answer is “Y“ (run the wizard) because:
//
//   - Most callers of “defenseclaw tui“ with no config are first-
//     time installs; the wizard collects strictly more options
//     than the embedded panel and is the recommended path.
//   - Operators who want the embedded panel can answer "n" or use
//     “--skip-first-run-prompt“ — both are O(1) keystrokes.
//
// Errors are reserved for genuine failures of the spawned wizard.
// "I couldn't read the answer", "the answer was gibberish", and
// "stdin isn't a TTY" all return “firstRunUnavailable, nil“ so
// the caller can degrade gracefully to the embedded panel.
func promptFirstRunBeforeTUI(
	in io.Reader,
	out io.Writer,
	skip bool,
	ttyOK bool,
	spawn func() error,
) (firstRunOutcome, error) {
	if skip || !ttyOK {
		return firstRunUnavailable, nil
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "  DefenseClaw isn't configured yet — no config.yaml was found at")
	fmt.Fprintf(out, "  %s\n", config.ConfigPath())
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  The setup wizard collects your connector, profile, fail-mode, and")
	fmt.Fprintln(out, "  optional Human-In-the-Loop policy in a few short prompts. The TUI")
	fmt.Fprintln(out, "  embeds a shorter version of the same flow, but the wizard surfaces")
	fmt.Fprintln(out, "  every option (recommended for first-time installs).")
	fmt.Fprintln(out)
	fmt.Fprint(out, "  Run the setup wizard now? [Y/n] ")

	reader := bufio.NewReader(in)
	line, rerr := reader.ReadString('\n')
	// EOF on an empty input is fine: it means the operator pressed
	// Ctrl+D at the prompt, which we treat as "no" to be safe — a
	// hard EOF probably means stdin already closed and we'd loop on
	// any spawned interactive subprocess that tried to read it.
	// Other read errors mean we genuinely couldn't talk to stdin,
	// so we degrade to "unavailable" instead of pretending we got
	// an answer.
	if rerr != nil && rerr != io.EOF {
		return firstRunUnavailable, nil
	}

	answer := strings.TrimSpace(strings.ToLower(line))
	switch answer {
	case "n", "no":
		fmt.Fprintln(out, "  OK — opening the TUI without running the wizard.")
		fmt.Fprintln(out, "  Run it later anytime with: defenseclaw init")
		return firstRunDeclined, nil
	case "", "y", "yes":
		// fall through to spawn
	default:
		// Print the *trimmed* answer so we don't dump trailing
		// whitespace or the original newline. Keep the message
		// helpful: tell the operator how to opt back in later
		// instead of leaving them at a dead end.
		fmt.Fprintf(out, "  Couldn't parse %q — opening the TUI without running the wizard.\n", answer)
		fmt.Fprintln(out, "  Run it later anytime with: defenseclaw init")
		return firstRunUnavailable, nil
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "  Launching defenseclaw init…")
	fmt.Fprintln(out)

	if err := spawn(); err != nil {
		// Wrap rather than swallow: the operator deserves to know
		// the wizard failed. Caller logs this as a warning and
		// still opens the TUI so the user isn't completely
		// stranded.
		return firstRunUnavailable, fmt.Errorf("defenseclaw init: %w", err)
	}
	return firstRunHanded, nil
}
