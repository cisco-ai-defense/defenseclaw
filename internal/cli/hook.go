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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/envvars"
	gwconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func init() {
	rootCmd.AddCommand(newHookCmd())
}

// newHookCmd builds the hidden `hook` subcommand the agent runtime invokes per
// event. On Windows most agents invoke the native launcher directly. Cursor's
// PowerShell transport instead uses a generated adapter and this command's
// validated --input-file path because its object pipeline cannot preserve JSON
// on native stdin. Both paths forward the event to the local gateway and shape
// the agent-native stdout + exit code. It is hidden because it is a
// machine-facing entrypoint, not something a human runs directly.
func newHookCmd() *cobra.Command {
	var (
		connector         string
		event             string
		hookContractID    string
		hookSurface       string
		apiAddr           string
		failMode          string
		inputFile         string
		enterpriseManaged bool
		foreignHookCheck  bool
	)

	cmd := &cobra.Command{
		Use:    "hook",
		Short:  "Run an agent guardrail hook (invoked by the agent runtime)",
		Hidden: true,
		Args: func(cmd *cobra.Command, args []string) error {
			return hookFailure(hookFailureContext{connector: connector}, cobra.NoArgs(cmd, args))
		},
		// The hook is a short-lived per-event subprocess. Skip the daemon's
		// PersistentPreRunE/PostRun (config load and audit store open):
		// they are slow, can fail when the gateway is mid-setup, and would
		// hold the audit DB on every keystroke an agent makes.
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		PersistentPostRun: func(*cobra.Command, []string) {},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateHookSurface(connector, hookSurface); err != nil {
				return hookFailure(hookFailureContext{connector: connector}, err)
			}
			if foreignHookCheck {
				// The standalone Amp and OpenCode plugins ask for the
				// foreign-hook guard's decision only; nothing is sent to
				// the gateway.
				os.Exit(runForeignHookCheck(connector, os.Stdin, os.Stdout))
				return nil
			}
			if !enterpriseManaged && implicitEnterpriseManagedHook() {
				enterpriseManaged = true
			}
			startedAt := hookInvocationStart()
			// At the answer deadline of a tool call the hook writes its
			// fail-closed answer and ends, even while its own work is held
			// up (GAP-0155).
			exit := func(code int) { hookProcessExit(code) }
			// The watchdog is armed before the runtime resolution below,
			// which can itself take seconds on a stalled host.
			var stdin io.Reader
			var watchdog *hookexec.AnswerWatchdog
			if inputFile == "" {
				stdin, watchdog = armHookAnswerWatchdog(connector, event, failMode, hookSurface, enterpriseManaged, startedAt, exit)
			}
			if enterpriseManaged && prepareEnterpriseManagedHookRuntime(connector) {
				endHookBeforeRun(watchdog)
				return nil
			}
			if copilotCLIRunsVSCodeLocalHook(connector, hookSurface, enterpriseManaged) {
				endHookBeforeRun(watchdog)
				return nil
			}
			opts := buildHookOptionsForRuntime(connector, event, apiAddr, failMode, enterpriseManaged)
			opts.StartedAt = startedAt
			opts.Exit = exit
			opts.AnswerWatchdog = watchdog
			if stdin != nil {
				opts.Stdin = stdin
			}
			opts.HookContractID = hookContractID
			opts.HookSurface = strings.TrimSpace(hookSurface)
			// Only the standalone binary explains an unenrolled account.
			opts.ExplainUnenrolledAccount = enterpriseManaged && implicitEnterpriseManagedHook()
			if enterpriseManaged {
				opts.AssetFacts = hookAssetFacts
			}
			var input *os.File
			if inputFile != "" {
				if runtime.GOOS != "windows" || connector != "cursor" {
					return hookFailure(hookFailureContext{connector: connector}, fmt.Errorf("--input-file is only supported for the Cursor Windows hook adapter"))
				}
				var err error
				input, err = openCursorHookInputFile(opts.HookDir, inputFile)
				if err != nil {
					return err
				}
				opts.Stdin = input
			}
			applyHostEnterpriseForeignHookGuard(&opts)
			// hookexec returns the connector-native process status after writing
			// any structured decision. os.Exit is required because cobra
			// collapses RunE outcomes to 0/1.
			code := hookexec.Run(cmd.Context(), opts)
			if input != nil {
				// Preserve hookexec's exact allow/block exit code after it has
				// emitted the vendor response. Process exit also releases the
				// read handle if an unusual filesystem reports a close error.
				_ = input.Close()
			}
			hookProcessExit(code)
			return nil
		},
	}

	cmd.Flags().StringVar(&connector, "connector", "", "connector name (e.g. claudecode, codex, amp, cursor)")
	cmd.Flags().StringVar(&event, "event", "", "agent hook event name (selects the request deadline; inferred when omitted)")
	cmd.Flags().StringVar(&hookContractID, "hook-contract", "", "installer-bound connector hook contract")
	cmd.Flags().StringVar(&hookSurface, "hook-surface", "", "hook dialect the invoking hook configuration speaks (per connector; kiro: v3, copilot: vscode-local)")
	cmd.Flags().StringVar(&apiAddr, "api-addr", "", "gateway host:port (defaults to the hook sidecar / local gateway)")
	cmd.Flags().StringVar(&failMode, "fail-mode", "", "response-failure policy: open or closed (defaults to the hook sidecar, else closed)")
	cmd.Flags().StringVar(&inputFile, "input-file", "", "Cursor Windows adapter payload file")
	cmd.Flags().BoolVar(&enterpriseManaged, "enterprise-managed", false, "resolve the current SID's administrator-managed hook runtime")
	cmd.Flags().BoolVar(&foreignHookCheck, "foreign-hook-check", false, "print the standalone foreign-hook guard decision as JSON (in-agent plugins)")
	_ = cmd.Flags().MarkHidden("input-file")
	_ = cmd.Flags().MarkHidden("foreign-hook-check")
	_ = cmd.Flags().MarkHidden("hook-contract")
	_ = cmd.Flags().MarkHidden("hook-surface")
	_ = cmd.Flags().MarkHidden("enterprise-managed")
	_ = cmd.MarkFlagRequired("connector")
	// A flag the hook does not know (or a malformed value) fails before
	// RunE. Report it with the connector's failure status, not cobra's 1.
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return hookFailure(hookFailureContext{connector: connector}, err)
	})
	cmd.AddCommand(newHookSessionFactsCmd())
	cmd.AddCommand(&cobra.Command{
		Use: "resolve-writes", Hidden: true, Args: cobra.NoArgs,
		Annotations: map[string]string{secureClientAbsentAnnotation: "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			payload, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 1<<20+1))
			if err != nil || len(payload) > 1<<20 {
				return fmt.Errorf("invalid hook write evidence")
			}
			_, err = io.WriteString(cmd.OutOrStdout(), hookpaths.Resolve(payload))
			return err
		},
	})

	return cmd
}

// newHookSessionFactsCmd is `hook session-facts`: it prints the calling
// session's X-DefenseClaw-Session-Facts value, the Kerberos default
// principal included. The Linux and macOS shell hooks run it because a
// shell cannot read a credential cache; it caches the value in
// ~/.defenseclaw/session-facts.json, which the hooks read without running
// it for the next five minutes (30 seconds when a KCM read failed in
// transit or the macOS klist timed out).
func newHookSessionFactsCmd() *cobra.Command {
	return &cobra.Command{
		Use:         "session-facts",
		Short:       "Print this session's claimed session facts (invoked by the shell hooks)",
		Hidden:      true,
		Annotations: map[string]string{secureClientAbsentAnnotation: "true"},
		Args:        cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := io.WriteString(cmd.OutOrStdout(), useridentity.CurrentSessionFactsHeader())
			return err
		},
	}
}

// armHookAnswerWatchdog reads the call's payload and arms the answer
// watchdog of a tool call before the hook resolves its runtime: the
// descriptor, account and sidecar reads before Run count against the call's
// budget too (GAP-0155). It returns the hook's stdin, the payload read
// followed by the rest, so Run reads exactly what the agent wrote.
func armHookAnswerWatchdog(connectorName, event, failMode, surface string, managed bool, startedAt time.Time, exit func(int)) (io.Reader, *hookexec.AnswerWatchdog) {
	payload, _ := io.ReadAll(io.LimitReader(os.Stdin, hookexec.DefaultMaxBody+1))
	stdin := io.MultiReader(bytes.NewReader(payload), os.Stdin)
	opts := hookexec.Options{
		Connector:         connectorName,
		Event:             event,
		FailMode:          failMode,
		HookSurface:       strings.TrimSpace(surface),
		ManagedEnterprise: managed,
		SecureClient:      managed && secureClientHost(),
		StartedAt:         startedAt,
		Exit:              exit,
	}
	if managed {
		// The watchdog starts this account lookup in the background before
		// it can fire, and Run's rows reuse it: a deadline that passed
		// before Run, or a lookup slower than the watchdog's log wait, left
		// the call it answered with no hook-failures row.
		profileDir := hookUserProfileDir
		opts.FailureLogHome = func() string { return failureLogHomeIn(profileDir) }
	}
	return stdin, hookexec.ArmAnswerWatchdog(opts, payload)
}

// endHookBeforeRun ends a hook call that needs no answer (a retired launcher,
// a hook another surface runs): it exits 0 unless the answer watchdog
// already answered.
func endHookBeforeRun(watchdog *hookexec.AnswerWatchdog) {
	if watchdog != nil {
		hookProcessExit(watchdog.Finish(0))
	}
}

// hookInvocationStart is when this hook call began, which its time budgets
// count from. A process the agent launched for the call (its first argument
// is `hook`) began when the system created it: the launch and the runtime
// resolution before Run can take seconds on a busy host (GAP-0155). Any
// other caller (a test running the command in process) began now.
func hookInvocationStart() time.Time {
	if len(os.Args) > 1 && os.Args[1] == "hook" {
		return hookexec.ProcessStartTime()
	}
	return time.Now()
}

// hookProcessExit ends the hook process with hookexec's connector-native
// status. It is a variable so tests can run the command without exiting.
var hookProcessExit = os.Exit

// hookRawArgs returns the hook process's own arguments. A flag error stops
// parsing before --connector may have been read, so the failure status looks
// the connector up here. It is a variable for tests, which run the command
// through SetArgs rather than os.Args.
var hookRawArgs = func() []string { return os.Args[1:] }

// validateHookSurface accepts an empty --hook-surface and any value the
// connector lists (hookexec.HookSurfaceAllowed). There is one hidden flag
// for every connector; each connector names the hook dialects its installed
// configuration speaks, and anything else is a usage error.
func validateHookSurface(connectorName, surface string) error {
	if strings.TrimSpace(surface) == "" || hookexec.HookSurfaceAllowed(connectorName, surface) {
		return nil
	}
	return fmt.Errorf("--hook-surface %q is not valid for connector %q", surface, connectorName)
}

// hookFailureContext is what a hook invocation that failed before hookexec
// ran says about itself: the flags parsed before the failure. A flag error
// stops parsing, so resolve completes them from the raw arguments.
type hookFailureContext struct {
	connector string
}

func (c hookFailureContext) resolve() hookFailureContext {
	if strings.TrimSpace(c.connector) == "" {
		c.connector = hookRawFlagValue("connector")
	}
	return c
}

// hookFailureExitCode is the exit status of a hook invocation that fails
// before hookexec runs: an unknown flag, a malformed or unlisted flag value,
// a positional argument. Cobra reports these as 1. Kiro treats every status
// other than 0 and 2 as a failed hook, shows its stderr as a warning and
// lets the prompt or tool call go ahead (kiro.dev/docs/hooks/actions). A
// Kiro hook exits 2, the only status Kiro honors as a block. Every other
// connector keeps 1 for its own hook dialect.
func hookFailureExitCode(failure hookFailureContext) int {
	failure = failure.resolve()
	if strings.EqualFold(strings.TrimSpace(failure.connector), "kiro") && hookPreRunFailsClosed(failure) {
		return 2
	}
	return 1
}

// hookPreRunFailsClosed covers errors before hookexec can classify an outage.
// Such errors never carry a verified gateway decision or connection outage.
func hookPreRunFailsClosed(_ hookFailureContext) bool {
	return true
}

// nativeHookFailMode resolves the fail mode a hook command ends with (flag,
// else sidecar) as the config resolver does: only an explicit "open" opens.
// A Windows native command carries no --fail-mode and relies on
// hooks/.hookcfg; when that sidecar is missing, unreadable or names no mode
// for the connector the hook fails closed, never open. The mode governs a
// confirmed gateway outage only: hookexec closes every answered, malformed or
// unanswered call outside Secure Client whatever it says.
func nativeHookFailMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "open") {
		return "open"
	}
	return "closed"
}

// hookFailure labels a pre-run hook failure with the connector's failure
// status (see hookFailureExitCode).
func hookFailure(failure hookFailureContext, err error) error {
	if err == nil {
		return nil
	}
	if code := hookFailureExitCode(failure); code != 1 {
		return withExitCode(err, code)
	}
	return err
}

// hookRawFlagValue returns --name's value in the raw arguments ("--name v"
// or "--name=v"), stopping at "--".
func hookRawFlagValue(name string) string {
	args := hookRawArgs()
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "--":
			return ""
		case arg == "--"+name && index+1 < len(args):
			return args[index+1]
		case strings.HasPrefix(arg, "--"+name+"="):
			return strings.TrimPrefix(arg, "--"+name+"=")
		}
	}
	return ""
}

const cursorHookInputMaxBytes int64 = 1 << 20

func openCursorHookInputFile(hookDir, path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("Cursor hook input path must be absolute")
	}
	cleanDir, err := filepath.Abs(hookDir)
	if err != nil {
		return nil, fmt.Errorf("resolve Cursor hook directory: %w", err)
	}
	cleanPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve Cursor hook input: %w", err)
	}
	if !pathidentity.Same(filepath.Dir(cleanPath), cleanDir) {
		return nil, fmt.Errorf("Cursor hook input must be inside the DefenseClaw hooks directory")
	}
	base := filepath.Base(cleanPath)
	if !strings.HasPrefix(base, ".cursor-input-") || !strings.HasSuffix(base, ".json") {
		return nil, fmt.Errorf("Cursor hook input filename is not DefenseClaw-managed")
	}
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("inspect Cursor hook input: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("Cursor hook input must be a regular file")
	}
	if info.Size() > cursorHookInputMaxBytes {
		return nil, fmt.Errorf("Cursor hook input exceeds %d bytes", cursorHookInputMaxBytes)
	}
	input, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("open Cursor hook input: %w", err)
	}
	openedInfo, err := input.Stat()
	if err != nil {
		_ = input.Close()
		return nil, fmt.Errorf("inspect opened Cursor hook input: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Size() > cursorHookInputMaxBytes {
		_ = input.Close()
		return nil, fmt.Errorf("opened Cursor hook input is not a valid payload file")
	}
	return input, nil
}

// buildHookOptions resolves hook configuration. Source builds and Unix hooks
// retain their environment-compatible behavior. A packaged Windows hook binds
// security-critical values to installer-owned state and accepts inherited
// environment only when it tightens policy. It is factored out of RunE (which
// calls os.Exit) so it can be unit-tested.
func buildHookOptions(connector, event, apiAddr, failMode string) hookexec.Options {
	return buildHookOptionsForRuntime(connector, event, apiAddr, failMode, false)
}

// hookUserProfileDir resolves the invoking user's profile
// (managedHookUserProfileDir); a variable so tests can stall it.
var hookUserProfileDir = managedHookUserProfileDir

// managedHookFailureLogHome is the invoking user's diagnostic directory for
// managed hook failure rows (hookUserProfileDir). It is never on the answer
// path: a tool call looks it up in the background once its watchdog is armed
// (armHookAnswerWatchdog), any other call only when it writes a row. The
// account lookup (NSS, Open Directory, a token Known Folder) can be slow.
func managedHookFailureLogHome() string {
	return failureLogHomeIn(hookUserProfileDir)
}

// failureLogHomeIn is the diagnostic directory in the profile that
// profileDir resolves; empty when it resolves none.
func failureLogHomeIn(profileDir func() (string, error)) string {
	home, err := profileDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, config.DefaultDataDirName)
}

func buildHookOptionsForRuntime(connector, event, apiAddr, failMode string, enterpriseManaged bool) hookexec.Options {
	if enterpriseManaged && enterpriseManagedHookRuntimeForceClosed() {
		// The administrator-owned runtime failed trust validation. Do not read its
		// sidecar/token or contact any endpoint derived from those files; hand an
		// unavailable strict runtime directly to hookexec's fail-closed boundary.
		opts := hookexec.Options{
			Connector:             connector,
			Event:                 event,
			FailMode:              "closed",
			StrictAvailability:    true,
			ManagedEnterprise:     true,
			SecureClient:          secureClientHost(),
			ManagedRuntimeFailure: enterpriseManagedHookRuntimeFailureReason(),
		}
		opts.FailureLogHome = managedHookFailureLogHome
		// Marks a failed Unix standalone runtime as the standalone profile's
		// (no transport is selected); a no-op elsewhere.
		applyStandaloneManagedHookTransport(&opts, connector)
		return opts
	}
	home, trustedNativeState := trustedNativeHookHome()
	if !trustedNativeState {
		home = config.DefaultDataPath()
	}
	hookDir := filepath.Join(home, "hooks")

	// Setup writes hooks/.hookcfg on Windows so the agent's hook command can
	// stay free of per-install flags (keeping its trust-hash / match string
	// stable). It supplies the gateway address + fail mode the flags omit.
	sidecar := map[string]string{}
	if !enterpriseManaged {
		// Managed Windows resolution already consumed the same sidecar through
		// its bounded, identity-stable verifier and then replaces every
		// security-critical value with protected machine state. Avoid a second
		// unbounded target-owned read while preserving unmanaged behavior.
		sidecar = readHookSidecar(filepath.Join(hookDir, ".hookcfg"))
	}

	managedGatewayService := ""
	var authenticatedManagedToken *string
	managedRuntimeFailure := ""
	if enterpriseManaged {
		protectedAddr, protectedService, protectedToken, ok :=
			enterpriseManagedHookRuntimeConnection(connector)
		if ok {
			apiAddr = protectedAddr
			managedGatewayService = protectedService
			authenticatedManagedToken = protectedToken
		} else {
			// Resolver failure is carried separately and blocks before network
			// contact. Keep a loopback placeholder so no user-supplied flag,
			// environment value, or target-writable sidecar becomes selected.
			apiAddr = "127.0.0.1:1"
			managedRuntimeFailure = enterpriseManagedHookRuntimeFailureReason()
			if strings.TrimSpace(managedRuntimeFailure) == "" {
				// Keep direct/internal callers safe even when they bypass the normal
				// NativeHookRuntimeNoop preflight. Managed execution may never fall
				// back to the mutable legacy sidecars merely because no authenticated
				// generation has been cached yet.
				managedRuntimeFailure = "enterprise_managed_runtime_state_invalid"
			}
		}
	} else {
		if apiAddr == "" && trustedNativeState {
			apiAddr = sidecar["DEFENSECLAW_GATEWAY_ADDR"]
		}
		if apiAddr == "" && !trustedNativeState {
			apiAddr = os.Getenv("DEFENSECLAW_GATEWAY_ADDR")
		}
		if apiAddr == "" {
			apiAddr = sidecar["DEFENSECLAW_GATEWAY_ADDR"]
		}
		if apiAddr == "" {
			apiAddr = fmt.Sprintf("127.0.0.1:%d", config.DefaultGatewayAPIPort)
		}
	}

	// The gateway is always a local, loopback-bound sidecar: setup bakes
	// 127.0.0.1:<port> into every hook (connector_cmd.go) and the daemon binds
	// loopback. This native path, unlike the .sh hooks, resolves its address
	// partly from the process environment (DEFENSECLAW_GATEWAY_ADDR) and the
	// .hookcfg sidecar, so a compromised agent process could otherwise redirect
	// it to a remote host and exfiltrate hook payloads plus the bearer token.
	// Refuse any non-loopback target and fall back to the safe default, matching
	// the .sh hooks which bake the loopback address and ignore the environment.
	if !hookIsLoopbackAddr(apiAddr) {
		fmt.Fprintf(os.Stderr,
			"defenseclaw: ignoring non-loopback gateway address %q; using local gateway\n", apiAddr)
		apiAddr = fmt.Sprintf("127.0.0.1:%d", config.DefaultGatewayAPIPort)
	}

	// The fail mode is installed state only: the registered command's
	// --fail-mode, else the hook sidecar setup wrote. DEFENSECLAW_FAIL_MODE in
	// the agent's environment is never read, so status and doctor, which read
	// the same sidecar, report what the hook does (GAP-0315).
	if failMode == "" {
		failMode = hookSidecarFailMode(sidecar, connector, home)
	}
	failMode = nativeHookFailMode(failMode)
	token := os.Getenv("DEFENSECLAW_GATEWAY_TOKEN")
	if trustedNativeState {
		// Connector-scoped token sidecars are ACL-protected installer state.
		// Never let an inherited generic token shadow or replace them.
		token = ""
	}

	opts := hookexec.Options{
		Connector:                 connector,
		Event:                     event,
		APIAddr:                   apiAddr,
		FailMode:                  failMode,
		Home:                      home,
		HookDir:                   hookDir,
		Token:                     token,
		AuthenticatedManagedToken: authenticatedManagedToken,
		StrictAvailability:        hookEnvTrue(os.Getenv("DEFENSECLAW_STRICT_AVAILABILITY")),
		ManagedEnterprise:         enterpriseManaged,
		SecureClient:              enterpriseManaged && secureClientHost(),
		ManagedGatewayServiceName: managedGatewayService,
		TraceParent: hookFirstNonEmpty(
			envvars.Getenv("DEFENSECLAW_TRACEPARENT"),
			os.Getenv("TRACEPARENT"),
			os.Getenv("OTEL_TRACEPARENT"),
		),
		TraceState: hookFirstNonEmpty(
			envvars.Getenv("DEFENSECLAW_TRACESTATE"),
			os.Getenv("TRACESTATE"),
			os.Getenv("OTEL_TRACESTATE"),
		),
	}
	if enterpriseManaged {
		opts.FailureLogHome = managedHookFailureLogHome
	}
	if trustedNativeState {
		opts.GatewayRecovery = trustedNativeGatewayRecovery()
		if opts.GatewayRecovery == nil && !enterpriseManaged {
			// A PowerShell (install.ps1) per-user install publishes no
			// protected hook runtime, so its hook had no cold start and a
			// gateway that ended with the sign-in session stayed down
			// (GAP-0377). Managed and Secure Client hooks never get here.
			opts.GatewayRecovery = perUserGatewayRecovery()
		}
	}
	if enterpriseManaged {
		opts.ManagedEnterprise = true
		if managedRuntimeFailure == "" {
			managedRuntimeFailure = enterpriseManagedHookRuntimeFailureReason()
		}
		opts.ManagedRuntimeFailure = managedRuntimeFailure
		// A managed hook takes its fail mode from administrator-owned runtime
		// state, never from the command line: the authenticated Windows
		// runtime generation, or the root-owned Unix runtime descriptor. Each
		// records the mode the administrator's config resolved (owner
		// decision 2026-10-20: explicit open or closed wins, unset is closed,
		// and open under Secure Client, #1163). A runtime failure, and
		// anything but open, keeps the fail-closed, strict-availability
		// contract. The agent's environment never changes it.
		opts.FailMode = enterpriseManagedHookRuntimeFailMode()
		if managedRuntimeFailure != "" || opts.FailMode != "open" {
			opts.FailMode = "closed"
			opts.StrictAvailability = true
		}
	}

	if v := os.Getenv("DEFENSECLAW_HOOK_MAX_BODY"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			if !trustedNativeState || n <= 1<<20 {
				// Packaged hooks allow projects to lower the cap, never raise it.
				opts.MaxBody = n
			}
		}
	}
	if enterpriseManaged {
		// Unix standalone profile: bind the transport to the root-owned
		// runtime descriptor (no-op elsewhere).
		applyStandaloneManagedHookTransport(&opts, connector)
	}

	return opts
}

// readHookSidecar parses the hooks/.hookcfg file setup writes on Windows.
// Version 2 is JSON with a connector-keyed fail_modes map. The legacy
// KEY=value shape remains readable so the first connector refresh can migrate
// an existing install without changing its runtime behavior beforehand.
// A connector map that is present but not an object of strings (null
// included), or a blank entry, is malformed state: it resolves closed and
// never falls back to the legacy mode. A missing map is what every release
// writes before the first connector entry, so the legacy mode still applies.
// A JSON document that does not parse, or is not version 2 or later, is
// malformed too: it resolves closed and is never read as KEY=value lines.
// A missing or unreadable file names no mode, which is closed as well.
func readHookSidecar(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var current struct {
		Version     int               `json:"version"`
		GatewayAddr string            `json:"gateway_addr"`
		FailModes   json.RawMessage   `json:"fail_modes"`
		Sources     map[string]string `json:"fail_mode_sources"`
		LegacyMode  string            `json:"legacy_fail_mode"`
		LegacySrc   string            `json:"legacy_fail_mode_source"`
	}
	if json.Unmarshal(data, &current) == nil && current.Version >= 2 {
		out["DEFENSECLAW_GATEWAY_ADDR"] = current.GatewayAddr
		var modes map[string]string
		if len(current.FailModes) > 0 {
			if err := json.Unmarshal(current.FailModes, &modes); err != nil || modes == nil {
				out["DEFENSECLAW_FAIL_MODE"] = "closed"
				return out
			}
		}
		for connector, mode := range modes {
			if strings.TrimSpace(mode) == "" {
				mode = "closed"
			}
			out[hookSidecarFailModeKey(connector)] = mode
		}
		for connector, source := range current.Sources {
			out[hookSidecarFailModeSourceKey(connector)] = source
		}
		if current.LegacyMode != "" {
			out["DEFENSECLAW_FAIL_MODE"] = current.LegacyMode
			out[hookSidecarFailModeSourceKey("")] = current.LegacySrc
		}
		return out
	}
	if trimmed := bytes.TrimSpace(data); json.Valid(trimmed) ||
		(len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')) {
		// JSON that is not a v2 sidecar (an older or unknown version, an
		// array, a scalar) or that does not parse is no sidecar this hook
		// understands: closed, never KEY=value lines.
		out["DEFENSECLAW_FAIL_MODE"] = "closed"
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if unq, err := strconv.Unquote(val); err == nil {
			val = unq
		} else {
			val = strings.Trim(val, `"'`)
		}
		// Only this release's JSON records a source.
		if key != "" && !strings.HasPrefix(key, hookSidecarSourcePrefix) {
			out[key] = val
		}
	}
	return out
}

// hookSidecarFailMode is connector's fail mode in the hook sidecar. An open
// counts only when the sidecar records that the config chose it
// (fail_mode_sources, written by this release). Any other open is closed
// unless home's config.yaml sets open for the connector: an earlier release's
// (the 0.8.x KEY=value file, a 1.0.x file without that field, an unscoped
// legacy mode), which may be an unset mode resolved from the guardrail mode,
// and one CapableHookFailMode lowered for a vendor that cannot fail closed,
// which is that vendor's limit, not an operator's open. The installers
// refresh the sidecar from the config before the gateway stops; this covers
// one that was not refreshed.
func hookSidecarFailMode(sidecar map[string]string, connector, home string) string {
	mode := sidecar[hookSidecarFailModeKey(connector)]
	source := sidecar[hookSidecarFailModeSourceKey(connector)]
	if mode == "" {
		mode, source = sidecar["DEFENSECLAW_FAIL_MODE"], sidecar[hookSidecarFailModeSourceKey("")]
	}
	if nativeHookFailMode(mode) != "open" || source == gwconnector.HookFailModeSourceConfig {
		return mode
	}
	if hookConfigSetsOpen(home, connector) {
		return "open"
	}
	return "closed"
}

// hookConfigMaxBytes bounds the config.yaml read of readHookConfigDocument.
const hookConfigMaxBytes = 4 << 20

// readHookConfigDocument returns the config.yaml document at path, or nil
// when it is missing, not a regular file or larger than hookConfigMaxBytes.
func readHookConfigDocument(path string) []byte {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > hookConfigMaxBytes {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

// hookConfigSetsOpen reports whether home's config.yaml sets hook fail mode
// open for connector (config.ConfiguredHookFailModeInDocument). Only the
// data directory's own config.yaml is read, never DEFENSECLAW_CONFIG: the
// environment can only tighten a hook.
func hookConfigSetsOpen(home, connector string) bool {
	data := readHookConfigDocument(filepath.Join(home, "config.yaml"))
	return data != nil && config.ConfiguredHookFailModeInDocument(data, connector) == "open"
}

func hookSidecarFailModeKey(connector string) string {
	return "DEFENSECLAW_FAIL_MODE_" + hookSidecarConnectorKey(connector)
}

// hookSidecarSourcePrefix keys readHookSidecar's sources. No KEY=value
// sidecar line can set one.
const hookSidecarSourcePrefix = "source:"

func hookSidecarFailModeSourceKey(connector string) string {
	return hookSidecarSourcePrefix + hookSidecarConnectorKey(connector)
}

func hookSidecarConnectorKey(connector string) string {
	name := strings.ToUpper(strings.TrimSpace(connector))
	return strings.NewReplacer("-", "", "_", "", " ", "").Replace(name)
}

// hookIsLoopbackAddr reports whether addr ("host:port" or a bare host) targets
// the local loopback interface. The hook only ever talks to the local gateway,
// so any other host is treated as untrusted (see buildHookOptions).
func hookIsLoopbackAddr(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// hookEnvTrue mirrors defenseclaw_should_fail_closed_on_unreachable's truthy
// set: 1, true, yes (case-insensitive).
func hookEnvTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func hookFirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
