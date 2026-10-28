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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
		executionProbe    bool
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
			if executionProbe {
				if connector != "hermes" || event != "" || hookContractID != "" || hookSurface != "" ||
					apiAddr != "" || failMode != "" || inputFile != "" || enterpriseManaged || foreignHookCheck {
					return fmt.Errorf("hermes execution probe requires the exact registered command")
				}
				// cmd/defenseclaw-hook reaches this only after the protected
				// runtime is active. A disabled stable launcher returns no proof.
				_, err := io.WriteString(cmd.OutOrStdout(), "defenseclaw-execution-probe-ok\n")
				return err
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
					return hookFailure(hookFailureContext{connector: connector, managed: enterpriseManaged}, err)
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
	cmd.Flags().StringVar(&failMode, "fail-mode", "", "managed response-failure policy (per-user hooks always close)")
	cmd.Flags().StringVar(&inputFile, "input-file", "", "Cursor Windows adapter payload file")
	cmd.Flags().BoolVar(&enterpriseManaged, "enterprise-managed", false, "resolve the current SID's administrator-managed hook runtime")
	cmd.Flags().BoolVar(&foreignHookCheck, "foreign-hook-check", false, "print the standalone foreign-hook guard decision as JSON (in-agent plugins)")
	cmd.Flags().BoolVar(&executionProbe, "defenseclaw-execution-probe", false, "prove the registered Hermes command reaches the active hook runtime")
	_ = cmd.Flags().MarkHidden("input-file")
	_ = cmd.Flags().MarkHidden("foreign-hook-check")
	_ = cmd.Flags().MarkHidden("defenseclaw-execution-probe")
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
	if !managed {
		// The data directory whose install lock closes the call's early
		// answer (GAP-0862); Run's own home replaces it when Run adopts the
		// watchdog. DEFENSECLAW_HOME counts, as for Run.
		opts.Home = config.DefaultDataPath()
		// The registered command may still carry --fail-mode open from an
		// earlier release. A per-user timeout must never allow the event.
		opts.FailMode = "closed"
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
	// managed is the administrator-managed hook (--enterprise-managed); a
	// per-user hook's fail mode is closed whatever its flags say.
	managed bool
}

func (c hookFailureContext) resolve() hookFailureContext {
	if strings.TrimSpace(c.connector) == "" {
		c.connector = hookRawFlagValue("connector")
	}
	if !c.managed {
		c.managed = hookRawBoolFlag("enterprise-managed")
	}
	return c
}

// hookFailureIO is the hook process's stdin, stdout and stderr for a failure
// answered before Run; a variable for tests.
var hookFailureIO = func() (io.Reader, io.Writer, io.Writer) { return os.Stdin, os.Stdout, os.Stderr }

// answerHookFailureClosed answers a hook invocation that fails before
// hookexec runs (an unknown flag, a malformed or unlisted flag value, a
// positional argument, an unusable Cursor input file) whose policy is
// closed (hookPreRunFailsClosed: a managed hook, any hook while its
// account's installer holds the data directory, else a mode that is not
// open). Cobra reports these as 1, which Claude Code, Codex, Kiro, Hermes,
// Copilot and Antigravity all run the call on: hookexec answers with the
// connector's own block for the event the raw arguments name (GAP-0862,
// GAP-0982). A Secure Client hook keeps its upstream statuses, Kiro's
// blocking 2 included; an open hook and an unknown connector keep 1.
func answerHookFailureClosed(failure hookFailureContext, err error) (int, bool) {
	name := strings.ToLower(strings.TrimSpace(failure.connector))
	if !hookPreRunFailsClosed(failure) || !slices.Contains(hookexec.SupportedConnectors(), name) {
		return 0, false
	}
	managed := failure.managed || implicitEnterpriseManagedHook()
	if managed && secureClientHost() {
		if name == "kiro" {
			return 2, true
		}
		return 0, false
	}
	home, trusted := trustedNativeHookHome()
	if !trusted {
		home = config.DefaultDataPath()
	}
	stdin, stdout, stderr := hookFailureIO()
	opts := hookexec.Options{
		Connector:         name,
		Event:             hookRawFlagValue("event"),
		HookContractID:    hookRawFlagValue("hook-contract"),
		HookSurface:       strings.TrimSpace(hookRawFlagValue("hook-surface")),
		Home:              home,
		ManagedEnterprise: managed,
		Stdin:             stdin,
		Stdout:            stdout,
		Stderr:            stderr,
	}
	reason := "hook invocation error: " + err.Error()
	if managed {
		opts.ExplainUnenrolledAccount = implicitEnterpriseManagedHook()
		opts.ManagedRuntimeFailure = reason
	} else {
		opts.InvocationFailure = reason
	}
	return hookexec.Run(context.Background(), opts), true
}

// hookPreRunFailsClosed applies the fail-closed boundary before hookexec has
// loaded trusted runtime state. A flag or old sidecar cannot open this path.
func hookPreRunFailsClosed(_ hookFailureContext) bool {
	return true
}

// hookFailure answers a pre-run hook failure closed where its policy is
// closed (answerHookFailureClosed) and labels it with that answer's status.
func hookFailure(failure hookFailureContext, err error) error {
	if err == nil {
		return nil
	}
	if code, answered := answerHookFailureClosed(failure.resolve(), err); answered {
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

// hookRawBoolFlag reads a boolean flag from the raw arguments, for a failure
// answered before Cobra parsed them.
func hookRawBoolFlag(name string) bool {
	for _, arg := range hookRawArgs() {
		if arg == "--" {
			return false
		}
		if arg == "--"+name {
			return true
		}
		if value, ok := strings.CutPrefix(arg, "--"+name+"="); ok {
			set, err := strconv.ParseBool(value)
			return err == nil && set
		}
	}
	return false
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

func buildHookOptionsForRuntime(connector, event, apiAddr, _ string, enterpriseManaged bool) hookexec.Options {
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
	// stable). It supplies the gateway address the flags omit.
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

	// Per-user native hooks fail closed for every failure but a gateway
	// outage. Their outage mode is the one Setup recorded for the connector
	// in hooks/.hookcfg from its policy tier (config.HookOutageFailMode); an
	// older registration flag or the environment cannot open them. Managed
	// hooks take their mode from protected administrator state below.
	outageFailMode := "closed"
	if !enterpriseManaged {
		outageFailMode = perUserHookOutageFailMode(filepath.Join(hookDir, ".hookcfg"), connector)
	}
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
		FailMode:                  "closed",
		OutageFailMode:            outageFailMode,
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

// readHookSidecar reads only the gateway address from a per-user hook
// sidecar. Legacy fail-mode fields are ignored: they cannot grant an outage
// exception. Malformed JSON is never retried as KEY=value lines.
func readHookSidecar(path string) map[string]string {
	out := map[string]string{}
	// A link, another file type or a file past the writers' bound
	// (gwconnector.HookSidecarMaxBytes) supplies no address.
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > gwconnector.HookSidecarMaxBytes {
		return out
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > gwconnector.HookSidecarMaxBytes {
		return out
	}
	var current struct {
		Version     int    `json:"version"`
		GatewayAddr string `json:"gateway_addr"`
	}
	if json.Unmarshal(data, &current) == nil && current.Version >= 2 {
		out["DEFENSECLAW_GATEWAY_ADDR"] = current.GatewayAddr
		return out
	}
	if trimmed := bytes.TrimSpace(data); json.Valid(trimmed) ||
		(len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')) {
		// An older or malformed JSON sidecar supplies no address. It is not
		// interpreted as flat lines even if it embeds an address assignment.
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
		if key == "DEFENSECLAW_GATEWAY_ADDR" {
			out[key] = val
		}
	}
	return out
}

// perUserHookOutageFailMode is connector's outage mode in the per-user hook
// sidecar at path: "open" only when the sidecar is a regular, bounded v2+
// JSON document of a per-user install whose fail_modes entry for the
// connector is "open" with the config source (Setup's record of
// config.HookOutageFailMode). Anything else (no entry, another value, no
// source, a managed or malformed sidecar, a link) is "closed".
func perUserHookOutageFailMode(path, connector string) string {
	name := strings.ToLower(strings.TrimSpace(connector))
	if name == "" {
		return "closed"
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > hookConfigMaxBytes {
		return "closed"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "closed"
	}
	var state struct {
		Version   int               `json:"version"`
		FailModes map[string]string `json:"fail_modes"`
		Sources   map[string]string `json:"fail_mode_sources"`
		Managed   bool              `json:"managed_enterprise"`
	}
	if json.Unmarshal(data, &state) != nil || state.Version < 2 || state.Managed {
		return "closed"
	}
	if state.FailModes[name] == "open" && state.Sources[name] == gwconnector.HookFailModeSourceConfig {
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
