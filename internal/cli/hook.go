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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
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
			return hookFailure(hookFailureContext{connector, failMode, enterpriseManaged}, cobra.NoArgs(cmd, args))
		},
		// The hook is a short-lived per-event subprocess. Skip the daemon's
		// PersistentPreRunE/PostRun (config load and audit store open):
		// they are slow, can fail when the gateway is mid-setup, and would
		// hold the audit DB on every keystroke an agent makes.
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		PersistentPostRun: func(*cobra.Command, []string) {},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateHookSurface(connector, hookSurface); err != nil {
				return hookFailure(hookFailureContext{connector, failMode, enterpriseManaged}, err)
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
			if enterpriseManaged && enterpriseManagedHookRuntimeNoop(connector) {
				return nil
			}
			if copilotCLIRunsVSCodeLocalHook(connector, hookSurface, enterpriseManaged) {
				return nil
			}
			opts := buildHookOptionsForRuntime(connector, event, apiAddr, failMode, enterpriseManaged)
			opts.HookContractID = hookContractID
			opts.HookSurface = strings.TrimSpace(hookSurface)
			// Only the standalone binary explains an unenrolled account.
			opts.ExplainUnenrolledAccount = enterpriseManaged && implicitEnterpriseManagedHook()
			var input *os.File
			if inputFile != "" {
				if runtime.GOOS != "windows" || connector != "cursor" {
					return hookFailure(hookFailureContext{connector, failMode, enterpriseManaged}, fmt.Errorf("--input-file is only supported for the Cursor Windows hook adapter"))
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
	cmd.Flags().StringVar(&failMode, "fail-mode", "", "response-failure policy: open or closed (defaults to the hook sidecar / open)")
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
		return hookFailure(hookFailureContext{connector, failMode, enterpriseManaged}, err)
	})
	cmd.AddCommand(newHookSessionFactsCmd())

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
	failMode  string
	managed   bool
}

func (c hookFailureContext) resolve() hookFailureContext {
	if strings.TrimSpace(c.connector) == "" {
		c.connector = hookRawFlagValue("connector")
	}
	if strings.TrimSpace(c.failMode) == "" {
		c.failMode = hookRawFlagValue("fail-mode")
	}
	if !c.managed {
		c.managed = hookRawBoolFlag("enterprise-managed")
	}
	return c
}

// hookFailureExitCode is the exit status of a hook invocation that fails
// before hookexec runs: an unknown flag, a malformed or unlisted flag value,
// a positional argument. Cobra reports these as 1. Kiro treats every status
// other than 0 and 2 as a failed hook, shows its stderr as a warning and
// lets the prompt or tool call go ahead (kiro.dev/docs/hooks/actions). A
// Kiro hook that fails closed (an administrator-managed hook, or fail mode
// closed from the flag, the hook sidecar or DEFENSECLAW_FAIL_MODE, resolved
// as hookexec resolves it) exits 2, the only status Kiro honors as a block.
// A fail-open Kiro hook and every other connector keep 1.
func hookFailureExitCode(failure hookFailureContext) int {
	failure = failure.resolve()
	if strings.EqualFold(strings.TrimSpace(failure.connector), "kiro") && hookPreRunFailsClosed(failure) {
		return 2
	}
	return 1
}

// hookPreRunFailsClosed reports whether the failed invocation's policy is to
// fail closed, with buildHookOptionsForRuntime's precedence: a managed hook
// always does; otherwise --fail-mode, else the sidecar, then an inherited
// DEFENSECLAW_FAIL_MODE (for a packaged hook only when it tightens).
func hookPreRunFailsClosed(failure hookFailureContext) bool {
	if failure.managed || implicitEnterpriseManagedHook() {
		return true
	}
	home, trusted := trustedNativeHookHome()
	if !trusted {
		home = config.DefaultDataPath()
	}
	mode := strings.TrimSpace(failure.failMode)
	if mode == "" {
		mode = hookSidecarFailMode(readHookSidecar(filepath.Join(home, "hooks", ".hookcfg")), failure.connector)
	}
	if v := os.Getenv("DEFENSECLAW_FAIL_MODE"); v != "" && (!trusted || strings.EqualFold(strings.TrimSpace(v), "closed")) {
		mode = v
	}
	return strings.EqualFold(strings.TrimSpace(mode), "closed")
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

// hookRawBoolFlag reports whether the raw arguments set the boolean --name.
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
			ManagedRuntimeFailure: enterpriseManagedHookRuntimeFailureReason(),
		}
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

	if failMode == "" {
		failMode = hookSidecarFailMode(sidecar, connector)
	}
	if v := os.Getenv("DEFENSECLAW_FAIL_MODE"); v != "" {
		if !trustedNativeState || strings.EqualFold(strings.TrimSpace(v), "closed") {
			// A packaged native hook accepts inherited environment only when it
			// tightens policy. Project settings cannot turn a baked closed mode open.
			failMode = v
		}
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
		FailMode:                  failMode,
		Home:                      home,
		HookDir:                   hookDir,
		Token:                     token,
		AuthenticatedManagedToken: authenticatedManagedToken,
		StrictAvailability:        hookEnvTrue(os.Getenv("DEFENSECLAW_STRICT_AVAILABILITY")),
		ManagedEnterprise:         enterpriseManaged,
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
		opts.FailMode = "closed"
		opts.StrictAvailability = true
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
func readHookSidecar(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var current struct {
		Version     int               `json:"version"`
		GatewayAddr string            `json:"gateway_addr"`
		FailModes   map[string]string `json:"fail_modes"`
		LegacyMode  string            `json:"legacy_fail_mode"`
	}
	if json.Unmarshal(data, &current) == nil && current.Version >= 2 {
		out["DEFENSECLAW_GATEWAY_ADDR"] = current.GatewayAddr
		for connector, mode := range current.FailModes {
			out[hookSidecarFailModeKey(connector)] = mode
		}
		if current.LegacyMode != "" {
			out["DEFENSECLAW_FAIL_MODE"] = current.LegacyMode
		}
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
		if key != "" {
			out[key] = val
		}
	}
	return out
}

func hookSidecarFailMode(sidecar map[string]string, connector string) string {
	if mode := sidecar[hookSidecarFailModeKey(connector)]; mode != "" {
		return mode
	}
	return sidecar["DEFENSECLAW_FAIL_MODE"]
}

func hookSidecarFailModeKey(connector string) string {
	name := strings.ToUpper(strings.TrimSpace(connector))
	name = strings.NewReplacer("-", "", "_", "", " ", "").Replace(name)
	return "DEFENSECLAW_FAIL_MODE_" + name
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
