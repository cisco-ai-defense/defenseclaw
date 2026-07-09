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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
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
		connector string
		event     string
		apiAddr   string
		failMode  string
		inputFile string
	)

	cmd := &cobra.Command{
		Use:    "hook",
		Short:  "Run an agent guardrail hook (invoked by the agent runtime)",
		Hidden: true,
		Args:   cobra.NoArgs,
		// The hook is a short-lived per-event subprocess. Skip the daemon's
		// PersistentPreRunE/PostRun (config load, audit store open, OTel init):
		// they are slow, can fail when the gateway is mid-setup, and would
		// hold the audit DB on every keystroke an agent makes.
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		PersistentPostRun: func(*cobra.Command, []string) {},
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := buildHookOptions(connector, event, apiAddr, failMode)
			var input *os.File
			if inputFile != "" {
				if runtime.GOOS != "windows" || connector != "cursor" {
					return fmt.Errorf("--input-file is only supported for the Cursor Windows hook adapter")
				}
				var err error
				input, err = openCursorHookInputFile(opts.HookDir, inputFile)
				if err != nil {
					return err
				}
				opts.Stdin = input
			}
			// hookexec returns the exact agent exit code (0 allow / 2 block).
			// os.Exit is required because cobra collapses RunE outcomes to 0/1.
			code := hookexec.Run(cmd.Context(), opts)
			if input != nil {
				// Preserve hookexec's exact allow/block exit code after it has
				// emitted the vendor response. Process exit also releases the
				// read handle if an unusual filesystem reports a close error.
				_ = input.Close()
			}
			os.Exit(code)
			return nil
		},
	}

	cmd.Flags().StringVar(&connector, "connector", "", "connector name (e.g. claudecode, codex, cursor)")
	cmd.Flags().StringVar(&event, "event", "", "agent hook event name (informational)")
	cmd.Flags().StringVar(&apiAddr, "api-addr", "", "gateway host:port (defaults to the hook sidecar / local gateway)")
	cmd.Flags().StringVar(&failMode, "fail-mode", "", "response-failure policy: open or closed (defaults to the hook sidecar / open)")
	cmd.Flags().StringVar(&inputFile, "input-file", "", "Cursor Windows adapter payload file")
	_ = cmd.Flags().MarkHidden("input-file")
	_ = cmd.MarkFlagRequired("connector")

	return cmd
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
	if !strings.EqualFold(filepath.Clean(filepath.Dir(cleanPath)), filepath.Clean(cleanDir)) {
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

// buildHookOptions resolves the hook configuration from flags plus the same
// environment variables the .sh hooks honor, so the native path and the Bash
// path behave identically. It is factored out of RunE (which calls os.Exit)
// so it can be unit-tested.
func buildHookOptions(connector, event, apiAddr, failMode string) hookexec.Options {
	home := config.DefaultDataPath()
	hookDir := filepath.Join(home, "hooks")

	// Setup writes hooks/.hookcfg on Windows so the agent's hook command can
	// stay free of per-install flags (keeping its trust-hash / match string
	// stable). It supplies the gateway address + fail mode the flags omit.
	sidecar := readHookSidecar(filepath.Join(hookDir, ".hookcfg"))

	if apiAddr == "" {
		apiAddr = os.Getenv("DEFENSECLAW_GATEWAY_ADDR")
	}
	if apiAddr == "" {
		apiAddr = sidecar["DEFENSECLAW_GATEWAY_ADDR"]
	}
	if apiAddr == "" {
		apiAddr = fmt.Sprintf("127.0.0.1:%d", config.DefaultConfig().Gateway.APIPort)
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
		apiAddr = fmt.Sprintf("127.0.0.1:%d", config.DefaultConfig().Gateway.APIPort)
	}

	// Precedence mirrors the .sh `FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-baked}"`:
	// the env var wins, then the explicit flag, then the sidecar's baked value,
	// and finally hookexec's "open" default for an empty string.
	if v := os.Getenv("DEFENSECLAW_FAIL_MODE"); v != "" {
		failMode = v
	}
	if failMode == "" {
		failMode = hookSidecarFailMode(sidecar, connector)
	}

	opts := hookexec.Options{
		Connector:          connector,
		Event:              event,
		APIAddr:            apiAddr,
		FailMode:           failMode,
		Home:               home,
		HookDir:            hookDir,
		Token:              os.Getenv("DEFENSECLAW_GATEWAY_TOKEN"),
		StrictAvailability: hookEnvTrue(os.Getenv("DEFENSECLAW_STRICT_AVAILABILITY")),
		TraceParent: hookFirstNonEmpty(
			os.Getenv("DEFENSECLAW_TRACEPARENT"),
			os.Getenv("TRACEPARENT"),
			os.Getenv("OTEL_TRACEPARENT"),
		),
		TraceState: hookFirstNonEmpty(
			os.Getenv("DEFENSECLAW_TRACESTATE"),
			os.Getenv("TRACESTATE"),
			os.Getenv("OTEL_TRACESTATE"),
		),
	}

	if v := os.Getenv("DEFENSECLAW_HOOK_MAX_BODY"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			opts.MaxBody = n
		}
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
