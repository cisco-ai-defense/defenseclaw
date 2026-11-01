// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 1.0.4 review (loop round 1 of G-hooks-upg, lead directive): the gateway
// outage behaviour of every connector is stated once, in the capability
// matrix's outage table, which enterprisepolicy
// TestDocsCapabilityMatrixOutageMatchesTheHooks checks against
// ConnectorHookOutage. These tests check ConnectorHookOutage against the
// hooks themselves: the call-time reader each per-user render installs (here),
// the running shell hooks (TestShellHookFailureRecordsNameTheOutcomeTheHookApplied),
// the managed per-user-route Copilot hook and Amp and OpenCode plugins
// (TestManagedUnixPerUserRouteCopilotOutageFollowsHookOutage,
// TestManagedPluginOutageFollowsHookOutage) and the native hook (hookexec).

var (
	// The installed mode a render bakes: its top-level FAIL_MODE line (an
	// indented reset to closed inside a failure branch is not the mode). A
	// 1.0.3 or older render baked it as the default of the
	// DEFENSECLAW_FAIL_MODE override; 1.0.4 renders bake the mode itself.
	renderedShellOutageMode = regexp.MustCompile(`(?m)^FAIL_MODE="(?:\$\{DEFENSECLAW_FAIL_MODE:-)?(open|closed)\}?"`)
	// pluginEnvRead matches a read of a DEFENSECLAW_* variable in a rendered
	// plugin or policy bridge (not a comment that names it).
	pluginEnvRead = func(name string) *regexp.Regexp {
		return regexp.MustCompile(`(?:process\.env\.|process\.env\[["']|environ(?:\.get)?\(\s*["']|environ\[["']|getenv\(\s*["'])` + name)
	}
	renderedPluginOutageMode = regexp.MustCompile(`const DC_FAIL_MODE(?:: string)? = "([a-z]*)"`)
)

// renderedHookOutage renders conn's hooks for opts the way Setup does and
// checks the per-user call-time reader or the managed/Secure Client mode.
func renderedHookOutage(t *testing.T, conn Connector, opts SetupOpts) string {
	t.Helper()
	var modes []string
	switch {
	default:
		plugin := hookOnlyPlugin(conn)
		if plugin != nil {
			body, err := plugin.renderPluginArtifact(opts)
			if err != nil {
				t.Fatalf("%s: render plugin: %v", conn.Name(), err)
			}
			pattern := renderedPluginOutageMode
			if perUserOutageRender(opts) {
				// The installed plugin makes its outage decision at call time.
				if !strings.Contains(string(body), "defenseclaw-call-time-outage-v1") ||
					!strings.Contains(string(body), "hook-outage-mode") ||
					strings.Contains(string(body), "DC_OUTAGE_FAIL_MODE") {
					t.Fatalf("%s: per-user plugin does not use the call-time outage decision", conn.Name())
				}
				modes = append(modes, normalizeHookFailMode(opts.HookFailMode))
				break
			}
			for _, m := range pattern.FindAllSubmatch(body, -1) {
				modes = append(modes, string(m[1]))
			}
			break
		}
		owner, ok := conn.(HookScriptOwner)
		if !ok {
			t.Fatalf("%s renders no hook", conn.Name())
		}
		hookDir := filepath.Join(opts.DataDir, "hooks")
		if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
			t.Fatalf("%s: render: %v", conn.Name(), err)
		}
		if perUserOutageRender(opts) {
			// A per-user script bakes closed for other failures; its outage
			// mode comes from the runtime config when the hook is called.
			for _, name := range owner.HookScriptNames(opts) {
				body, err := os.ReadFile(filepath.Join(hookDir, name))
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range renderedShellOutageMode.FindAllSubmatch(body, -1) {
					if string(m[1]) != "closed" {
						t.Fatalf("%s: per-user %s bakes FAIL_MODE=%s, want closed", conn.Name(), name, m[1])
					}
				}
			}
			helper, err := os.ReadFile(filepath.Join(hookDir, "_hardening.sh"))
			if err != nil || !strings.Contains(string(helper), "defenseclaw-call-time-outage-v1") ||
				!strings.Contains(string(helper), "hook-outage-mode") {
				t.Fatalf("%s: per-user hook does not use the call-time outage decision: %v", conn.Name(), err)
			}
			modes = append(modes, normalizeHookFailMode(opts.HookFailMode))
			break
		}
		for _, name := range owner.HookScriptNames(opts) {
			body, err := os.ReadFile(filepath.Join(hookDir, name))
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range renderedShellOutageMode.FindAllSubmatch(body, -1) {
				modes = append(modes, string(m[1]))
			}
		}
	}
	if len(modes) == 0 {
		t.Fatalf("%s: no rendered outage fail mode (managed %v, hook socket %q, Secure Client delivery %v)",
			conn.Name(), opts.ManagedEnterprise, opts.ManagedHookSocket, opts.SecureClientHookDelivery)
	}
	for _, mode := range modes[1:] {
		if mode != modes[0] {
			t.Fatalf("%s: rendered hooks disagree on the outage fail mode: %v", conn.Name(), modes)
		}
	}
	switch modes[0] {
	case "closed":
		return OutageBlocks
	case "open":
		return OutageRuns
	}
	t.Fatalf("%s: rendered outage fail mode %q", conn.Name(), modes[0])
	return ""
}

// hookOnlyPlugin is conn's in-agent plugin connector, nil for a connector
// with hook scripts.
func hookOnlyPlugin(conn Connector) *hookOnlyConnector {
	switch c := conn.(type) {
	case *AMPConnector:
		return c.hookOnlyConnector
	case *hookOnlyConnector:
		if c.pluginArtifact {
			return c
		}
	}
	return nil
}

func TestHookOutageMatchesTheRenderedHooks(t *testing.T) {
	for _, conn := range newBuiltinConnectors() {
		name := conn.Name()
		outage := ConnectorHookOutage(conn)
		if IsProxyConnector(name) {
			if outage.PerUserClosed != OutageBlocks || outage.PerUserOpen != OutageBlocks ||
				outage.ManagedOpenUnixPerUserRoute != OutageBlocks || outage.SecureClientClosed != OutageBlocks {
				t.Errorf("%s is proxy-backed: its requests are blocked while the gateway is down, got %+v", name, outage)
			}
			continue
		}
		t.Run(name, func(t *testing.T) {
			base := func() SetupOpts {
				root := t.TempDir()
				return SetupOpts{DataDir: filepath.Join(root, "defenseclaw"), APIAddr: "127.0.0.1:18970",
					HookAPIToken: "connector-scoped-token", HookAPITokenScoped: true}
			}
			for _, mode := range []string{"closed", "open"} {
				want := outage.PerUserClosed
				if mode == "open" {
					want = outage.PerUserOpen
				}
				for _, guardrail := range []string{"observe", "action"} {
					opts := base()
					opts.HookFailMode, opts.GuardrailMode = mode, guardrail
					expected := want
					if got := renderedHookOutage(t, conn, opts); got != expected {
						t.Errorf("per-user, fail mode %s, %s mode: hooks render %s, HookOutage says %s", mode, guardrail, got, want)
					}
				}

				// A managed standalone Linux or macOS per-user route: the
				// hook socket. Closed (the default) blocks on every route.
				opts := base()
				guard := filepath.Join(filepath.Dir(opts.DataDir), "defenseclaw-hook")
				opts.ManagedEnterprise, opts.HookFailMode, opts.GuardrailMode = true, mode, "observe"
				opts.ManagedHookSocket, opts.ManagedServiceUID = filepath.Join(filepath.Dir(opts.DataDir), "hook.sock"), os.Getuid()
				opts.ManagedHookBinary, opts.ForeignHookGuardBinary = guard, guard
				want = OutageBlocks
				if mode == "open" {
					want = outage.ManagedOpenUnixPerUserRoute
				}
				if got := renderedHookOutage(t, conn, opts); got != want {
					t.Errorf("managed Linux and macOS per-user route, fail mode %s: hooks render %s, HookOutage says %s", mode, got, want)
				}

				// The Windows standalone plugin render (the guard, no hook
				// socket) follows the mode, except a plugin that blocks the
				// outage on every OS; the Windows shell connectors run the
				// native hook (hookexec tests).
				if hookOnlyPlugin(conn) != nil {
					opts = base()
					opts.ManagedEnterprise, opts.HookFailMode, opts.ForeignHookGuardBinary = true, mode, guard
					want = map[string]string{"closed": OutageBlocks, "open": OutageRuns}[mode]
					if outage.ManagedPluginOutageClosedEveryOS {
						want = OutageBlocks
					}
					if got := renderedHookOutage(t, conn, opts); got != want {
						t.Errorf("managed Windows plugin, fail mode %s: hooks render %s, want %s", mode, got, want)
					}
				}

				// Secure Client follows the mode it is given, and lowers
				// closed for an agent without a fail-closed hook. Only an
				// authenticated Secure Client deployment renders that profile.
				opts = base()
				opts.ManagedEnterprise, opts.HookFailMode, opts.SecureClientHookDelivery = true, mode, true
				want = OutageRuns
				if mode == "closed" {
					want = outage.SecureClientClosed
				}
				verified := SecureClientDeploymentVerified
				SecureClientDeploymentVerified = func() bool { return true }
				if mode == "closed" {
					want = ConnectorHookOutage(conn).SecureClientClosed
				}
				got := renderedHookOutage(t, conn, opts)
				SecureClientDeploymentVerified = verified
				if got != want {
					t.Errorf("Secure Client, fail mode %s: hooks render %s, HookOutage says %s", mode, got, want)
				}
			}
		})
	}
}

// The DEFENSECLAW_FAIL_MODE column: only the Secure Client delivery render
// of the hooks HookOutage names reads the variable; no other render does.
func TestHookOutageEnvFailModeMatchesTheRenderedHooks(t *testing.T) {
	for _, conn := range newBuiltinConnectors() {
		name := conn.Name()
		if IsProxyConnector(name) {
			continue
		}
		// Rule 16: the installed mode is the only fail-mode source, on every
		// profile, Secure Client delivery included (1a229d8335).
		want := false
		var bodies [][]byte
		if plugin := hookOnlyPlugin(conn); plugin != nil {
			for _, managed := range []bool{false, true} {
				opts := SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970", HookFailMode: "closed",
					ManagedEnterprise: managed, SecureClientHookDelivery: managed}
				body, err := plugin.renderPluginArtifact(opts)
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, body)
			}
		} else {
			names := conn.(HookScriptOwner).HookScriptNames(SetupOpts{})
			for _, delivery := range []bool{false, true} {
				for _, managed := range []bool{false, true} {
					scripts, err := renderHookScripts("127.0.0.1:18970", "closed", ".token", names, managed, name, true, "", "", managed, delivery, "")
					if err != nil {
						t.Fatal(err)
					}
					for _, script := range scripts {
						reads := strings.Contains(string(script.body), perUserEnvFailModeRead)
						expected := want && managed && delivery
						if strings.HasPrefix(script.name, "inspect-") {
							expected = false // the shared scripts serve every connector
						}
						if reads != expected {
							t.Errorf("%s %s (Secure Client %v, delivery %v): reads DEFENSECLAW_FAIL_MODE = %v, want %v",
								name, script.name, managed, delivery, reads, want)
						}
					}
				}
			}
			continue
		}
		if want {
			t.Errorf("%s: HookOutage says its Secure Client hook reads DEFENSECLAW_FAIL_MODE; only shell hooks do", name)
		}
		for _, body := range bodies {
			if pluginEnvRead("DEFENSECLAW_FAIL_MODE").Match(body) {
				t.Errorf("%s: rendered plugin or bridge reads DEFENSECLAW_FAIL_MODE", name)
			}
		}
	}
}

// The strict availability column for the hooks that are not shell scripts
// (the running shell hooks are checked in
// TestShellHookFailureRecordsNameTheOutcomeTheHookApplied): a plugin or
// policy bridge that HookOutage says does not read the variable never names
// it, and one that reads it does.
func TestHookOutageStrictAvailabilityMatchesThePlugins(t *testing.T) {
	for _, conn := range newBuiltinConnectors() {
		var body []byte
		var err error
		opts := SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970", HookFailMode: "open"}
		if plugin := hookOnlyPlugin(conn); plugin != nil {
			body, err = plugin.renderPluginArtifact(opts)
		} else {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		strict := ConnectorHookOutage(conn).StrictAvailability
		reads := pluginEnvRead("DEFENSECLAW_STRICT_AVAILABILITY").Match(body)
		if reads != (strict == StrictAvailabilityRead) {
			t.Errorf("%s: rendered per-user hook names DEFENSECLAW_STRICT_AVAILABILITY = %v, HookOutage.StrictAvailability = %q", conn.Name(), reads, strict)
		}
	}
}
