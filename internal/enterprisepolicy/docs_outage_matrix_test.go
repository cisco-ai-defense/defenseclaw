// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// 1.0.4 lead directive (G-hooks-upg loop round 1): what each connector's
// hooks do during a gateway outage is stated once, in the gateway outage
// table of the connectors capability matrix
// (docs-site/data/capability-matrix.json, "outage"). The table is checked
// here against the code: connector.ConnectorHookOutage, whose fields the
// connector and hookexec tests check against the hooks, and the machine
// policy targets of this package, whose managed hooks (defenseclaw-hook
// --enterprise-managed) follow the administrator's fail mode on every OS,
// and the foreign-hook guard (GuardBlocksOutage), which with the default
// foreign_hooks: remove blocks a guarded connector's call in every fail mode
// while the gateway cannot answer for the agent session (internal/cli
// TestOutageTableManagedOpenMatchesAFullManagedCall runs that call).
// Every other page links to the table instead of restating it
// (TestOutageBehaviourIsStatedOnlyInTheCapabilityMatrix).

const outageTableLink = "/docs/reference/apis/capability-matrix#gateway-outage"

// Values of the table's managed open columns.
const (
	managedOpenRuns                 = "runs"
	managedOpenBlocks               = "blocks"
	managedOpenBlocksLinuxMacOS     = "blocks-linux-macos"
	managedOpenPerUserRouteBlocksLM = "per-user-route-blocks-linux-macos"
	managedOpenPerUserRouteBlocks   = "per-user-route-blocks"
	// The default managed_hooks_only: enforce turns on the vendor lock and
	// leaves the guard off; preserve turns the guard on.
	managedOpenRunsBlocksWithHooksOnlyPreserve = "runs-blocks-with-hooks-only-preserve"
)

var outageTableOSes = []string{"linux", "darwin", "windows"}

type documentedOutage struct {
	PerUserClosed string `json:"perUserClosed"`
	PerUserOpen   string `json:"perUserOpen"`
	// ManagedOpen is the administrator's open with the default machine
	// policy (foreign_hooks: remove, so the foreign-hook guard runs where it
	// covers the connector); ManagedOpenNoGuard with foreign_hooks report or
	// allow, where only the hook decides.
	ManagedOpen        string `json:"managedOpen"`
	ManagedOpenNoGuard string `json:"managedOpenNoGuard"`
	SecureClientClosed string `json:"secureClientClosed"`
	StrictAvailability string `json:"strictAvailability"`
}

func repoRoot() string { return filepath.Join("..", "..") }

func documentedConnectorRows(t *testing.T) []struct {
	ID     string            `json:"id"`
	Label  string            `json:"label"`
	Outage *documentedOutage `json:"outage"`
} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "docs-site", "data", "capability-matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var matrix struct {
		Connectors []struct {
			ID     string            `json:"id"`
			Label  string            `json:"label"`
			Outage *documentedOutage `json:"outage"`
		} `json:"connectors"`
	}
	if err := json.Unmarshal(raw, &matrix); err != nil {
		t.Fatal(err)
	}
	return matrix.Connectors
}

// codeOutage is the table row the code gives for conn.
func codeOutage(t *testing.T, conn connector.Connector) documentedOutage {
	outage := connector.ConnectorHookOutage(conn)
	// The Secure Client column is an authenticated Secure Client deployment:
	// only there do the hooks render that profile.
	verified := connector.SecureClientDeploymentVerified
	connector.SecureClientDeploymentVerified = func() bool { return true }
	outage.SecureClientClosed = connector.ConnectorHookOutage(conn).SecureClientClosed
	connector.SecureClientDeploymentVerified = verified
	noGuard := outage.ManagedOpenUnixPerUserRoute
	if outage.ManagedOpenUnixPerUserRoute == connector.OutageBlocks && !connector.IsProxyConnector(conn.Name()) {
		// Linux and macOS only: the Windows standalone hooks follow the
		// administrator's mode. With machine policy (the default where the
		// connector has it) the hook is defenseclaw-hook --enterprise-managed,
		// which follows it too; only the per-user route blocks.
		noGuard = managedOpenBlocksLinuxMacOS
		_, machinePolicy := targets[conn.Name()]
		switch {
		case outage.ManagedPluginOutageClosedEveryOS && machinePolicy:
			noGuard = managedOpenPerUserRouteBlocks
		case outage.ManagedPluginOutageClosedEveryOS:
			// The plugin's Windows standalone render blocks too.
			noGuard = connector.OutageBlocks
		case machinePolicy:
			noGuard = managedOpenPerUserRouteBlocksLM
		}
	}
	managedOpen := managedOpenWithDefaultGuard(t, conn.Name(), noGuard)
	return documentedOutage{
		PerUserClosed:      outage.PerUserClosed,
		PerUserOpen:        outage.PerUserOpen,
		ManagedOpen:        managedOpen,
		ManagedOpenNoGuard: noGuard,
		SecureClientClosed: outage.SecureClientClosed,
		StrictAvailability: outage.StrictAvailability,
	}
}

// managedOpenWithDefaultGuard is the managed open cell under the default
// machine policy: on each OS the call blocks where the foreign-hook guard
// blocks the outage (GuardBlocksOutage) and otherwise does what the hook
// does (noGuard, the cell for foreign_hooks report or allow).
func managedOpenWithDefaultGuard(t *testing.T, name, noGuard string) string {
	t.Helper()
	policy := config.EnterpriseMachinePolicyConfig{}.PolicyFor(name)
	preserve := policy
	preserve.ManagedHooksOnly = config.ManagedHooksOnlyPreserve
	guard, guardPreserve := map[string]bool{}, map[string]bool{}
	for _, goos := range outageTableOSes {
		guard[goos] = GuardBlocksOutage(name, goos, policy)
		guardPreserve[goos] = GuardBlocksOutage(name, goos, preserve)
	}
	all := func(m map[string]bool) bool { return m["linux"] && m["darwin"] && m["windows"] }
	none := func(m map[string]bool) bool { return !m["linux"] && !m["darwin"] && !m["windows"] }
	switch {
	case all(guard):
		return managedOpenBlocks
	case guard["linux"] && guard["darwin"] && !guard["windows"]:
		// Windows does what the hook does: every no-guard value but blocks
		// lets a Windows outage call run.
		if noGuard == managedOpenBlocks {
			return managedOpenBlocks
		}
		return managedOpenBlocksLinuxMacOS
	case none(guard) && all(guardPreserve) && noGuard == managedOpenRuns:
		return managedOpenRunsBlocksWithHooksOnlyPreserve
	case none(guard) && none(guardPreserve):
		return noGuard
	}
	t.Errorf("%s: no table value for a guard that blocks an outage on %v (%v with managed_hooks_only preserve) over %q; add one", name, guard, guardPreserve, noGuard)
	return ""
}

func TestDocsCapabilityMatrixOutageMatchesTheHooks(t *testing.T) {
	registry := connector.NewDefaultRegistry()
	rows := documentedConnectorRows(t)
	if len(rows) != registry.Len() {
		t.Errorf("capability matrix has %d connectors, the registry %d", len(rows), registry.Len())
	}
	for _, row := range rows {
		conn, ok := registry.Get(row.ID)
		if !ok {
			t.Errorf("capability matrix connector %q is not a built-in connector", row.ID)
			continue
		}
		if row.Outage == nil {
			t.Errorf("%s: capability matrix row has no outage entry", row.ID)
			continue
		}
		if want := codeOutage(t, conn); *row.Outage != want {
			t.Errorf("%s: docs outage row %+v, the code says %+v", row.ID, *row.Outage, want)
		}
	}
}

// Machine policy is the managed route for the connectors that have it: the
// managed Copilot and OpenCode hooks that the table says follow the mode are
// the --enterprise-managed command, on Linux and macOS as on Windows.
func TestOutageTableMachinePolicyRouteRunsTheManagedHook(t *testing.T) {
	for name, target := range targets {
		if target.Name() != name {
			t.Errorf("machine policy target %q is named %q", name, target.Name())
		}
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		opts := Options{GOOS: goos, HookBinary: map[string]string{"windows": `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`}[goos]}
		if opts.HookBinary == "" {
			opts.HookBinary = "/opt/defenseclaw/bin/defenseclaw-hook"
		}
		raw, err := encodeOrdered(copilotHandler(opts, "preToolUse", 30))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "--enterprise-managed") {
			t.Errorf("%s: the machine-policy Copilot hook is not the managed hook binary: %s", goos, raw)
		}
	}
	if !strings.Contains(string(OpenCodeManagedPlugin()), `"--enterprise-managed"`) {
		t.Error("the machine-policy OpenCode plugin does not run the managed hook binary")
	}
}

// outageRestatement matches a sentence that restates a connector's outage
// behaviour: one that names a connector (on a connector's own page, any
// sentence) and either an environment override of the outage, the upstream
// fail-open of an agent, or a gateway outage together with a fail mode.
type outageRestatement struct {
	labels []string
	down   []string
	modes  []string
	always []string
}

func newOutageRestatement(t *testing.T) outageRestatement {
	r := outageRestatement{
		down: []string{"outage", "gateway is down", "gateway service is not running", "gateway is unreachable",
			"while the gateway", "gateway is stopped", "gateway stops", "gateway cannot answer", "cannot reach the gateway",
			"gateway was stopped", "gateway is not running", "gateway errors"},
		modes: []string{"fail mode", "`open`", "`closed`", "fail-open", "fail open", "fails open", "hook_fail_mode",
			"fail_mode", "failure mode"},
		always: []string{"strict_availability", "defenseclaw_fail_mode", "upstream fail-open", "fails open upstream",
			"fail open upstream"},
	}
	for _, row := range documentedConnectorRows(t) {
		r.labels = append(r.labels, row.Label)
	}
	r.labels = append(r.labels, "Copilot")
	return r
}

func (r outageRestatement) match(sentence string, connectorPage bool) bool {
	if strings.Contains(sentence, outageTableLink) && !outcomeWord.MatchString(sentence) {
		return false // a pointer to the table
	}
	named := connectorPage
	for _, label := range r.labels {
		if strings.Contains(sentence, label) {
			named = true
		}
	}
	if !named {
		return false
	}
	low := strings.ToLower(sentence)
	has := func(terms []string) bool {
		for _, term := range terms {
			if strings.Contains(low, strings.ToLower(term)) {
				return true
			}
		}
		return false
	}
	return has(r.always) || (has(r.down) && has(r.modes))
}

// outcomeWord is a word that states what an outage does; a sentence that
// only points at the table has none.
var outcomeWord = regexp.MustCompile(`(?i)\b(?:block|blocks|blocked|run|runs|allow|allows|allowed|deny|denies|denied|lets?)\b`)

var sentenceBreak = regexp.MustCompile(`(?:[.!?])\s+|\s\|\s|\n\s*\n`)

func TestOutageBehaviourIsStatedOnlyInTheCapabilityMatrix(t *testing.T) {
	restatement := newOutageRestatement(t)
	docs := filepath.Join(repoRoot(), "docs-site", "content", "docs")
	linked := map[string]bool{}
	err := filepath.WalkDir(docs, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".mdx") {
			return err
		}
		rel, err := filepath.Rel(docs, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(data)
		if strings.Contains(text, outageTableLink) {
			linked[rel] = true
		}
		connectorPage := strings.HasPrefix(rel, "connectors/") && rel != "connectors/index.mdx"
		for _, sentence := range sentenceBreak.Split(text, -1) {
			sentence = strings.Join(strings.Fields(sentence), " ")
			if restatement.match(sentence, connectorPage) {
				t.Errorf("%s restates a connector's outage behaviour; link to %s instead: %.240q", rel, outageTableLink, sentence)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The pages that describe fail modes and outages point at the table.
	for _, page := range []string{
		"reference/configuration/fail-modes.mdx", "enterprise/plan/threat-model.mdx",
		"enterprise/configure/machine-policy.mdx", "enterprise/configure/foreign-hook-guard.mdx",
		"connectors/amp.mdx", "connectors/copilot.mdx", "connectors/hermes.mdx", "connectors/opencode.mdx",
	} {
		if !linked[page] {
			t.Errorf("%s does not link to the gateway outage table (%s)", page, outageTableLink)
		}
	}
}
