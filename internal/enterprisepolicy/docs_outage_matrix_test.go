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
// --enterprise-managed) follow the administrator's fail mode on every OS.
// Every other page links to the table instead of restating it
// (TestOutageBehaviourIsStatedOnlyInTheCapabilityMatrix).

const outageTableLink = "/docs/reference/apis/capability-matrix#gateway-outage"

// Values of the table's managed open column.
const (
	managedOpenBlocksLinuxMacOS     = "blocks-linux-macos"
	managedOpenPerUserRouteBlocksLM = "per-user-route-blocks-linux-macos"
)

type documentedOutage struct {
	PerUserClosed      string `json:"perUserClosed"`
	PerUserOpen        string `json:"perUserOpen"`
	ManagedOpen        string `json:"managedOpen"`
	SecureClientClosed string `json:"secureClientClosed"`
	StrictAvailability string `json:"strictAvailability"`
	EnvFailMode        string `json:"envFailMode"`
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
func codeOutage(conn connector.Connector) documentedOutage {
	outage := connector.ConnectorHookOutage(conn)
	managedOpen := outage.ManagedOpenUnixPerUserRoute
	if outage.ManagedOpenUnixPerUserRoute == connector.OutageBlocks && !connector.IsProxyConnector(conn.Name()) {
		// Linux and macOS only: the Windows standalone hooks follow the
		// administrator's mode. With machine policy (the default where the
		// connector has it) the hook is defenseclaw-hook --enterprise-managed,
		// which follows it too; only the per-user route blocks.
		managedOpen = managedOpenBlocksLinuxMacOS
		if _, machinePolicy := targets[conn.Name()]; machinePolicy {
			managedOpen = managedOpenPerUserRouteBlocksLM
		}
	}
	// Under the default foreign_hooks: remove, a guarded tool call needs a
	// gateway answer for its session even when the native hook's installed
	// mode is open. A locally kept session does not need that answer.
	policy := config.EnterpriseMachinePolicyConfig{}.PolicyFor(conn.Name())
	guardLinux := GuardApplies(conn.Name(), "linux", policy)
	guardDarwin := GuardApplies(conn.Name(), "darwin", policy)
	guardWindows := GuardApplies(conn.Name(), "windows", policy) && !ForeignHookSessionLocal(conn.Name(), "windows")
	switch {
	case guardLinux && guardDarwin && guardWindows:
		managedOpen = connector.OutageBlocks
	case guardLinux && guardDarwin && managedOpen == connector.OutageRuns:
		managedOpen = managedOpenBlocksLinuxMacOS
	}
	env := "no"
	if outage.SecureClientEnvFailMode {
		env = "secure-client"
	}
	return documentedOutage{
		PerUserClosed:      outage.PerUserClosed,
		PerUserOpen:        outage.PerUserOpen,
		ManagedOpen:        managedOpen,
		SecureClientClosed: outage.SecureClientClosed,
		StrictAvailability: outage.StrictAvailability,
		EnvFailMode:        env,
	}
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
		if want := codeOutage(conn); *row.Outage != want {
			t.Errorf("%s: docs outage row %+v, the code says %+v", row.ID, *row.Outage, want)
		}
	}
}

func TestDefaultForeignHookGuardOutageCoversEveryManagedConnector(t *testing.T) {
	rows := map[string]documentedOutage{}
	for _, row := range documentedConnectorRows(t) {
		if row.Outage != nil {
			rows[row.ID] = *row.Outage
		}
	}
	for name := range guardConnectors {
		policy := config.EnterpriseMachinePolicyConfig{}.PolicyFor(name)
		for _, goos := range []string{"linux", "darwin", "windows"} {
			if !GuardApplies(name, goos, policy) {
				t.Errorf("%s: default foreign-hook guard absent on %s", name, goos)
			}
		}
		got := rows[name].ManagedOpen
		if ForeignHookSessionLocal(name, "windows") {
			// Both representations block Linux and macOS. Windows depends on
			// the plugin's own installed fail mode, which differs on the T8 train.
			if got != connector.OutageBlocks && got != managedOpenBlocksLinuxMacOS {
				t.Errorf("%s: managed open outage = %q, want Linux and macOS blocked", name, got)
			}
		} else if got != connector.OutageBlocks {
			t.Errorf("%s: managed open outage = %q, want %q under the default guard", name, got, connector.OutageBlocks)
		}
	}
	policy := config.EnterpriseMachinePolicyConfig{}.PolicyFor(ConnectorHermes)
	if !GuardApplies(ConnectorHermes, "linux", policy) || !GuardApplies(ConnectorHermes, "darwin", policy) || GuardApplies(ConnectorHermes, "windows", policy) {
		t.Error("Hermes foreign-hook guard must apply on Linux and macOS only")
	}
	if got := rows[ConnectorHermes].ManagedOpen; got != managedOpenBlocksLinuxMacOS {
		t.Errorf("Hermes: managed open outage = %q, want %q", got, managedOpenBlocksLinuxMacOS)
	}
}

// Machine policy is the managed route for the connectors that have it. After
// the foreign-hook guard, Copilot and OpenCode use the --enterprise-managed
// hook on Linux and macOS as on Windows.
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
		down: []string{"outage", "gateway is down", "gateway service is not running", "gateway is unreachable", "gateway failure", "gateway cannot give a usable answer",
			"while the gateway", "gateway is stopped", "gateway stops", "gateway cannot answer", "cannot reach the gateway",
			"gateway was stopped", "gateway is not running", "gateway errors"},
		modes: []string{"fail mode", "`open`", "`closed`", "fail-open", "fail open", "fails open", "hook_fail_mode",
			"fail_mode", "failure mode"},
		always: []string{"strict_availability", "defenseclaw_fail_mode", "upstream fail-open", "fails open upstream",
			"fail open upstream", "times out or cannot start", "hook timeout also lets", "timeout does not stop"},
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
		connectorPage := (strings.HasPrefix(rel, "connectors/") || strings.HasPrefix(rel, "reference/connectors/")) && rel != "reference/apis/capability-matrix.mdx" && rel != "connectors/index.mdx"
		for _, sentence := range sentenceBreak.Split(text, -1) {
			sentence = strings.Join(strings.Fields(sentence), " ")
			if rel != "reference/apis/capability-matrix.mdx" && restatement.match(sentence, connectorPage) {
				t.Errorf("%s restates a connector's outage behaviour; link to %s instead: %.240q", rel, outageTableLink, sentence)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range documentedConnectorRows(t) {
		if page := "reference/connectors/" + row.ID + ".mdx"; !linked[page] {
			t.Errorf("%s does not link to %s", page, outageTableLink)
		}
	}
	// The pages that describe fail modes and outages point at the table.
	for _, page := range []string{
		"reference/configuration/fail-modes.mdx", "reference/configuration/source-of-truth.mdx",
		"enterprise/index.mdx", "enterprise/plan/threat-model.mdx", "troubleshooting/enterprise/index.mdx",
		"enterprise/configure/machine-policy.mdx", "troubleshooting/windows.mdx",
		"connectors/amp.mdx", "connectors/copilot.mdx", "connectors/hermes.mdx", "connectors/opencode.mdx",
	} {
		if !linked[page] {
			t.Errorf("%s does not link to the gateway outage table (%s)", page, outageTableLink)
		}
	}
}
