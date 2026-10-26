// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// policies/guardrail/tool-chains.json is the read-only inventory of the fixed
// bounded chains that the CLI and the TUI Protection center show. Chains are
// code-owned in toolChainDefinitions and are not configurable, so the file is
// generated from the catalog plus the display metadata below; never edit it by
// hand. TestToolChainCatalogJSON fails when the checked-in file drifts. After
// changing toolChainDefinitions or toolChainDisplay, regenerate the file and
// refresh the wheel copy:
//
//	DEFENSECLAW_UPDATE_GOLDEN=1 go test ./internal/guardrail -run TestToolChainCatalogJSON
//	make _bundle-data
const (
	toolChainCatalogVersion    = 1
	toolChainCatalogRegenerate = "DEFENSECLAW_UPDATE_GOLDEN=1 go test ./internal/guardrail -run TestToolChainCatalogJSON"

	toolChainNoteAlertOnly = "Alert-only"
	toolChainNoteCanBlock  = "Can block when the profile maps its severity to block and the connector is block-capable"
)

// toolChainDomains are the chain groups the Protection center shows.
var toolChainDomains = []string{
	"sql", "kubernetes", "cloud", "host", "credentials", "data-egress", "network", "security-controls",
}

// toolChainDisplay is the hand-kept domain and note for every chain. The
// domain is the system the steps act on when they need a specific technology
// (sql, kubernetes, cloud, network); otherwise it is the risk the chain guards:
// security-control tampering, credential abuse, sensitive data leaving
// (data-egress), or host execution, persistence and privilege (host). Notes
// use the "Runtime posture" column of
// docs-site/content/docs/policies/deterministic-detection.mdx; a chain that can
// block gets toolChainNoteCanBlock unless the gateway gates it further.
var toolChainDisplay = map[string]struct{ domain, note string }{
	ToolChainGuardrailsOffThenEgress:               {"security-controls", toolChainNoteAlertOnly},
	ToolChainPermissionDeniedThenBypass:            {"security-controls", toolChainNoteAlertOnly},
	ToolChainPrivilegeDiscoveryThenElevation:       {"host", toolChainNoteAlertOnly},
	ToolChainSecretManagerReadThenEgress:           {"data-egress", toolChainNoteAlertOnly},
	ToolChainSecretReadThenEgress:                  {"data-egress", toolChainNoteAlertOnly},
	ToolChainWorkloadIdentityThenLateralExec:       {"kubernetes", toolChainNoteAlertOnly},
	ToolChainDownloadDecodeExecuteSameArtifact:     {"host", toolChainNoteAlertOnly},
	ToolChainDownloadThenExecuteSameArtifact:       {"host", toolChainNoteAlertOnly},
	ToolChainSensitiveEgressArtifactThenExec:       {"data-egress", toolChainNoteAlertOnly},
	ToolChainFirewallExpansionThenDestination:      {"network", "Alert-only until protected-firewall/approved-destination policy exists"},
	ToolChainSQLServerXPCommandShellExecution:      {"sql", "Alert-only until protected-database policy exists"},
	ToolChainPrivilegedKubernetesHostRootExec:      {"kubernetes", "Alert-only until protected-cluster policy exists"},
	ToolChainWirelessCaptureThenDeauthSameBSSID:    {"network", "Alert-only because authorization is deployment-specific"},
	ToolChainSecretsdumpThenPsExecSameIdentity:     {"credentials", "Alert-only until protected-target policy exists"},
	ToolChainCloudIAMPrincipalAdmin:                {"cloud", "Alert-only until protected-account policy exists"},
	ToolChainKubernetesPrivilegedCronJob:           {"kubernetes", "Alert-only until protected-cluster policy exists"},
	ToolChainSQLCommandUDF:                         {"sql", "Alert-only until protected-database policy exists"},
	ToolChainStagedReverseShellPersistence:         {"host", toolChainNoteCanBlock},
	ToolChainEndpointSecurityControlMutation:       {"security-controls", toolChainNoteAlertOnly},
	ToolChainSensitiveReadValueExternalTransmit:    {"data-egress", toolChainNoteAlertOnly},
	ToolChainSensitiveSQLValueCrossResourcePersist: {"sql", toolChainNoteAlertOnly},
	ToolChainCompromisedCredentialThenAuthenticate: {"credentials", toolChainNoteAlertOnly},
	ToolChainADCSCertificateRequestThenPFXAuth:     {"credentials", toolChainNoteCanBlock},
	ToolChainS4UTicketThenKerberosSecretsdump:      {"credentials", toolChainNoteCanBlock},
	// The gateway projects enforcement for this proof only when the active
	// rule pack declares the database protected (the strict pack or the
	// database-destruction-protection pack). With the default or permissive
	// pack it only alerts, even where the policy blocks CRITICAL.
	ToolChainSensitiveSQLiteReadThenUnboundedDelete: {"sql", "Can block only with the strict rule pack or the " +
		"database-destruction-protection pack, when the profile maps its severity to block and the connector is block-capable"},
	ToolChainFileReadThenEmailSameArtifact: {"data-egress", toolChainNoteAlertOnly},
}

// toolChainCatalogFile is the tool-chains.json document.
type toolChainCatalogFile struct {
	Version int                     `json:"version"`
	Chains  []toolChainCatalogEntry `json:"chains"`
}

type toolChainCatalogEntry struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Severity          string   `json:"severity"`
	Domain            string   `json:"domain"`
	CanBlock          bool     `json:"can_block"`
	EventWindow       uint64   `json:"event_window"`
	TimeWindowSeconds int64    `json:"time_window_seconds"`
	Requires          []string `json:"requires"`
	Note              string   `json:"note"`
}

// toolChainRequires turns the matcher flags into the plain phrases listed
// under "Requires". Every chain is confined to one authenticated session.
func toolChainRequires(definition ToolChainDefinition) []string {
	requires := []string{"same session"}
	switch {
	case definition.RequiresExactJoin:
		requires = append(requires, "exact identity join")
	case definition.RequiresEnforcementJoin:
		// Conflicting identities disprove the chain and a missing one still
		// alerts; only enforcement needs the exact join.
		requires = append(requires, "matching identity when known")
	}
	if definition.RequiresValueJoin {
		requires = append(requires, "exact value join")
	}
	if definition.RequiresDistinctResourceJoin {
		requires = append(requires, "distinct destination resource")
	}
	if definition.RequiresTerminalSuccess {
		requires = append(requires, "terminal step succeeded")
	}
	if definition.ArtifactMutationBarrier {
		requires = append(requires, "artifact unchanged")
	}
	if definition.MutationBit != 0 {
		// A chain-specific barrier, such as xp_cmdshell disabled again or the
		// staged payload rewritten, voids the proof for that identity.
		requires = append(requires, "joined object unchanged")
	}
	return requires
}

// buildToolChainCatalog projects the catalog, in catalog order, and reports
// every chain whose display metadata is missing, stale or inconsistent.
func buildToolChainCatalog(definitions []ToolChainDefinition) (toolChainCatalogFile, []string) {
	domains := make(map[string]bool, len(toolChainDomains))
	for _, domain := range toolChainDomains {
		domains[domain] = true
	}
	catalog := toolChainCatalogFile{
		Version: toolChainCatalogVersion,
		Chains:  make([]toolChainCatalogEntry, 0, len(definitions)),
	}
	var problems []string
	listed := make(map[string]bool, len(definitions))
	for _, definition := range definitions {
		listed[definition.ID] = true
		display, ok := toolChainDisplay[definition.ID]
		if !ok {
			problems = append(problems, fmt.Sprintf(
				"chain %s has no domain or note: add it to toolChainDisplay in "+
					"internal/guardrail/tool_chain_catalog_json_test.go", definition.ID))
			continue
		}
		if !domains[display.domain] {
			problems = append(problems, fmt.Sprintf(
				"chain %s has domain %q; use one of %s", definition.ID, display.domain,
				strings.Join(toolChainDomains, ", ")))
		}
		canBlock := !definition.DetectionOnly
		if canBlock && !strings.HasPrefix(display.note, "Can block") {
			problems = append(problems, fmt.Sprintf(
				"chain %s can block (DetectionOnly is false) but its toolChainDisplay note says %q",
				definition.ID, display.note))
		}
		if !canBlock && !strings.HasPrefix(display.note, toolChainNoteAlertOnly) {
			problems = append(problems, fmt.Sprintf(
				"chain %s is detection-only but its toolChainDisplay note says %q",
				definition.ID, display.note))
		}
		catalog.Chains = append(catalog.Chains, toolChainCatalogEntry{
			ID:                definition.ID,
			Title:             definition.Title,
			Severity:          definition.Severity,
			Domain:            display.domain,
			CanBlock:          canBlock,
			EventWindow:       definition.EventWindow,
			TimeWindowSeconds: int64(definition.TimeWindow / time.Second),
			Requires:          toolChainRequires(definition),
			Note:              display.note,
		})
	}
	var stale []string
	for id := range toolChainDisplay {
		if !listed[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(stale)
	for _, id := range stale {
		problems = append(problems, fmt.Sprintf(
			"toolChainDisplay lists %s, which is not in toolChainDefinitions: remove it", id))
	}
	return catalog, problems
}

func renderToolChainCatalog(catalog toolChainCatalogFile) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	// Titles and notes are plain text for the CLI and TUI, not HTML.
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(catalog); err != nil { // Encode ends with a newline.
		return nil, err
	}
	return out.Bytes(), nil
}

func toolChainCatalogPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate policies/guardrail/tool-chains.json")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "policies", "guardrail", "tool-chains.json")
}

// firstDifferentLine returns the 1-based number and content of the first
// line where want and got differ.
func firstDifferentLine(want, got []byte) (int, string, string) {
	wantLines := strings.Split(string(want), "\n")
	gotLines := strings.Split(string(got), "\n")
	for index := 0; index < len(wantLines) || index < len(gotLines); index++ {
		wantLine, gotLine := "(end of file)", "(end of file)"
		if index < len(wantLines) {
			wantLine = wantLines[index]
		}
		if index < len(gotLines) {
			gotLine = gotLines[index]
		}
		if wantLine != gotLine {
			return index + 1, wantLine, gotLine
		}
	}
	return 0, "", ""
}

func TestToolChainCatalogJSON(t *testing.T) {
	t.Parallel()

	catalog, problems := buildToolChainCatalog(ToolChainDefinitions())
	for _, problem := range problems {
		t.Error(problem)
	}
	if len(problems) > 0 {
		return
	}
	rendered, err := renderToolChainCatalog(catalog)
	if err != nil {
		t.Fatalf("encode the chain catalog: %v", err)
	}

	path := toolChainCatalogPath(t)
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, rendered, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("wrote %s; run `make _bundle-data` to refresh the wheel copy", path)
		return
	}

	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\ngenerate it with:\n  %s", path, err, toolChainCatalogRegenerate)
	}
	committed = bytes.ReplaceAll(committed, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(committed, rendered) {
		line, want, got := firstDifferentLine(rendered, committed)
		t.Fatalf("policies/guardrail/tool-chains.json does not match toolChainDefinitions "+
			"(first difference at line %d)\n  want: %s\n  got:  %s\n"+
			"The file is generated; do not edit it by hand. Regenerate it with\n  %s\n"+
			"then run `make _bundle-data` and commit the JSON with the catalog change.",
			line, want, got, toolChainCatalogRegenerate)
	}
}
