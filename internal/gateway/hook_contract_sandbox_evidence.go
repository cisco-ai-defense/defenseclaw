package gateway

// F9: the hook-contract gate and the sandbox-only layout.
//
// In the layout the OpenShell sandbox documentation recommends - no agent
// installed on the host, the agent inside the harness image - the guardrail
// could not be put into action mode. Both admission paths asked for the
// connector's host agent version, found none, resolved the contract to
// "unversioned" and refused - even though the host held a stronger fact than a
// probe produces: the harness image DefenseClaw itself built, pinned a harness
// version into, and verified by proving that a denied tool call does not run
// (image.Builder.VerifyHooks, which is what sets Record.HookFireVerified).
//
// This file supplies that fact to those two paths. It is deliberately narrow:
//
//   - it applies only when the host has no agent version at all, so a host
//     verdict always keeps its authority;
//   - it applies only when the connector's effective guardrail mode is action,
//     which is the mode that refuses an unversioned contract;
//   - it accepts only a record whose hooks were fire-verified, whose harness
//     version resolves to a Known sandbox contract, and that this same
//     DefenseClaw release built.
//
// Everything else keeps refusing exactly as before: an unknown host version, a
// missing or unverified image, a harness version without a reviewed contract,
// and (independently, in the callers) a contract that drifted from the lock.

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// sandboxHarnessContract is the hook contract of a connector's verified
// harness image, together with the record it came from so a caller can name
// its evidence.
type sandboxHarnessContract struct {
	Resolution connector.HookContractResolution
	Record     image.Record
}

// sandboxHarnessHookContract returns the contract of the newest verified
// harness image recorded for connectorName, when that contract is Known.
// No record, no fire-verified record, no harness version, an image from
// another DefenseClaw release or an unknown contract are all reported as
// (false, nil): the caller keeps its host-based verdict.
func sandboxHarnessHookContract(dataDir, connectorName string) (sandboxHarnessContract, bool, error) {
	return sandboxHarnessHookContractFor(dataDir, connectorName, version.Current().BinaryVersion)
}

// sandboxHarnessHookContractFor is sandboxHarnessHookContract with the release
// pinned by the caller, so tests can exercise the "image built by another
// release" rule without depending on the test binary's build metadata.
func sandboxHarnessHookContractFor(dataDir, connectorName, release string) (sandboxHarnessContract, bool, error) {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	if strings.TrimSpace(dataDir) == "" || name == "" {
		return sandboxHarnessContract{}, false, nil
	}
	records, err := image.NewStore(dataDir).List()
	if err != nil {
		return sandboxHarnessContract{}, false, fmt.Errorf("sandbox harness hook contract: %w", err)
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].BuiltAt.After(records[j].BuiltAt) })
	currentRelease := release
	for _, rec := range records {
		if !rec.HookFireVerified {
			continue
		}
		if strings.ToLower(strings.TrimSpace(rec.Connector)) != name {
			continue
		}
		harnessVersion := strings.TrimSpace(rec.HarnessVersion)
		if harnessVersion == "" {
			continue
		}
		// An image built by another release carries the hooks that release
		// rendered. A record that names no release at all cannot be shown to be
		// this release's evidence either. Both are refused; the operator rebuilds
		// the image instead.
		if currentRelease != "" && strings.TrimSpace(rec.DefenseClawVersion) != currentRelease {
			continue
		}
		resolution := connector.ResolveSandboxHookContract(rec.Connector, harnessVersion)
		if resolution.Status != connector.HookCompatibilityKnown {
			continue
		}
		resolution.Reason = harnessEvidenceReason(rec, resolution.Reason)
		return sandboxHarnessContract{Resolution: resolution, Record: rec}, true, nil
	}
	return sandboxHarnessContract{}, false, nil
}

// harnessEvidenceReason names the evidence a sandbox-derived resolution came
// from, appended to whatever the contract table said. It reaches the hook
// contract lock's compatibility_reason and the gateway log, so an operator can
// see why an enforcing hook was installed without a host agent.
func harnessEvidenceReason(rec image.Record, reason string) string {
	evidence := fmt.Sprintf(
		"resolved from the verified harness image %s (harness %s, contract %s, hook-fire probe passed %s)",
		rec.Tag, strings.TrimSpace(rec.HarnessVersion), rec.HookContract,
		rec.HookFireVerifiedAt.UTC().Format(time.RFC3339),
	)
	if strings.TrimSpace(reason) == "" {
		return evidence
	}
	return reason + "; " + evidence
}

// applySandboxHarnessEvidence replaces a host verdict that has no version to
// resolve with the verified harness image's contract, when the connector's
// effective guardrail mode is action. Every other case returns its inputs
// unchanged, so a host agent, an observe-mode connector and a connector with
// no verified image behave exactly as before.
func (s *Sidecar) applySandboxHarnessEvidence(connectorName, agentVersion string, resolution connector.HookContractResolution) (string, connector.HookContractResolution) {
	if s == nil || s.currentConfig() == nil {
		return agentVersion, resolution
	}
	if strings.TrimSpace(agentVersion) != "" || resolution.Status == connector.HookCompatibilityKnown {
		return agentVersion, resolution
	}
	if !strings.EqualFold(strings.TrimSpace(s.currentConfig().EffectiveGuardrailModeForConnector(connectorName)), "action") {
		return agentVersion, resolution
	}
	evidence, ok, err := sandboxHarnessHookContract(s.currentConfig().DataDir, connectorName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] connector %s: sandbox harness evidence unreadable: %v\n", connectorName, err)
		return agentVersion, resolution
	}
	if !ok {
		return agentVersion, resolution
	}
	fmt.Fprintf(os.Stderr,
		"[guardrail] connector %s: action mode admitted without a host agent, on the verified harness image %s (harness %s, contract %s, hook-fire probe passed %s)\n",
		connectorName, evidence.Record.Tag, strings.TrimSpace(evidence.Record.HarnessVersion),
		evidence.Resolution.Contract.ContractID, evidence.Record.HookFireVerifiedAt.UTC().Format(time.RFC3339))
	return strings.TrimSpace(evidence.Record.HarnessVersion), evidence.Resolution
}
