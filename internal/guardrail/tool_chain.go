// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const (
	// ToolChainCount and the bounds below are deliberately fixed. This is a
	// small policy primitive for the authenticated tool-call hook, not a
	// user-configurable correlation engine.
	ToolChainCount           = 18
	ToolChainLegacyCount     = 13
	ToolChainKnownStepMask   = uint64(1<<44 - 1)
	ToolChainKnownResultMask = uint32(1<<ToolChainCount - 1)
	// ToolChainReservedSignBit is never allocated. SQLite INTEGER is signed,
	// so persisted step masks must remain below this bit even though the in-
	// process representation is uint64.
	ToolChainReservedSignBit = uint64(1 << 63)
	// ToolChainReservedResultSignBit is never allocated. Result masks use
	// uint32 in process, but their SQLite INTEGER representation remains
	// intentionally bounded below this bit.
	ToolChainReservedResultSignBit = uint32(1 << 31)
	// ToolChainArtifactMutationBarrier is a content-free invalidation marker.
	// An intervening event that may change file bytes prevents path identity
	// from being treated as continuity of the same artifact.
	ToolChainArtifactMutationBarrier = uint64(1 << 19)
	// ToolChainMaxEvents is intentionally small: a contextual decision may
	// inspect only the current action and eight predecessors from the same
	// authenticated session. Individual chain definitions may impose a smaller
	// bound. Longer-range correlation is useful telemetry, but
	// is not a deterministic blocking proof.
	ToolChainMaxEvents     = uint64(9)
	ToolChainMaxPartitions = 4096
	ToolChainReceiptTTL    = 7 * 24 * time.Hour
	ToolChainMaxHorizon    = 30 * time.Minute

	ToolChainGuardrailsOffThenEgress            = "chain.guardrails_off_then_egress"
	ToolChainPermissionDeniedThenBypass         = "chain.permission_denied_then_runtime_bypass"
	ToolChainPrivilegeDiscoveryThenElevation    = "chain.privilege_discovery_then_elevation"
	ToolChainSecretManagerReadThenEgress        = "chain.secret_manager_read_then_egress"
	ToolChainSecretReadThenEgress               = "chain.secret_read_then_egress"
	ToolChainWorkloadIdentityThenLateralExec    = "chain.workload_identity_then_lateral_execution"
	ToolChainDownloadDecodeExecuteSameArtifact  = "chain.download_decode_execute_same_artifact"
	ToolChainDownloadThenExecuteSameArtifact    = "chain.download_then_execute_same_artifact"
	ToolChainSensitiveEgressArtifactThenExec    = "chain.sensitive_egress_artifact_then_execute"
	ToolChainFirewallExpansionThenDestination   = "chain.firewall_trust_expansion_then_destination_use"
	ToolChainSQLServerXPCommandShellExecution   = "chain.sqlserver_xp_cmdshell_enable_then_invoke"
	ToolChainPrivilegedKubernetesHostRootExec   = "chain.kubernetes_privileged_host_root_write_apply_exec"
	ToolChainWirelessCaptureThenDeauthSameBSSID = "chain.wireless_capture_then_deauth_same_bssid"
	ToolChainSecretsdumpThenPsExecSameIdentity  = "chain.secretsdump_then_psexec_same_target_principal"
	ToolChainCloudIAMPrincipalAdmin             = "chain.cloud_iam_principal_create_then_admin_attach_same_principal"
	ToolChainKubernetesPrivilegedCronJob        = "chain.kubernetes_privileged_cronjob_patch_then_create_job"
	ToolChainSQLCommandUDF                      = "chain.sql_command_udf_create_then_invoke_same_function"
	ToolChainStagedReverseShellPersistence      = "chain.reverse_shell_payload_write_then_persistence_install_same_artifact"
	toolChainProjectionFingerprintDomain        = "defenseclaw.tool-chain.projection.v2"
	toolChainWideProjectionFingerprintDomain    = "defenseclaw.tool-chain.projection.v3-wide"
	toolChainRulesetFingerprintDomain           = "defenseclaw.tool-chain.ruleset.v1"
	toolChainDefinitionFingerprintDomain        = "defenseclaw.tool-chain.definition.v1"
	toolChainCatalogFingerprintDomain           = "defenseclaw.tool-chain.catalog.v1"
	toolChainRelevantSemanticProjection         = "actionfacts-v10-staged-reverse-shell-persistence-lineage"
	toolChainRelevantEnforcementProjection      = "enforcement-proof-v1"
	toolChainRelevantFallbackProjection         = "owner-local-fallback-v1"
	toolChainRelevantExternalEgressProjection   = "external-egress-v1"
	toolChainRelevantN13Projection              = "n13-lateral-exec-proof-v1"
	toolChainRelevantH18Projection              = "h18-system-root-proof-v1"
)

// ToolChainDefinition is the immutable private catalog entry for one bounded
// ordered behavior. Step bits are stable storage ABI.
type ToolChainDefinition struct {
	ID                      string
	Version                 string
	Title                   string
	Severity                string
	EventWindow             uint64
	TimeWindow              time.Duration
	Step1Bit                uint64
	Step2Bit                uint64
	Step3Bit                uint64
	MutationBit             uint64
	ResultBit               uint32
	Revision                string
	RequiresEnforcementJoin bool
	RequiresExactJoin       bool
	RequiresTerminalSuccess bool
	ArtifactMutationBarrier bool
	DetectionOnly           bool
	// OutputJoinFromFirst selects a three-step proof whose source action knows
	// the terminal identity while the middle action knows only the input
	// artifact. This is used for manifest write -> apply -> named-pod exec.
	OutputJoinFromFirst bool
}

var toolChainDefinitions = [...]ToolChainDefinition{
	{
		ID: ToolChainGuardrailsOffThenEgress, Version: "1.5",
		Title:       "Guardrails disabled before external egress",
		EventWindow: 8, TimeWindow: 30 * time.Minute, Revision: "n20-to-data-external-egress-bounded8-v2",
	},
	{
		ID: ToolChainPermissionDeniedThenBypass, Version: "1.4",
		Title:       "Permission denial followed by runtime bypass",
		EventWindow: 8, TimeWindow: 5 * time.Minute, Revision: "permission-denial-to-n08-bounded8-v2",
	},
	{
		ID: ToolChainPrivilegeDiscoveryThenElevation, Version: "1.4",
		Title:       "Privilege discovery followed by elevation",
		EventWindow: 8, TimeWindow: 15 * time.Minute, Revision: "h18-system-root-to-h21-n12-n11-bounded8-v2",
	},
	{
		ID: ToolChainSecretManagerReadThenEgress, Version: "1.6",
		Title:       "Secret-manager read followed by external egress",
		EventWindow: 8, TimeWindow: 30 * time.Minute, Revision: "n03-to-data-external-egress-bounded8-v2",
	},
	{
		ID: ToolChainSecretReadThenEgress, Version: "1.7",
		Title:       "Secret read followed by external egress",
		Severity:    "CRITICAL",
		EventWindow: 8, TimeWindow: 30 * time.Minute, Revision: "h01-h07-n01-n02-n04-to-data-external-egress-bounded8-v2",
		RequiresEnforcementJoin: true,
		ArtifactMutationBarrier: true,
	},
	{
		ID: ToolChainWorkloadIdentityThenLateralExec, Version: "1.7",
		Title:       "Workload identity access followed by lateral execution",
		EventWindow: 8, TimeWindow: 15 * time.Minute, Revision: "n04-to-n13-bounded8-v2",
	},
	{
		ID: ToolChainDownloadDecodeExecuteSameArtifact, Version: "1.0",
		Title:       "Remote artifact downloaded, decoded, and executed",
		Severity:    "CRITICAL",
		EventWindow: 8, TimeWindow: 30 * time.Minute,
		Revision:                "public-remote-download-to-exact-decode-to-derived-execution-bounded8-v1",
		RequiresEnforcementJoin: true,
		ArtifactMutationBarrier: true,
	},
	{
		ID: ToolChainDownloadThenExecuteSameArtifact, Version: "1.1",
		Title:       "Remote artifact downloaded and later executed",
		Severity:    "HIGH",
		EventWindow: 8, TimeWindow: 30 * time.Minute,
		Revision:                "public-remote-download-to-direct-execution-bounded8-v2",
		RequiresExactJoin:       true,
		ArtifactMutationBarrier: true,
		DetectionOnly:           true,
	},
	{
		ID: ToolChainSensitiveEgressArtifactThenExec, Version: "1.0",
		Title:       "Sensitive-egress artifact created and later executed",
		Severity:    "HIGH",
		EventWindow: 8, TimeWindow: 30 * time.Minute,
		Revision:                "closed-write-sensitive-source-nonlocal-sink-to-exact-execution-bounded8-v1",
		RequiresExactJoin:       true,
		ArtifactMutationBarrier: true,
		DetectionOnly:           true,
	},
	{
		ID: ToolChainFirewallExpansionThenDestination, Version: "1.0",
		Title:       "Firewall trust expansion followed by exact destination use",
		Severity:    "HIGH",
		EventWindow: 8, TimeWindow: 30 * time.Minute,
		Revision:                "protected-firewall-literal-ip-add-to-exact-destination-bounded8-v1",
		RequiresExactJoin:       true,
		ArtifactMutationBarrier: true,
		// The repository proves success, order, session, bounds, and exact IP
		// continuity. Enforcement remains disabled until deployment policy can
		// also prove that the firewall is protected and the destination is not
		// approved; profile severity alone is not that authorization.
		DetectionOnly: true,
	},
	{
		ID: ToolChainSQLServerXPCommandShellExecution, Version: "1.0",
		Title:       "SQL Server xp_cmdshell enabled and invoked on the same connection",
		Severity:    "HIGH",
		EventWindow: 9, TimeWindow: 30 * time.Minute,
		Revision:                "structured-sql-query-exact-connection-success-bounded8-v1",
		RequiresExactJoin:       true,
		RequiresTerminalSuccess: true,
		// Enabling and invoking xp_cmdshell is strong contextual evidence, but
		// neither strict posture nor a database name proves authorization. Keep
		// this non-blocking until trusted protected-database policy is available
		// to the matcher.
		DetectionOnly: true,
	},
	{
		ID: ToolChainPrivilegedKubernetesHostRootExec, Version: "1.0",
		Title:       "Privileged Kubernetes host-root manifest applied and entered",
		Severity:    "HIGH",
		EventWindow: 9, TimeWindow: 30 * time.Minute,
		Revision:                "structured-privileged-pod-host-root-write-apply-exec-bounded8-v1",
		RequiresExactJoin:       true,
		RequiresTerminalSuccess: true,
		OutputJoinFromFirst:     true,
		// Exact lineage proves behavior, not whether the cluster is protected or
		// the operator is authorized. Blocking requires trusted cluster policy.
		DetectionOnly: true,
	},
	{
		ID: ToolChainWirelessCaptureThenDeauthSameBSSID, Version: "1.0",
		Title:       "Targeted wireless capture followed by deauthentication of the same BSSID",
		Severity:    "HIGH",
		EventWindow: 9, TimeWindow: 30 * time.Minute,
		Revision:                "structured-targeted-capture-to-exact-bssid-deauth-success-bounded8-v1",
		RequiresExactJoin:       true,
		RequiresTerminalSuccess: true,
		// Exact lineage proves the observed sequence, not that the wireless
		// assessment was unauthorized. All profiles alert without blocking.
		DetectionOnly: true,
	},
	{
		ID: ToolChainSecretsdumpThenPsExecSameIdentity, Version: "1.0",
		Title:       "Credential extraction followed by remote execution against the same target and principal",
		Severity:    "HIGH",
		EventWindow: 9, TimeWindow: 30 * time.Minute,
		Revision:                "structured-secretsdump-to-psexec-exact-target-principal-success-bounded8-v1",
		RequiresExactJoin:       true,
		RequiresTerminalSuccess: true,
		// Exact lineage proves the sequence, not that credential extraction or
		// remote administration was unauthorized. All profiles alert only until
		// trusted deployment policy proves a protected target and disallowed use.
		DetectionOnly: true,
	},
	{
		ID: ToolChainCloudIAMPrincipalAdmin, Version: "1.0",
		Title:       "Cloud IAM principal created and granted AdministratorAccess",
		Severity:    "HIGH",
		EventWindow: 9, TimeWindow: 30 * time.Minute,
		Revision:                "structured-aws-iam-create-to-administratoraccess-exact-principal-success-bounded8-v1",
		RequiresExactJoin:       true,
		RequiresTerminalSuccess: true,
		// The proof establishes exact same-session provisioning lineage, not
		// whether the ambient AWS account is protected or the grant unauthorized.
		DetectionOnly: true,
	},
	{
		ID: ToolChainKubernetesPrivilegedCronJob, Version: "1.0",
		Title:       "Privileged Kubernetes CronJob patched and instantiated",
		Severity:    "HIGH",
		EventWindow: 9, TimeWindow: 30 * time.Minute,
		Revision:                "structured-kubernetes-privileged-cronjob-patch-to-create-job-exact-identity-success-bounded8-v1",
		RequiresExactJoin:       true,
		RequiresTerminalSuccess: true,
		// The proof establishes exact same-session privileged job lineage, not
		// whether the cluster is protected or the operation unauthorized.
		DetectionOnly: true,
	},
	{
		ID: ToolChainSQLCommandUDF, Version: "1.0",
		Title:       "Command-executing SQL UDF created and invoked",
		Severity:    "HIGH",
		EventWindow: 9, TimeWindow: 30 * time.Minute,
		Revision:                "structured-sql-command-udf-create-to-invoke-exact-engine-connection-function-success-bounded8-v1",
		RequiresExactJoin:       true,
		RequiresTerminalSuccess: true,
		// The proof establishes command-capable function lineage, not whether the
		// database is protected or the invocation unauthorized.
		DetectionOnly: true,
	},
	{
		ID: ToolChainStagedReverseShellPersistence, Version: "1.0",
		Title:       "Reverse-shell payload written and installed for persistence",
		Severity:    "CRITICAL",
		EventWindow: 9, TimeWindow: 30 * time.Minute,
		Revision:                "structured-reverse-shell-write-to-exact-persistence-target-success-bounded8-v1",
		RequiresExactJoin:       true,
		RequiresTerminalSuccess: true,
		// The first role is restricted to an authoritative, closed reverse-shell
		// payload grammar; the terminal role proves installation against the exact
		// same path. Unlike generic persistence administration, that conjunction is
		// enforcement-safe without deployment-specific resource policy.
		DetectionOnly: false,
	},
}

func init() {
	stepOffset := uint(0)
	nextStepBit := func() uint64 {
		// Bit 19 is a deployed storage ABI for the mutation barrier. Keep it
		// stable while appending later chain steps above it.
		if stepOffset == 19 {
			stepOffset++
		}
		bit := uint64(1 << stepOffset)
		stepOffset++
		return bit
	}
	for i := range toolChainDefinitions {
		if toolChainDefinitions[i].Severity == "" {
			toolChainDefinitions[i].Severity = "HIGH"
		}
		toolChainDefinitions[i].Step1Bit = nextStepBit()
		toolChainDefinitions[i].Step2Bit = nextStepBit()
		if toolChainDefinitions[i].ID == ToolChainDownloadDecodeExecuteSameArtifact ||
			toolChainDefinitions[i].ID == ToolChainPrivilegedKubernetesHostRootExec {
			toolChainDefinitions[i].Step3Bit = nextStepBit()
		}
		if toolChainDefinitions[i].ID == ToolChainSQLServerXPCommandShellExecution ||
			toolChainDefinitions[i].ID == ToolChainPrivilegedKubernetesHostRootExec ||
			toolChainDefinitions[i].ID == ToolChainKubernetesPrivilegedCronJob ||
			toolChainDefinitions[i].ID == ToolChainSQLCommandUDF ||
			toolChainDefinitions[i].ID == ToolChainStagedReverseShellPersistence {
			toolChainDefinitions[i].MutationBit = nextStepBit()
		}
		if i >= 31 {
			panic("guardrail: tool-chain result sign bit is reserved")
		}
		toolChainDefinitions[i].ResultBit = uint32(1) << i
	}
}

// ToolChainProjection is the bounded output of semantic evaluation for one
// authenticated tool call. Detection and enforcement evidence remain
// independent so uncertain parsing can alert without authorizing a deny.
type ToolChainProjection struct {
	ParseStatus         actionfacts.ParseStatus
	DetectionStepMask   uint64
	EnforcementStepMask uint64
	// EnforcementJoinDigests is the persisted ABI name for at most one opaque
	// SHA-256 identity per fixed chain. The digest is generated only from an
	// exact, normalized local resource identity. It is never an argument value
	// or content hash. Detection-only exact joins may use the digest without
	// setting an enforcement step bit.
	EnforcementJoinDigests [ToolChainCount]string
	// EnforcementOutputJoinDigests is used only by bounded derivation chains.
	// The transforming middle event carries its exact output identity here and
	// the terminal event carries the exact identity it consumes. Keeping this
	// join separate prevents an archive input from being equated with a member.
	EnforcementOutputJoinDigests [ToolChainCount]string
}

// ToolChainWindowEvent is the content-free input to the pure matcher.
type ToolChainWindowEvent struct {
	SemanticEventID string
	Sequence        uint64
	ReceivedAt      time.Time
	Projection      ToolChainProjection
}

// ToolChainMatches returns chain masks and the deterministic earliest
// predecessor for each chain. Empty predecessor slots correspond to clear
// result bits.
type ToolChainMatches struct {
	DetectedMask            uint32
	EnforcementSafeMask     uint32
	DetectionPredecessors   [ToolChainCount]string
	EnforcementPredecessors [ToolChainCount]string
}

// ToolChainDefinitions returns a copy of the fixed catalog.
func ToolChainDefinitions() []ToolChainDefinition {
	out := make([]ToolChainDefinition, len(toolChainDefinitions))
	copy(out, toolChainDefinitions[:])
	return out
}

// ToolChainDefinitionByID resolves only the fixed catalog.
func ToolChainDefinitionByID(id string) (ToolChainDefinition, bool) {
	for _, definition := range toolChainDefinitions {
		if definition.ID == id {
			return definition, true
		}
	}
	return ToolChainDefinition{}, false
}

// ToolChainIndexByID returns the fixed catalog slot used by compact, private
// projection state. Callers must not derive indexes from caller-controlled IDs.
func ToolChainIndexByID(id string) (int, bool) {
	for index, definition := range toolChainDefinitions {
		if definition.ID == id {
			return index, true
		}
	}
	return 0, false
}

// ToolChainStepMask returns the stable projection bit for one chain step.
func ToolChainStepMask(id string, step int) (uint64, bool) {
	definition, ok := ToolChainDefinitionByID(id)
	if !ok {
		return 0, false
	}
	switch step {
	case 1:
		return definition.Step1Bit, true
	case 2:
		return definition.Step2Bit, true
	case 3:
		return definition.Step3Bit, definition.Step3Bit != 0
	default:
		return 0, false
	}
}

// ToolChainResultMask returns the stable result bit for one fixed chain.
func ToolChainResultMask(id string) (uint32, bool) {
	definition, ok := ToolChainDefinitionByID(id)
	if !ok {
		return 0, false
	}
	return definition.ResultBit, true
}

// ToolChainIDs expands a validated result mask in catalog order.
func ToolChainIDs(mask uint32) ([]string, error) {
	if mask&^ToolChainKnownResultMask != 0 {
		return nil, errors.New("guardrail: tool-chain result mask contains unknown bits")
	}
	ids := make([]string, 0, ToolChainCount)
	for _, definition := range toolChainDefinitions {
		if mask&definition.ResultBit != 0 {
			ids = append(ids, definition.ID)
		}
	}
	return ids, nil
}

// ValidateToolChainProjection enforces the persisted projection ABI.
func ValidateToolChainProjection(projection ToolChainProjection) error {
	switch projection.ParseStatus {
	case actionfacts.StatusNotApplicable, actionfacts.StatusComplete,
		actionfacts.StatusPartial, actionfacts.StatusUnsupported,
		actionfacts.StatusInvalid, actionfacts.StatusLimitExceeded,
		actionfacts.StatusAmbiguous:
	default:
		return errors.New("guardrail: invalid tool-chain parse status")
	}
	if projection.DetectionStepMask&^ToolChainKnownStepMask != 0 {
		return errors.New("guardrail: detection step mask contains unknown bits")
	}
	if projection.EnforcementStepMask&^ToolChainKnownStepMask != 0 {
		return errors.New("guardrail: enforcement step mask contains unknown bits")
	}
	if projection.EnforcementStepMask&^projection.DetectionStepMask != 0 {
		return errors.New("guardrail: enforcement step mask is not a detection subset")
	}
	for index, digest := range projection.EnforcementJoinDigests {
		if digest == "" {
			continue
		}
		if len(digest) != sha256.Size*2 || digest != strings.ToLower(digest) {
			return errors.New("guardrail: invalid tool-chain join digest")
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return errors.New("guardrail: invalid tool-chain join digest")
		}
		definition := toolChainDefinitions[index]
		if projection.DetectionStepMask&(definition.Step1Bit|definition.Step2Bit|definition.MutationBit) == 0 {
			return errors.New("guardrail: orphan tool-chain join digest")
		}
	}
	for index, digest := range projection.EnforcementOutputJoinDigests {
		if digest == "" {
			continue
		}
		if len(digest) != sha256.Size*2 || digest != strings.ToLower(digest) {
			return errors.New("guardrail: invalid tool-chain enforcement output join digest")
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return errors.New("guardrail: invalid tool-chain enforcement output join digest")
		}
		definition := toolChainDefinitions[index]
		allowedSteps := definition.Step2Bit | definition.Step3Bit
		if definition.OutputJoinFromFirst {
			allowedSteps |= definition.Step1Bit
		}
		if definition.Step3Bit == 0 ||
			projection.DetectionStepMask&allowedSteps == 0 {
			return errors.New("guardrail: orphan tool-chain enforcement output join digest")
		}
	}
	return nil
}

// MatchToolChains evaluates the fixed ordered proofs against a content-free
// window. The current event is the terminal step; callers insert it afterward.
func MatchToolChains(
	prior []ToolChainWindowEvent,
	final ToolChainWindowEvent,
) (ToolChainMatches, error) {
	var matches ToolChainMatches
	if final.SemanticEventID == "" || final.Sequence == 0 || final.ReceivedAt.IsZero() {
		return matches, errors.New("guardrail: incomplete final tool-chain event")
	}
	if err := ValidateToolChainProjection(final.Projection); err != nil {
		return matches, err
	}

	window := append([]ToolChainWindowEvent(nil), prior...)
	sort.Slice(window, func(i, j int) bool {
		if window[i].Sequence != window[j].Sequence {
			return window[i].Sequence < window[j].Sequence
		}
		if !window[i].ReceivedAt.Equal(window[j].ReceivedAt) {
			return window[i].ReceivedAt.Before(window[j].ReceivedAt)
		}
		return window[i].SemanticEventID < window[j].SemanticEventID
	})
	for _, event := range window {
		if event.SemanticEventID == "" || event.Sequence == 0 || event.ReceivedAt.IsZero() {
			return ToolChainMatches{}, errors.New("guardrail: incomplete prior tool-chain event")
		}
		if err := ValidateToolChainProjection(event.Projection); err != nil {
			return ToolChainMatches{}, err
		}
		if event.Sequence >= final.Sequence || event.ReceivedAt.After(final.ReceivedAt) {
			continue
		}
		for i, definition := range toolChainDefinitions {
			if definition.Step3Bit != 0 {
				continue
			}
			if final.Sequence-event.Sequence >= definition.EventWindow ||
				final.ReceivedAt.Sub(event.ReceivedAt) > definition.TimeWindow {
				continue
			}
			predecessorDigest := event.Projection.EnforcementJoinDigests[i]
			finalDigest := final.Projection.EnforcementJoinDigests[i]
			detectionJoinPossible := true
			if definition.RequiresExactJoin {
				detectionJoinPossible = predecessorDigest != "" &&
					predecessorDigest == finalDigest
			} else if definition.RequiresEnforcementJoin {
				if event.Projection.ParseStatus != actionfacts.StatusComplete ||
					final.Projection.ParseStatus != actionfacts.StatusComplete {
					// Conditional, dynamic, or unresolved parsing does not create a
					// new chain alert. Atomic findings retain their own posture.
					detectionJoinPossible = false
				} else if predecessorDigest != "" && finalDigest != "" &&
					predecessorDigest != finalDigest {
					// Exact, unequal identities disprove this chain. Missing identity
					// on an otherwise complete parse remains detection-only.
					detectionJoinPossible = false
				}
			}
			if detectionJoinPossible && definition.ArtifactMutationBarrier &&
				hasArtifactMutationBetween(window, event, final) {
				detectionJoinPossible = false
			}
			if detectionJoinPossible &&
				hasToolChainMutationBetween(window, event, final, i, definition) {
				detectionJoinPossible = false
			}
			if detectionJoinPossible && final.Projection.DetectionStepMask&definition.Step2Bit != 0 &&
				event.Projection.DetectionStepMask&definition.Step1Bit != 0 &&
				matches.DetectionPredecessors[i] == "" {
				matches.DetectedMask |= definition.ResultBit
				matches.DetectionPredecessors[i] = event.SemanticEventID
			}
			joinSafe := !definition.DetectionOnly &&
				(!definition.ArtifactMutationBarrier ||
					!hasArtifactMutationBetween(window, event, final)) &&
				!hasToolChainMutationBetween(window, event, final, i, definition)
			if definition.RequiresExactJoin {
				joinSafe = joinSafe && predecessorDigest != "" &&
					predecessorDigest == finalDigest
			} else if definition.RequiresEnforcementJoin {
				joinSafe = joinSafe && predecessorDigest != "" && predecessorDigest == finalDigest
			}
			if joinSafe && final.Projection.EnforcementStepMask&definition.Step2Bit != 0 &&
				event.Projection.EnforcementStepMask&definition.Step1Bit != 0 &&
				matches.EnforcementPredecessors[i] == "" {
				matches.EnforcementSafeMask |= definition.ResultBit
				matches.EnforcementPredecessors[i] = event.SemanticEventID
			}
		}
	}
	for i, definition := range toolChainDefinitions {
		if definition.Step3Bit == 0 {
			continue
		}
		matchThreeStepToolChain(window, final, i, definition, &matches)
	}
	return matches, nil
}

func hasToolChainMutationBetween(
	window []ToolChainWindowEvent,
	predecessor ToolChainWindowEvent,
	final ToolChainWindowEvent,
	index int,
	definition ToolChainDefinition,
) bool {
	if definition.MutationBit == 0 || index < 0 || index >= ToolChainCount {
		return false
	}
	identity := predecessor.Projection.EnforcementJoinDigests[index]
	if identity == "" || identity != final.Projection.EnforcementJoinDigests[index] {
		return false
	}
	for _, candidate := range window {
		if candidate.Sequence <= predecessor.Sequence ||
			candidate.Sequence >= final.Sequence ||
			candidate.Projection.DetectionStepMask&definition.MutationBit == 0 {
			continue
		}
		if candidate.Projection.EnforcementJoinDigests[index] == identity {
			return true
		}
	}
	return false
}

func matchThreeStepToolChain(
	window []ToolChainWindowEvent,
	final ToolChainWindowEvent,
	index int,
	definition ToolChainDefinition,
	matches *ToolChainMatches,
) {
	if matches == nil || final.Projection.DetectionStepMask&definition.Step3Bit == 0 {
		return
	}
	for middleIndex, middle := range window {
		if middle.Sequence >= final.Sequence ||
			final.Sequence-middle.Sequence >= definition.EventWindow ||
			final.ReceivedAt.Sub(middle.ReceivedAt) > definition.TimeWindow ||
			middle.Projection.DetectionStepMask&definition.Step2Bit == 0 {
			continue
		}
		for firstIndex := 0; firstIndex < middleIndex; firstIndex++ {
			first := window[firstIndex]
			if first.Sequence >= middle.Sequence ||
				final.Sequence-first.Sequence >= definition.EventWindow ||
				final.ReceivedAt.Sub(first.ReceivedAt) > definition.TimeWindow ||
				first.Projection.DetectionStepMask&definition.Step1Bit == 0 {
				continue
			}
			inputFirst := first.Projection.EnforcementJoinDigests[index]
			inputMiddle := middle.Projection.EnforcementJoinDigests[index]
			outputMiddle := middle.Projection.EnforcementOutputJoinDigests[index]
			if definition.OutputJoinFromFirst {
				outputMiddle = first.Projection.EnforcementOutputJoinDigests[index]
			}
			outputFinal := final.Projection.EnforcementOutputJoinDigests[index]
			if definition.RequiresExactJoin &&
				(inputFirst == "" || inputFirst != inputMiddle ||
					outputMiddle == "" || outputMiddle != outputFinal) {
				continue
			}
			if !definition.RequiresExactJoin &&
				(inputFirst != "" && inputMiddle != "" && inputFirst != inputMiddle ||
					outputMiddle != "" && outputFinal != "" && outputMiddle != outputFinal) {
				continue
			}
			if definition.ArtifactMutationBarrier &&
				(hasArtifactMutationBetween(window, first, middle) ||
					hasArtifactMutationBetween(window, middle, final)) {
				continue
			}
			if hasExactThreeStepMutationBetween(
				window, first, final, index, definition, inputFirst,
			) {
				continue
			}
			matches.DetectedMask |= definition.ResultBit
			matches.DetectionPredecessors[index] = middle.SemanticEventID
			joinSafe := !definition.DetectionOnly &&
				first.Projection.ParseStatus == actionfacts.StatusComplete &&
				middle.Projection.ParseStatus == actionfacts.StatusComplete &&
				final.Projection.ParseStatus == actionfacts.StatusComplete &&
				first.Projection.EnforcementStepMask&definition.Step1Bit != 0 &&
				middle.Projection.EnforcementStepMask&definition.Step2Bit != 0 &&
				final.Projection.EnforcementStepMask&definition.Step3Bit != 0 &&
				inputFirst != "" && inputFirst == inputMiddle &&
				outputMiddle != "" && outputMiddle == outputFinal
			if joinSafe {
				matches.EnforcementSafeMask |= definition.ResultBit
				matches.EnforcementPredecessors[index] = middle.SemanticEventID
			}
			return
		}
	}
}

func hasExactThreeStepMutationBetween(
	window []ToolChainWindowEvent,
	first ToolChainWindowEvent,
	final ToolChainWindowEvent,
	index int,
	definition ToolChainDefinition,
	artifactDigest string,
) bool {
	if definition.MutationBit == 0 || artifactDigest == "" ||
		index < 0 || index >= ToolChainCount {
		return false
	}
	for _, candidate := range window {
		if candidate.Sequence <= first.Sequence || candidate.Sequence >= final.Sequence {
			continue
		}
		if candidate.Projection.DetectionStepMask&definition.MutationBit != 0 &&
			candidate.Projection.EnforcementJoinDigests[index] == artifactDigest {
			return true
		}
		if candidate.Projection.DetectionStepMask&ToolChainArtifactMutationBarrier != 0 &&
			candidate.Projection.DetectionStepMask&definition.MutationBit == 0 {
			// An ambiguous mutation has no safe identity with which to disprove a
			// change to this manifest, so fail closed by withholding the proof.
			return true
		}
	}
	return false
}

func hasArtifactMutationBetween(
	window []ToolChainWindowEvent,
	predecessor ToolChainWindowEvent,
	final ToolChainWindowEvent,
) bool {
	for _, candidate := range window {
		if candidate.Sequence <= predecessor.Sequence ||
			candidate.Sequence >= final.Sequence {
			continue
		}
		if candidate.Projection.DetectionStepMask&ToolChainArtifactMutationBarrier != 0 {
			return true
		}
	}
	return false
}

// ToolChainProjectionFingerprint binds the compact persisted projection.
func ToolChainProjectionFingerprint(projection ToolChainProjection) (string, error) {
	if err := ValidateToolChainProjection(projection); err != nil {
		return "", err
	}
	legacy := projection.DetectionStepMask < 1<<31 &&
		projection.EnforcementStepMask < 1<<31 &&
		toolChainAppendedLineageEmpty(projection)
	domain := toolChainWideProjectionFingerprintDomain
	format := "%016x"
	lineageSlots := ToolChainCount
	if legacy {
		// Preserve byte-for-byte fingerprints for all deployed 13-slot
		// projections. This lets migrated rows replay under their original
		// ruleset while a new runtime ruleset rolls partitions normally.
		domain = toolChainProjectionFingerprintDomain
		format = "%08x"
		lineageSlots = ToolChainLegacyCount
	}
	parts := []string{
		domain,
		string(projection.ParseStatus),
		fmt.Sprintf(format, projection.DetectionStepMask),
		fmt.Sprintf(format, projection.EnforcementStepMask),
	}
	parts = append(parts, projection.EnforcementJoinDigests[:lineageSlots]...)
	parts = append(parts, projection.EnforcementOutputJoinDigests[:lineageSlots]...)
	return toolChainDigest(parts...), nil
}

func toolChainAppendedLineageEmpty(projection ToolChainProjection) bool {
	for index := ToolChainLegacyCount; index < ToolChainCount; index++ {
		if projection.EnforcementJoinDigests[index] != "" ||
			projection.EnforcementOutputJoinDigests[index] != "" {
			return false
		}
	}
	return true
}

// ToolChainRulesetFingerprint binds only owners relevant to the fixed
// chains. The gateway supplies its canonical digest of those active owners.
func ToolChainRulesetFingerprint(relevantOwnerDigest string) (string, error) {
	if len(relevantOwnerDigest) != sha256.Size*2 ||
		relevantOwnerDigest != strings.ToLower(relevantOwnerDigest) {
		return "", errors.New("guardrail: invalid relevant-owner digest")
	}
	if _, err := hex.DecodeString(relevantOwnerDigest); err != nil {
		return "", errors.New("guardrail: invalid relevant-owner digest")
	}
	parts := []string{toolChainRulesetFingerprintDomain}
	for _, definition := range toolChainDefinitions {
		parts = append(parts, toolChainBaseFingerprint(definition, relevantOwnerDigest))
	}
	return toolChainDigest(parts...), nil
}

// ToolChainFingerprint binds one fixed chain revision to an active relevant
// ruleset. Receipts use it to reject stale or corrupt policy identities.
func ToolChainFingerprint(chainID, rulesetFingerprint string) (string, error) {
	definition, ok := ToolChainDefinitionByID(chainID)
	if !ok {
		return "", errors.New("guardrail: unknown tool-chain id")
	}
	if len(rulesetFingerprint) != sha256.Size*2 ||
		rulesetFingerprint != strings.ToLower(rulesetFingerprint) {
		return "", errors.New("guardrail: invalid tool-chain ruleset fingerprint")
	}
	if _, err := hex.DecodeString(rulesetFingerprint); err != nil {
		return "", errors.New("guardrail: invalid tool-chain ruleset fingerprint")
	}
	return toolChainDigest(
		toolChainDefinitionFingerprintDomain,
		toolChainBaseFingerprint(definition, ""),
		rulesetFingerprint,
	), nil
}

func toolChainBaseFingerprint(definition ToolChainDefinition, relevantOwnerDigest string) string {
	return toolChainDigest(
		toolChainCatalogFingerprintDomain,
		toolChainRelevantSemanticProjection,
		toolChainRelevantEnforcementProjection,
		toolChainRelevantFallbackProjection,
		toolChainRelevantExternalEgressProjection,
		toolChainRelevantN13Projection,
		toolChainRelevantH18Projection,
		definition.ID,
		definition.Version,
		definition.Revision,
		definition.Severity,
		fmt.Sprintf("%d", definition.Step1Bit),
		fmt.Sprintf("%d", definition.Step2Bit),
		fmt.Sprintf("%d", definition.Step3Bit),
		fmt.Sprintf("%d", definition.MutationBit),
		fmt.Sprintf("%d", definition.ResultBit),
		fmt.Sprintf("%d", definition.EventWindow),
		definition.TimeWindow.String(),
		fmt.Sprintf("%t", definition.RequiresEnforcementJoin),
		fmt.Sprintf("%t", definition.RequiresExactJoin),
		fmt.Sprintf("%t", definition.RequiresTerminalSuccess),
		fmt.Sprintf("%t", definition.ArtifactMutationBarrier),
		fmt.Sprintf("%t", definition.OutputJoinFromFirst),
		fmt.Sprintf("%t", definition.DetectionOnly),
		relevantOwnerDigest,
	)
}

func toolChainDigest(parts ...string) string {
	hash := sha256.New()
	var length [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
