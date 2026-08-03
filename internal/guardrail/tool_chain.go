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
	ToolChainCount           = 6
	ToolChainKnownStepMask   = uint16(1<<12 - 1)
	ToolChainKnownResultMask = uint8(1<<ToolChainCount - 1)
	ToolChainMaxEvents       = uint64(64)
	ToolChainMaxPartitions   = 4096
	ToolChainReceiptTTL      = 7 * 24 * time.Hour
	ToolChainMaxHorizon      = 30 * time.Minute

	ToolChainGuardrailsOffThenEgress          = "chain.guardrails_off_then_egress"
	ToolChainPermissionDeniedThenBypass       = "chain.permission_denied_then_runtime_bypass"
	ToolChainPrivilegeDiscoveryThenElevation  = "chain.privilege_discovery_then_elevation"
	ToolChainSecretManagerReadThenEgress      = "chain.secret_manager_read_then_egress"
	ToolChainSecretReadThenEgress             = "chain.secret_read_then_egress"
	ToolChainWorkloadIdentityThenLateralExec  = "chain.workload_identity_then_lateral_execution"
	toolChainProjectionFingerprintDomain      = "defenseclaw.tool-chain.projection.v1"
	toolChainRulesetFingerprintDomain         = "defenseclaw.tool-chain.ruleset.v1"
	toolChainDefinitionFingerprintDomain      = "defenseclaw.tool-chain.definition.v1"
	toolChainCatalogFingerprintDomain         = "defenseclaw.tool-chain.catalog.v1"
	toolChainRelevantSemanticProjection       = "actionfacts-v1"
	toolChainRelevantEnforcementProjection    = "enforcement-proof-v1"
	toolChainRelevantFallbackProjection       = "owner-local-fallback-v1"
	toolChainRelevantExternalEgressProjection = "external-egress-v1"
	toolChainRelevantN13Projection            = "n13-lateral-exec-proof-v1"
	toolChainRelevantH18Projection            = "h18-system-root-proof-v1"
)

// ToolChainDefinition is the immutable private catalog entry for one ordered
// two-step behavior. Step bits are stable storage ABI.
type ToolChainDefinition struct {
	ID          string
	Version     string
	Title       string
	Severity    string
	EventWindow uint64
	TimeWindow  time.Duration
	Step1Bit    uint16
	Step2Bit    uint16
	ResultBit   uint8
	Revision    string
}

var toolChainDefinitions = [...]ToolChainDefinition{
	{
		ID: ToolChainGuardrailsOffThenEgress, Version: "1.4",
		Title:       "Guardrails disabled before external egress",
		EventWindow: 64, TimeWindow: 30 * time.Minute, Revision: "n20-to-data-external-egress-v1",
	},
	{
		ID: ToolChainPermissionDeniedThenBypass, Version: "1.3",
		Title:       "Permission denial followed by runtime bypass",
		EventWindow: 16, TimeWindow: 5 * time.Minute, Revision: "permission-denial-to-n08-v1",
	},
	{
		ID: ToolChainPrivilegeDiscoveryThenElevation, Version: "1.3",
		Title:       "Privilege discovery followed by elevation",
		EventWindow: 32, TimeWindow: 15 * time.Minute, Revision: "h18-system-root-to-h21-n12-n11-v1",
	},
	{
		ID: ToolChainSecretManagerReadThenEgress, Version: "1.5",
		Title:       "Secret-manager read followed by external egress",
		EventWindow: 64, TimeWindow: 30 * time.Minute, Revision: "n03-to-data-external-egress-v1",
	},
	{
		ID: ToolChainSecretReadThenEgress, Version: "1.6",
		Title:       "Secret read followed by external egress",
		EventWindow: 64, TimeWindow: 30 * time.Minute, Revision: "h01-h07-n01-n02-n04-to-data-external-egress-v1",
	},
	{
		ID: ToolChainWorkloadIdentityThenLateralExec, Version: "1.6",
		Title:       "Workload identity access followed by lateral execution",
		EventWindow: 32, TimeWindow: 15 * time.Minute, Revision: "n04-to-n13-v1",
	},
}

func init() {
	for i := range toolChainDefinitions {
		toolChainDefinitions[i].Severity = "HIGH"
		toolChainDefinitions[i].Step1Bit = uint16(1 << (2 * i))
		toolChainDefinitions[i].Step2Bit = uint16(1 << (2*i + 1))
		toolChainDefinitions[i].ResultBit = uint8(1 << i)
	}
}

// ToolChainProjection is the bounded output of semantic evaluation for one
// authenticated tool call. Detection and enforcement evidence remain
// independent so uncertain parsing can alert without authorizing a deny.
type ToolChainProjection struct {
	ParseStatus         actionfacts.ParseStatus
	DetectionStepMask   uint16
	EnforcementStepMask uint16
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
	DetectedMask            uint8
	EnforcementSafeMask     uint8
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

// ToolChainStepMask returns the stable projection bit for step 1 or 2.
func ToolChainStepMask(id string, step int) (uint16, bool) {
	definition, ok := ToolChainDefinitionByID(id)
	if !ok {
		return 0, false
	}
	switch step {
	case 1:
		return definition.Step1Bit, true
	case 2:
		return definition.Step2Bit, true
	default:
		return 0, false
	}
}

// ToolChainResultMask returns the stable result bit for one fixed chain.
func ToolChainResultMask(id string) (uint8, bool) {
	definition, ok := ToolChainDefinitionByID(id)
	if !ok {
		return 0, false
	}
	return definition.ResultBit, true
}

// ToolChainIDs expands a validated result mask in catalog order.
func ToolChainIDs(mask uint8) ([]string, error) {
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
	return nil
}

// MatchToolChains evaluates the fixed ordered pairs against a content-free
// window. The final event can only be step two; callers insert it afterward.
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
			if final.Sequence-event.Sequence >= definition.EventWindow ||
				final.ReceivedAt.Sub(event.ReceivedAt) > definition.TimeWindow {
				continue
			}
			if final.Projection.DetectionStepMask&definition.Step2Bit != 0 &&
				event.Projection.DetectionStepMask&definition.Step1Bit != 0 &&
				matches.DetectionPredecessors[i] == "" {
				matches.DetectedMask |= definition.ResultBit
				matches.DetectionPredecessors[i] = event.SemanticEventID
			}
			if final.Projection.EnforcementStepMask&definition.Step2Bit != 0 &&
				event.Projection.EnforcementStepMask&definition.Step1Bit != 0 &&
				matches.EnforcementPredecessors[i] == "" {
				matches.EnforcementSafeMask |= definition.ResultBit
				matches.EnforcementPredecessors[i] = event.SemanticEventID
			}
		}
	}
	return matches, nil
}

// ToolChainProjectionFingerprint binds the compact persisted projection.
func ToolChainProjectionFingerprint(projection ToolChainProjection) (string, error) {
	if err := ValidateToolChainProjection(projection); err != nil {
		return "", err
	}
	return toolChainDigest(
		toolChainProjectionFingerprintDomain,
		string(projection.ParseStatus),
		fmt.Sprintf("%04x", projection.DetectionStepMask),
		fmt.Sprintf("%04x", projection.EnforcementStepMask),
	), nil
}

// ToolChainRulesetFingerprint binds only owners relevant to the six fixed
// chains. The gateway supplies its canonical digest of those active owners.
func ToolChainRulesetFingerprint(relevantOwnerDigest string) (string, error) {
	if len(relevantOwnerDigest) != sha256.Size*2 ||
		relevantOwnerDigest != strings.ToLower(relevantOwnerDigest) {
		return "", errors.New("guardrail: invalid relevant-owner digest")
	}
	if _, err := hex.DecodeString(relevantOwnerDigest); err != nil {
		return "", errors.New("guardrail: invalid relevant-owner digest")
	}
	return toolChainDigest(
		toolChainRulesetFingerprintDomain,
		toolChainBaseFingerprint(toolChainDefinitions[0], relevantOwnerDigest),
		toolChainBaseFingerprint(toolChainDefinitions[1], relevantOwnerDigest),
		toolChainBaseFingerprint(toolChainDefinitions[2], relevantOwnerDigest),
		toolChainBaseFingerprint(toolChainDefinitions[3], relevantOwnerDigest),
		toolChainBaseFingerprint(toolChainDefinitions[4], relevantOwnerDigest),
		toolChainBaseFingerprint(toolChainDefinitions[5], relevantOwnerDigest),
	), nil
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
		fmt.Sprintf("%d", definition.ResultBit),
		fmt.Sprintf("%d", definition.EventWindow),
		definition.TimeWindow.String(),
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
