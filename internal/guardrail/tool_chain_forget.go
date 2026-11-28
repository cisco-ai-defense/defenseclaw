// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
)

// The artifact chains join two steps on one file's path: the file a step
// wrote (a download, a decode's output, a sensitive-egress artifact) is the
// file a later step runs. A workspace undo (defenseclaw substrate undo)
// removes the files added since its checkpoint and puts the changed ones
// back, so a fact one of these chains holds about such a file describes
// bytes that are gone (substrate-1:GAP-0476). Only these chains' writing
// steps are ever forgotten: a read already happened, whatever the file
// holds now.
var toolChainArtifactChains = [...]string{
	ToolChainDownloadThenExecuteSameArtifact,
	ToolChainSensitiveEgressArtifactThenExec,
	ToolChainDownloadDecodeExecuteSameArtifact,
}

// ToolChainArtifactWriteStepMask is the steps a workspace undo can forget:
// the first step of each artifact chain, and the decode of the
// download-decode-execute chain.
func ToolChainArtifactWriteStepMask() uint64 {
	var mask uint64
	for _, id := range toolChainArtifactChains {
		definition, _ := ToolChainDefinitionByID(id)
		mask |= definition.Step1Bit
		if definition.Step3Bit != 0 {
			mask |= definition.Step2Bit
		}
	}
	return mask
}

// ToolChainPathIdentityDigest is the join digest of an exact path identity
// ("posix\x00/abs/path" or "windows\x00c:/abs/path") the chain projector
// gives a file.
func ToolChainPathIdentityDigest(identity string) string {
	digest := sha256.Sum256([]byte("defenseclaw/tool-chain/path-identity/v1\x00" + identity))
	return hex.EncodeToString(digest[:])
}

// ToolChainPOSIXPathDigest is the join digest the gateway's chain projector
// gives an absolute path in a Linux agent (an Agent Substrate actor), false
// for a path that is not absolute.
func ToolChainPOSIXPathDigest(p string) (string, bool) {
	if !strings.HasPrefix(p, "/") || strings.ContainsRune(p, '\x00') {
		return "", false
	}
	return ToolChainPathIdentityDigest("posix\x00" + path.Clean(p)), true
}

// ForgetToolChainArtifacts takes the facts about reverted files out of the
// events of one chain partition (any order): forget reports whether the
// fact an event holds about the file with that digest is to go (the file
// was reverted, and for a file put back, the event came after the
// checkpoint). The answer has the new projection of each event that
// changed, by semantic event id. Its other steps, results and receipts
// stay. The first step of a download-decode-execute chain whose download a
// later event of the partition decoded stays: the decoded file may lie
// outside the reverted folder.
func ForgetToolChainArtifacts(events []ToolChainWindowEvent, forget func(digest string, event ToolChainWindowEvent) bool) map[string]ToolChainProjection {
	out := map[string]ToolChainProjection{}
	for _, event := range events {
		projection := event.Projection
		for _, id := range toolChainArtifactChains {
			definition, _ := ToolChainDefinitionByID(id)
			index, _ := ToolChainIndexByID(id)
			var drop uint64
			input := projection.EnforcementJoinDigests[index]
			if projection.DetectionStepMask&definition.Step1Bit != 0 && input != "" && forget(input, event) &&
				(definition.Step3Bit == 0 || !toolChainDecodedLater(events, event, definition, index, input)) {
				drop |= definition.Step1Bit
			}
			if output := projection.EnforcementOutputJoinDigests[index]; definition.Step3Bit != 0 &&
				projection.DetectionStepMask&definition.Step2Bit != 0 && output != "" && forget(output, event) {
				drop |= definition.Step2Bit
			}
			if drop == 0 {
				continue
			}
			projection.DetectionStepMask &^= drop
			projection.EnforcementStepMask &^= drop
			all := definition.Step1Bit | definition.Step2Bit | definition.Step3Bit | definition.Step4Bit | definition.MutationBit
			if projection.DetectionStepMask&all == 0 {
				projection.EnforcementJoinDigests[index] = ""
				projection.EnforcementOutputJoinDigests[index] = ""
			} else if definition.Step3Bit != 0 && !definition.OutputJoinFromFirst &&
				projection.DetectionStepMask&(definition.Step2Bit|definition.Step3Bit|definition.Step4Bit) == 0 {
				projection.EnforcementOutputJoinDigests[index] = ""
			}
		}
		if projection != event.Projection && ValidateToolChainProjection(projection) == nil {
			out[event.SemanticEventID] = projection
		}
	}
	return out
}

func toolChainDecodedLater(events []ToolChainWindowEvent, download ToolChainWindowEvent, definition ToolChainDefinition, index int, input string) bool {
	for _, event := range events {
		if event.Sequence > download.Sequence && event.Projection.DetectionStepMask&definition.Step2Bit != 0 &&
			event.Projection.EnforcementJoinDigests[index] == input {
			return true
		}
	}
	return false
}

// ToolChainProjectionForgotten reports whether stored is input with some of
// the facts ForgetToolChainArtifacts takes out taken out: the stored event
// of a repeated observation after a workspace undo.
func ToolChainProjectionForgotten(stored, input ToolChainProjection) bool {
	if stored.ParseStatus != input.ParseStatus || stored.ValueJoinDigests != input.ValueJoinDigests {
		return false
	}
	mask := ToolChainArtifactWriteStepMask()
	for _, pair := range [][2]uint64{{stored.DetectionStepMask, input.DetectionStepMask}, {stored.EnforcementStepMask, input.EnforcementStepMask}} {
		if pair[0]&^mask != pair[1]&^mask || pair[0]&mask&^pair[1] != 0 {
			return false
		}
	}
	artifact := map[int]bool{}
	for _, id := range toolChainArtifactChains {
		index, _ := ToolChainIndexByID(id)
		artifact[index] = true
	}
	for index := range stored.EnforcementJoinDigests {
		for _, pair := range [][2]string{{stored.EnforcementJoinDigests[index], input.EnforcementJoinDigests[index]},
			{stored.EnforcementOutputJoinDigests[index], input.EnforcementOutputJoinDigests[index]}} {
			if pair[0] != pair[1] && (!artifact[index] || pair[0] != "") {
				return false
			}
		}
	}
	return true
}
