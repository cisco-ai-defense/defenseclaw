// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// The caps of this reader package, one line each (DET111 step 2, the cap
// registry: bounded.Register, checked by bounded.TestCapRegistry). A new
// max* cap this package compares a count against is added here.
var (
	_ = bounded.Register("hookpaths.maxRegistrationGlobMatches", bounded.Items, int(maxRegistrationGlobMatches))
	_ = bounded.Register("hookpaths.maxActiveStateDepth", bounded.Depth, int(maxActiveStateDepth))
	_ = bounded.Register("hookpaths.maxBoundLinkWords", bounded.Paths, int(maxBoundLinkWords))
	_ = bounded.Register("hookpaths.maxCallKeyReads", bounded.Time, int(maxCallKeyReads))
	_ = bounded.Register("hookpaths.maxCallScriptBytes", bounded.Bytes, int(maxCallScriptBytes))
	_ = bounded.Register("hookpaths.maxCommandPathBodyDepth", bounded.Depth, int(maxCommandPathBodyDepth))
	_ = bounded.Register("hookpaths.maxCopyBraceWords", bounded.Items, int(maxCopyBraceWords))
	_ = bounded.Register("hookpaths.maxCopyChildEntries", bounded.Paths, int(maxCopyChildEntries))
	_ = bounded.Register("hookpaths.maxDotDotWalkParts", bounded.Items, int(maxDotDotWalkParts))
	_ = bounded.Register("hookpaths.maxEncodedTargets", bounded.Items, int(maxEncodedTargets))
	_ = bounded.Register("hookpaths.maxEnterBases", bounded.Items, int(maxEnterBases))
	_ = bounded.Register("hookpaths.maxFileIdentityBytes", bounded.Bytes, int(maxFileIdentityBytes))
	_ = bounded.Register("hookpaths.maxFunctionStatements", bounded.Time, int(maxFunctionStatements))
	_ = bounded.Register("hookpaths.maxGlobFacts", bounded.Paths, int(maxGlobFacts))
	_ = bounded.Register("hookpaths.maxHiddenDirectoryDepth", bounded.Depth, int(maxHiddenDirectoryDepth))
	_ = bounded.Register("hookpaths.maxIndirectSourceBytes", bounded.Bytes, int(maxIndirectSourceBytes))
	_ = bounded.Register("hookpaths.maxLinkAliasSteps", bounded.Paths, int(maxLinkAliasSteps))
	_ = bounded.Register("hookpaths.maxLinkedTreeWork", bounded.Paths, int(maxLinkedTreeWork))
	_ = bounded.Register("hookpaths.maxMentionBraceFields", bounded.Items, int(maxMentionBraceFields))
	_ = bounded.Register("hookpaths.maxOpaquePathForms", bounded.Paths, int(maxOpaquePathForms))
	_ = bounded.Register("hookpaths.maxOversizePayloadBytes", bounded.Bytes, int(maxOversizePayloadBytes))
	_ = bounded.Register("hookpaths.maxPowerShellLinkCommands", bounded.Paths, int(maxPowerShellLinkCommands))
	_ = bounded.Register("hookpaths.maxProcMountTable", bounded.Items, int(maxProcMountTable))
	_ = bounded.Register("hookpaths.maxResolvedReadings", bounded.Items, int(maxResolvedReadings))
	_ = bounded.Register("hookpaths.maxSourceLinks", bounded.Paths, int(maxSourceLinks))
	_ = bounded.Register("hookpaths.maxStartupInstructionFiles", bounded.Paths, int(maxStartupInstructionFiles))
	_ = bounded.Register("hookpaths.maxTarPlainBytes", bounded.Bytes, int(maxTarPlainBytes))
	_ = bounded.Register("hookpaths.maxTarPlainMembers", bounded.Items, int(maxTarPlainMembers))
	_ = bounded.Register("hookpaths.maxTargetMemoEntries", bounded.Paths, int(maxTargetMemoEntries))
	_ = bounded.Register("hookpaths.maxWalkFactComponents", bounded.Items, int(maxWalkFactComponents))
	_ = bounded.Register("hookpaths.maxWalkFactWords", bounded.Items, int(maxWalkFactWords))
	_ = bounded.Register("hookpaths.maxWalkFacts", bounded.Items, int(maxWalkFacts))
	_ = bounded.Register("hookpaths.maxMemoParseBytes", bounded.Bytes, int(maxMemoParseBytes))
	_ = bounded.Register("hookpaths.maxMemoParses", bounded.Items, int(maxMemoParses))
	_ = bounded.Register("hookpaths.maxPlacedBodyReads", bounded.Items, int(maxPlacedBodyReads))
	_ = bounded.Register("hookpaths.maxPlacedWordDirs", bounded.Paths, int(maxPlacedWordDirs))
)
