// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package redaction

// DetectorGroup is an operator-facing immutable detector selection token.
type DetectorGroup string

const (
	DetectorGroupCredentials DetectorGroup = "credentials"
	DetectorGroupSecrets     DetectorGroup = "secrets"
	DetectorGroupPII         DetectorGroup = "pii"
)

// DetectorID is a stable detector and correlation identity.
type DetectorID string

// CatalogEntry is a value copy of one detector's machine-authored contract.
type CatalogEntry struct {
	Order               int
	Group               DetectorGroup
	ID                  DetectorID
	LexicalGrammar      string
	SemanticValidator   string
	InputContext        string
	CandidateBound      int
	ReplacementInterval string
	FixtureSet          string
}

type catalogDefinition struct {
	order               int
	group               DetectorGroup
	id                  DetectorID
	lexicalGrammar      string
	semanticValidator   string
	inputContext        string
	candidateBound      int
	replacementInterval string
	fixtureSet          string
}

type groupDefinition struct {
	token   DetectorGroup
	members [5]DetectorID
}

// DetectorCatalogVersion is the fixed v1 machine-catalog version.
func DetectorCatalogVersion() int { return generatedDetectorCatalogVersion }

// DetectorCatalog returns value copies in authoritative catalog order.
func DetectorCatalog() []CatalogEntry {
	entries := make([]CatalogEntry, len(generatedCatalogDefinitions))
	for i, item := range generatedCatalogDefinitions {
		entries[i] = CatalogEntry{
			Order: item.order, Group: item.group, ID: item.id,
			LexicalGrammar: item.lexicalGrammar, SemanticValidator: item.semanticValidator,
			InputContext: item.inputContext, CandidateBound: item.candidateBound,
			ReplacementInterval: item.replacementInterval, FixtureSet: item.fixtureSet,
		}
	}
	return entries
}

// DetectorGroups returns the only valid operator-facing groups in stable order.
func DetectorGroups() []DetectorGroup {
	return []DetectorGroup{DetectorGroupCredentials, DetectorGroupSecrets, DetectorGroupPII}
}

// DetectorsForGroup returns a copy of a group's ordered detector IDs.
func DetectorsForGroup(group DetectorGroup) ([]DetectorID, bool) {
	for _, definition := range generatedGroupDefinitions {
		if definition.token != group {
			continue
		}
		length := len(definition.members)
		for length > 0 && definition.members[length-1] == "" {
			length--
		}
		members := make([]DetectorID, length)
		copy(members, definition.members[:length])
		return members, true
	}
	return nil, false
}

func catalogDefinitionFor(id DetectorID) (catalogDefinition, bool) {
	for _, definition := range generatedCatalogDefinitions {
		if definition.id == id {
			return definition, true
		}
	}
	return catalogDefinition{}, false
}
