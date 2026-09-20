// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"sort"
	"strings"
)

const (
	structuredFilePersistenceIdentityDomain   = "defenseclaw/actionfacts/structured-file-persistence-target/v1"
	structuredEntityPersistenceIdentityDomain = "defenseclaw/actionfacts/structured-entity-persistence-target/v1"
)

type exactStructuredEntityTarget struct {
	name       string
	entityType string
}

// ExactStructuredLiteralPersistences returns validated value-free copies of
// exact literal persistence facts. It never returns content or target names.
func ExactStructuredLiteralPersistences(facts Facts) []StructuredLiteralPersistenceFact {
	result := make([]StructuredLiteralPersistenceFact, 0, len(facts.StructuredLiteralPersistences))
	for _, fact := range facts.StructuredLiteralPersistences {
		if !validStructuredLiteralPersistenceFact(fact) {
			return nil
		}
		result = append(result, fact)
	}
	return result
}

func validStructuredLiteralPersistenceFact(fact StructuredLiteralPersistenceFact) bool {
	if !fact.Exact || !validPrivateDigest(fact.TargetIdentityDigest) {
		return false
	}
	switch fact.SinkClass {
	case StructuredLiteralPersistenceFile, StructuredLiteralPersistenceEntity:
		return true
	default:
		return false
	}
}

func projectStructuredLiteralPersistences(input Input) []StructuredLiteralPersistenceFact {
	if input.Command != "" || len(input.Argv) != 0 ||
		!validTrustedToolResourceIdentity(input.ToolResourceIdentity) {
		return nil
	}
	switch input.Tool {
	case "write_file":
		path, ok := exactStructuredFilePersistenceArgs(input.Args)
		if !ok {
			return nil
		}
		return []StructuredLiteralPersistenceFact{{
			SinkClass: StructuredLiteralPersistenceFile,
			TargetIdentityDigest: framedPrivateDigest(
				structuredFilePersistenceIdentityDomain,
				input.ToolResourceIdentity,
				path,
			),
			Exact: true,
		}}
	case "create_entities":
		targets, ok := exactStructuredEntityPersistenceArgs(input.Args)
		if !ok {
			return nil
		}
		facts := make([]StructuredLiteralPersistenceFact, 0, len(targets))
		for _, target := range targets {
			facts = append(facts, StructuredLiteralPersistenceFact{
				SinkClass: StructuredLiteralPersistenceEntity,
				TargetIdentityDigest: framedPrivateDigest(
					structuredEntityPersistenceIdentityDomain,
					input.ToolResourceIdentity,
					target.entityType,
					target.name,
				),
				Exact: true,
			})
		}
		sort.Slice(facts, func(left, right int) bool {
			return facts[left].TargetIdentityDigest < facts[right].TargetIdentityDigest
		})
		return facts
	default:
		return nil
	}
}

func exactStructuredFilePersistenceArgs(raw json.RawMessage) (string, bool) {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || len(object) != 2 {
		return "", false
	}
	path, pathOK := exactStructuredPersistenceScalar(object["path"], maxScalarBytes)
	content, contentOK := object["content"].(string)
	if !pathOK || !contentOK || len(content) > maxCommandBytes ||
		validateScalar(content, maxCommandBytes) != "" ||
		containsDynamicStructuredPersistenceIdentity(content) {
		return "", false
	}
	return path, true
}

func exactStructuredEntityPersistenceArgs(raw json.RawMessage) (
	[]exactStructuredEntityTarget,
	bool,
) {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || len(object) != 1 {
		return nil, false
	}
	entities, ok := object["entities"].([]any)
	if !ok || len(entities) == 0 || len(entities) > maxArtifactFacts {
		return nil, false
	}
	targets := make([]exactStructuredEntityTarget, 0, len(entities))
	seen := make(map[string]struct{}, len(entities))
	for _, value := range entities {
		entity, ok := value.(map[string]any)
		if !ok || len(entity) != 3 {
			return nil, false
		}
		name, nameOK := exactStructuredPersistenceScalar(entity["name"], maxScalarBytes)
		entityType, typeOK := exactStructuredPersistenceScalar(entity["entityType"], maxScalarBytes)
		observations, observationsOK := entity["observations"].([]any)
		if !nameOK || !typeOK || !observationsOK || len(observations) == 0 ||
			len(observations) > maxArtifactFacts {
			return nil, false
		}
		for _, observation := range observations {
			text, ok := observation.(string)
			if !ok || text == "" || len(text) > maxCommandBytes ||
				validateScalar(text, maxCommandBytes) != "" ||
				containsDynamicStructuredPersistenceIdentity(text) {
				return nil, false
			}
		}
		identity := entityType + "\x00" + name
		if _, duplicate := seen[identity]; duplicate {
			return nil, false
		}
		seen[identity] = struct{}{}
		targets = append(targets, exactStructuredEntityTarget{name: name, entityType: entityType})
	}
	return targets, true
}

func exactStructuredPersistenceScalar(value any, limit int) (string, bool) {
	text, ok := value.(string)
	if !ok || text == "" || len(text) > limit ||
		validateScalar(text, limit) != "" || strings.TrimSpace(text) != text ||
		containsDynamicStructuredPersistenceIdentity(text) {
		return "", false
	}
	return text, true
}

func containsDynamicStructuredPersistenceIdentity(value string) bool {
	return strings.Contains(value, "${") || strings.Contains(value, "$(") ||
		strings.Contains(value, "#{") || strings.Contains(value, "{{") ||
		strings.Contains(value, "}}") || strings.Contains(value, "<%") ||
		strings.Contains(value, "%>") || strings.ContainsRune(value, '`')
}
