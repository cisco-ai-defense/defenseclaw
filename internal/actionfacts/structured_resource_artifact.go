// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"sort"
	"strings"
)

const (
	structuredFileIdentityDomain       = "defenseclaw/actionfacts/structured-file/v1"
	structuredRecipientIdentityDomain  = "defenseclaw/actionfacts/structured-recipient/v1"
	structuredEmailAttachmentMechanism = "email_attachment"
)

var structuredSendEmailKeys = map[string]bool{
	"attachments": true,
	"bcc":         true,
	"body":        true,
	"cc":          true,
	"recipients":  true,
	"subject":     true,
}

// ExactResourceReads returns validated value-free copies of exact resource
// reads. A read is a lineage capability and is not malicious on its own.
func ExactResourceReads(facts Facts) []ResourceReadFact {
	result := make([]ResourceReadFact, 0, len(facts.ResourceReads))
	for _, fact := range facts.ResourceReads {
		if fact.ResourceKind != "file" || !fact.Exact ||
			!validPrivateDigest(fact.ResourceIdentityDigest) {
			return nil
		}
		result = append(result, fact)
	}
	return result
}

// ExactArtifactTransfers returns deep, validated value-free copies of exact
// artifact transfers. A transfer is not malicious without policy context.
func ExactArtifactTransfers(facts Facts) []ArtifactTransferFact {
	result := make([]ArtifactTransferFact, 0, len(facts.ArtifactTransfers))
	for _, fact := range facts.ArtifactTransfers {
		if fact.Mechanism != structuredEmailAttachmentMechanism || !fact.Exact ||
			!validSortedPrivateDigests(fact.ArtifactIdentityDigests) ||
			!validSortedPrivateDigests(fact.DestinationPrincipalIdentityDigests) {
			return nil
		}
		fact.ArtifactIdentityDigests = append([]string(nil), fact.ArtifactIdentityDigests...)
		fact.DestinationPrincipalIdentityDigests = append(
			[]string(nil), fact.DestinationPrincipalIdentityDigests...,
		)
		result = append(result, fact)
	}
	return result
}

// ExactResourceMutations returns validated value-free copies of exact
// structured resource mutations. Mutations remain dual-use without policy
// context, even when their operation and identity are exact.
func ExactResourceMutations(facts Facts) []ResourceMutationFact {
	result := make([]ResourceMutationFact, 0, len(facts.ResourceMutations))
	for _, fact := range facts.ResourceMutations {
		if !validResourceMutationFact(fact) {
			return nil
		}
		result = append(result, fact)
	}
	return result
}

func validResourceMutationFact(fact ResourceMutationFact) bool {
	if fact.ResourceKind != "file" || !fact.Exact ||
		!validPrivateDigest(fact.ResourceIdentityDigest) {
		return false
	}
	switch fact.Operation {
	case ResourceMutationAppend, ResourceMutationDelete:
		return fact.DestinationPrincipalIdentityDigest == "" && fact.Permission == ""
	case ResourceMutationShare:
		return validPrivateDigest(fact.DestinationPrincipalIdentityDigest) &&
			(fact.Permission == ResourceMutationPermissionRead ||
				fact.Permission == ResourceMutationPermissionReadWrite)
	default:
		return false
	}
}

func projectStructuredResourceArtifactFacts(input Input) (
	[]ResourceReadFact,
	[]ArtifactTransferFact,
) {
	if input.Command != "" || len(input.Argv) != 0 {
		return nil, nil
	}
	switch input.Tool {
	case "get_file_by_id":
		fileID, ok := exactGetFileByIDInput(input.Args)
		if !ok {
			return nil, nil
		}
		return []ResourceReadFact{{
			ResourceKind:           "file",
			ResourceIdentityDigest: structuredFileIdentityDigest(fileID),
			Exact:                  true,
		}}, nil
	case "send_email":
		artifactIDs, recipients, ok := exactSendEmailAttachmentInput(input.Args)
		if !ok {
			return nil, nil
		}
		artifactDigests := make([]string, 0, len(artifactIDs))
		for _, artifactID := range artifactIDs {
			artifactDigests = append(artifactDigests, structuredFileIdentityDigest(artifactID))
		}
		recipientDigests := make([]string, 0, len(recipients))
		for _, recipient := range recipients {
			recipientDigests = append(
				recipientDigests,
				structuredPrincipalIdentityDigest(recipient),
			)
		}
		return nil, []ArtifactTransferFact{{
			Mechanism:                           structuredEmailAttachmentMechanism,
			ArtifactIdentityDigests:             sortedUniqueStrings(artifactDigests),
			DestinationPrincipalIdentityDigests: sortedUniqueStrings(recipientDigests),
			Exact:                               true,
		}}
	default:
		return nil, nil
	}
}

func projectStructuredResourceMutations(input Input) []ResourceMutationFact {
	if input.Command != "" || len(input.Argv) != 0 {
		return nil
	}
	var fact ResourceMutationFact
	switch input.Tool {
	case "append_to_file":
		fileID, ok := exactAppendToFileInput(input.Args)
		if !ok {
			return nil
		}
		fact.Operation = ResourceMutationAppend
		fact.ResourceIdentityDigest = structuredFileIdentityDigest(fileID)
	case "delete_file":
		fileID, ok := exactDeleteFileInput(input.Args)
		if !ok {
			return nil
		}
		fact.Operation = ResourceMutationDelete
		fact.ResourceIdentityDigest = structuredFileIdentityDigest(fileID)
	case "share_file":
		fileID, principal, permission, ok := exactShareFileInput(input.Args)
		if !ok {
			return nil
		}
		fact.Operation = ResourceMutationShare
		fact.ResourceIdentityDigest = structuredFileIdentityDigest(fileID)
		fact.DestinationPrincipalIdentityDigest = structuredPrincipalIdentityDigest(principal)
		fact.Permission = permission
	default:
		return nil
	}
	fact.ResourceKind = "file"
	fact.Exact = true
	if !validResourceMutationFact(fact) {
		return nil
	}
	return []ResourceMutationFact{fact}
}

func exactStructuredResourceArtifactInput(tool string, raw json.RawMessage) bool {
	switch tool {
	case "get_file_by_id":
		_, ok := exactGetFileByIDInput(raw)
		return ok
	case "send_email":
		_, _, ok := exactSendEmailAttachmentInput(raw)
		return ok
	case "append_to_file":
		_, ok := exactAppendToFileInput(raw)
		return ok
	case "delete_file":
		_, ok := exactDeleteFileInput(raw)
		return ok
	case "share_file":
		_, _, _, ok := exactShareFileInput(raw)
		return ok
	default:
		return false
	}
}

// structuredResourceMutationSchemaSelected distinguishes AgentDojo's
// identifier-based delete_file contract from the pre-existing path-based tool
// vocabulary. It does not validate the contract; the exact parser still owns
// that decision and rejects unknown or extended identifier schemas.
func structuredResourceMutationSchemaSelected(raw json.RawMessage) bool {
	object, problem := exactJSONObject(raw)
	if problem.status != "" {
		return false
	}
	_, selected := object["file_id"]
	return selected
}

func exactAppendToFileInput(raw json.RawMessage) (string, bool) {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || len(object) != 2 {
		return "", false
	}
	fileID, ok := exactStaticIdentityScalar(object["file_id"])
	if !ok {
		return "", false
	}
	content, ok := object["content"].(string)
	if !ok || len(content) > maxCommandBytes || validateScalar(content, maxCommandBytes) != "" {
		return "", false
	}
	return fileID, true
}

func exactDeleteFileInput(raw json.RawMessage) (string, bool) {
	return exactGetFileByIDInput(raw)
}

func exactShareFileInput(raw json.RawMessage) (
	string,
	string,
	ResourceMutationPermission,
	bool,
) {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || len(object) != 3 {
		return "", "", "", false
	}
	fileID, fileOK := exactStaticIdentityScalar(object["file_id"])
	principal, principalOK := exactStaticIdentityScalar(object["email"])
	permission, permissionOK := normalizedResourceMutationPermission(object["permission"])
	if !fileOK || !principalOK || !permissionOK {
		return "", "", "", false
	}
	return fileID, principal, permission, true
}

func normalizedResourceMutationPermission(value any) (ResourceMutationPermission, bool) {
	raw, ok := value.(string)
	if !ok {
		return "", false
	}
	switch raw {
	case "r":
		return ResourceMutationPermissionRead, true
	case "rw":
		return ResourceMutationPermissionReadWrite, true
	default:
		return "", false
	}
}

func exactGetFileByIDInput(raw json.RawMessage) (string, bool) {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || len(object) != 1 {
		return "", false
	}
	fileID, ok := exactStaticIdentityScalar(object["file_id"])
	return fileID, ok
}

func exactSendEmailAttachmentInput(raw json.RawMessage) ([]string, []string, bool) {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || !exactObjectKeys(object, structuredSendEmailKeys) {
		return nil, nil, false
	}
	recipients, ok := exactStaticIdentityArray(object["recipients"], maxArgvItems, true)
	if !ok {
		return nil, nil, false
	}
	cc, ok := exactOptionalIdentityArray(object, "cc")
	if !ok {
		return nil, nil, false
	}
	bcc, ok := exactOptionalIdentityArray(object, "bcc")
	if !ok || !exactOptionalMessageString(object, "subject") ||
		!exactOptionalMessageString(object, "body") {
		return nil, nil, false
	}
	recipients = append(recipients, cc...)
	recipients = append(recipients, bcc...)
	if len(recipients) > maxArgvItems {
		return nil, nil, false
	}
	attachments, ok := object["attachments"].([]any)
	if !ok || len(attachments) == 0 || len(attachments) > maxArtifactFacts {
		return nil, nil, false
	}
	artifactIDs := make([]string, 0, len(attachments))
	for _, value := range attachments {
		attachment, ok := value.(map[string]any)
		if !ok || len(attachment) != 2 || exactString(attachment["type"]) != "file" {
			return nil, nil, false
		}
		if _, present := attachment["type"]; !present {
			return nil, nil, false
		}
		fileID, ok := exactStaticIdentityScalar(attachment["file_id"])
		if !ok {
			return nil, nil, false
		}
		artifactIDs = append(artifactIDs, fileID)
	}
	return sortedUniqueStrings(artifactIDs), sortedUniqueStrings(recipients), true
}

func exactOptionalMessageString(object map[string]any, key string) bool {
	value, present := object[key]
	if !present {
		return true
	}
	text, ok := value.(string)
	return ok && len(text) <= maxCommandBytes && validateScalar(text, maxCommandBytes) == ""
}

func exactOptionalIdentityArray(object map[string]any, key string) ([]string, bool) {
	value, present := object[key]
	if !present || value == nil {
		return nil, true
	}
	return exactStaticIdentityArray(value, maxArgvItems, false)
}

func exactStaticIdentityArray(value any, limit int, required bool) ([]string, bool) {
	items, ok := value.([]any)
	if !ok || len(items) > limit || required && len(items) == 0 {
		return nil, false
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		identity, ok := exactStaticIdentityScalar(item)
		if !ok {
			return nil, false
		}
		result = append(result, identity)
	}
	return result, true
}

func exactStaticIdentityScalar(value any) (string, bool) {
	text, ok := value.(string)
	if !ok || text == "" || strings.TrimSpace(text) != text ||
		validateScalar(text, maxScalarBytes) != "" || unresolvedStructuredIdentity(text) {
		return "", false
	}
	return text, true
}

func unresolvedStructuredIdentity(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(value, "${") || strings.Contains(value, "$(") ||
		strings.Contains(value, "{{") || strings.Contains(value, "}}") ||
		strings.Contains(value, "<%") || strings.Contains(value, "%>") ||
		strings.ContainsRune(value, '`') || strings.Contains(lower, "placeholder") ||
		strings.Contains(lower, "your_file_id") || strings.Contains(lower, "your_recipient")
}

func structuredFileIdentityDigest(fileID string) string {
	return framedPrivateDigest(structuredFileIdentityDomain, "file", fileID)
}

func structuredPrincipalIdentityDigest(principal string) string {
	return framedPrivateDigest(structuredRecipientIdentityDomain, principal)
}

func sortedUniqueStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func validSortedPrivateDigests(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for index, value := range values {
		if !validPrivateDigest(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}
