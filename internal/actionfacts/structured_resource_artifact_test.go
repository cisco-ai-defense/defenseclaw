// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestStructuredResourceArtifactIdentityJoinsWithoutRawValues(t *testing.T) {
	const (
		fileID    = "file-record-27"
		recipient = "reviewer@reserved.example"
	)
	read := Analyze(Input{
		Tool: "get_file_by_id",
		Args: json.RawMessage(`{"file_id":"file-record-27"}`),
	})
	transfer := Analyze(Input{
		Tool: "send_email",
		Args: json.RawMessage(`{
			"recipients":["reviewer@reserved.example","reviewer@reserved.example"],
			"attachments":[
				{"type":"file","file_id":"file-record-27"},
				{"file_id":"file-record-27","type":"file"}
			],
			"subject":"Reviewed report",
			"body":"Attached for review.",
			"cc":["audit@reserved.example"],
			"bcc":[]
		}`),
	})

	reads := ExactResourceReads(read)
	transfers := ExactArtifactTransfers(transfer)
	if read.Parse.Status != StatusComplete || len(reads) != 1 {
		t.Fatalf("read projection = %+v", read)
	}
	if transfer.Parse.Status != StatusComplete || len(transfers) != 1 {
		t.Fatalf("transfer projection = %+v", transfer)
	}
	if !reads[0].Exact || reads[0].ResourceKind != "file" ||
		!validPrivateDigest(reads[0].ResourceIdentityDigest) {
		t.Fatalf("invalid resource read = %+v", reads[0])
	}
	if len(transfers[0].ArtifactIdentityDigests) != 1 ||
		transfers[0].ArtifactIdentityDigests[0] != reads[0].ResourceIdentityDigest {
		t.Fatalf("same-file identity did not join: read=%+v transfer=%+v", reads[0], transfers[0])
	}
	if len(transfers[0].DestinationPrincipalIdentityDigests) != 2 ||
		!validPrivateDigest(transfers[0].DestinationPrincipalIdentityDigests[0]) ||
		!validPrivateDigest(transfers[0].DestinationPrincipalIdentityDigests[1]) ||
		transfers[0].DestinationPrincipalIdentityDigests[0] == reads[0].ResourceIdentityDigest {
		t.Fatalf("recipient identity was not domain separated: %+v", transfers[0])
	}
	projection := fmt.Sprintf("%+v %+v", read, transfer)
	for _, raw := range []string{fileID, recipient, "audit@reserved.example", "Reviewed report", "Attached for review."} {
		if strings.Contains(projection, raw) {
			t.Fatalf("raw structured value escaped private projection: %q", raw)
		}
	}

	// Returned transfer facts are deep copies; callers cannot mutate Facts.
	transfers[0].ArtifactIdentityDigests[0] = strings.Repeat("0", 64)
	if transfer.ArtifactTransfers[0].ArtifactIdentityDigests[0] != reads[0].ResourceIdentityDigest {
		t.Fatal("ExactArtifactTransfers returned an aliased digest slice")
	}
}

func TestStructuredResourceArtifactIdentityIsStableAndSeparated(t *testing.T) {
	first := Analyze(Input{Tool: "get_file_by_id", Args: json.RawMessage(`{"file_id":"file-a"}`)})
	same := Analyze(Input{Tool: "get_file_by_id", Args: json.RawMessage(`{"file_id":"file-a"}`)})
	other := Analyze(Input{Tool: "get_file_by_id", Args: json.RawMessage(`{"file_id":"file-b"}`)})

	firstDigest := ExactResourceReads(first)[0].ResourceIdentityDigest
	if firstDigest != ExactResourceReads(same)[0].ResourceIdentityDigest {
		t.Fatal("same exact file ID did not produce a stable identity")
	}
	if firstDigest == ExactResourceReads(other)[0].ResourceIdentityDigest {
		t.Fatal("different file IDs collided")
	}
}

func TestStructuredResourceArtifactSchemasAbstainOnUnprovedInput(t *testing.T) {
	tests := []struct {
		name string
		tool string
		args string
	}{
		{name: "empty file ID", tool: "get_file_by_id", args: `{"file_id":""}`},
		{name: "numeric file ID", tool: "get_file_by_id", args: `{"file_id":27}`},
		{name: "dynamic file ID", tool: "get_file_by_id", args: `{"file_id":"${file_id}"}`},
		{name: "unknown read field", tool: "get_file_by_id", args: `{"file_id":"file-a","result":"secret"}`},
		{name: "duplicate read key", tool: "get_file_by_id", args: `{"file_id":"file-a","file_id":"file-b"}`},
		{name: "missing recipients", tool: "send_email", args: `{"attachments":[{"type":"file","file_id":"file-a"}]}`},
		{name: "empty recipients", tool: "send_email", args: `{"recipients":[],"attachments":[{"type":"file","file_id":"file-a"}]}`},
		{name: "scalar recipient", tool: "send_email", args: `{"recipients":"reviewer@reserved.example","attachments":[{"type":"file","file_id":"file-a"}]}`},
		{name: "dynamic recipient", tool: "send_email", args: `{"recipients":["{{recipient}}"],"attachments":[{"type":"file","file_id":"file-a"}]}`},
		{name: "missing attachments", tool: "send_email", args: `{"recipients":["reviewer@reserved.example"]}`},
		{name: "empty attachments", tool: "send_email", args: `{"recipients":["reviewer@reserved.example"],"attachments":[]}`},
		{name: "attachment missing type", tool: "send_email", args: `{"recipients":["reviewer@reserved.example"],"attachments":[{"file_id":"file-a"}]}`},
		{name: "attachment wrong type", tool: "send_email", args: `{"recipients":["reviewer@reserved.example"],"attachments":[{"type":"url","file_id":"file-a"}]}`},
		{name: "attachment extra field", tool: "send_email", args: `{"recipients":["reviewer@reserved.example"],"attachments":[{"type":"file","file_id":"file-a","name":"report"}]}`},
		{name: "dynamic attachment ID", tool: "send_email", args: `{"recipients":["reviewer@reserved.example"],"attachments":[{"type":"file","file_id":"$(lookup)"}]}`},
		{name: "unknown email field", tool: "send_email", args: `{"recipients":["reviewer@reserved.example"],"attachments":[{"type":"file","file_id":"file-a"}],"result":"sent"}`},
		{name: "malformed JSON", tool: "send_email", args: `{"recipients":`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: test.tool, Args: json.RawMessage(test.args)})
			if len(facts.ResourceReads) != 0 || len(facts.ArtifactTransfers) != 0 ||
				len(ExactResourceReads(facts)) != 0 || len(ExactArtifactTransfers(facts)) != 0 {
				t.Fatalf("unproved schema projected lineage facts: %+v", facts)
			}
		})
	}
}

func TestStructuredResourceArtifactSchemasRejectConflictingExecutionSources(t *testing.T) {
	read := Analyze(Input{
		Tool:    "get_file_by_id",
		Args:    json.RawMessage(`{"file_id":"file-a"}`),
		Command: "get file-a",
	})
	transfer := Analyze(Input{
		Tool: "send_email",
		Args: json.RawMessage(`{"recipients":["reviewer@reserved.example"],"attachments":[{"type":"file","file_id":"file-a"}]}`),
		Argv: []string{"send-email"},
	})
	if len(read.ResourceReads) != 0 || len(transfer.ArtifactTransfers) != 0 {
		t.Fatalf("conflicting execution source projected lineage: read=%+v transfer=%+v", read, transfer)
	}
}

func TestExactStructuredResourceArtifactAccessorsRejectInvalidPrivateFacts(t *testing.T) {
	invalidDigest := strings.Repeat("0", 63)
	if got := ExactResourceReads(Facts{ResourceReads: []ResourceReadFact{{
		ResourceKind: "file", ResourceIdentityDigest: invalidDigest, Exact: true,
	}}}); got != nil {
		t.Fatalf("invalid resource digest accepted: %+v", got)
	}
	if got := ExactArtifactTransfers(Facts{ArtifactTransfers: []ArtifactTransferFact{{
		Mechanism:                           structuredEmailAttachmentMechanism,
		ArtifactIdentityDigests:             []string{strings.Repeat("a", 64), strings.Repeat("a", 64)},
		DestinationPrincipalIdentityDigests: []string{strings.Repeat("b", 64)},
		Exact:                               true,
	}}}); got != nil {
		t.Fatalf("unsorted or duplicate transfer digests accepted: %+v", got)
	}
}

func TestStructuredResourceMutationsProjectExactValueFreeFacts(t *testing.T) {
	const (
		fileID    = "file-record-41"
		content   = "Private report content"
		principal = "collaborator@reserved.example"
	)
	tests := []struct {
		name       string
		tool       string
		args       string
		operation  ResourceMutationOperation
		permission ResourceMutationPermission
		principal  bool
	}{
		{
			name: "append", tool: "append_to_file",
			args:      `{"file_id":"file-record-41","content":"Private report content"}`,
			operation: ResourceMutationAppend,
		},
		{
			name: "delete", tool: "delete_file",
			args:      `{"file_id":"file-record-41"}`,
			operation: ResourceMutationDelete,
		},
		{
			name: "share read", tool: "share_file",
			args:      `{"file_id":"file-record-41","email":"collaborator@reserved.example","permission":"r"}`,
			operation: ResourceMutationShare, permission: ResourceMutationPermissionRead, principal: true,
		},
		{
			name: "share read write", tool: "share_file",
			args:      `{"file_id":"file-record-41","email":"collaborator@reserved.example","permission":"rw"}`,
			operation: ResourceMutationShare, permission: ResourceMutationPermissionReadWrite, principal: true,
		},
	}

	read := Analyze(Input{Tool: "get_file_by_id", Args: json.RawMessage(`{"file_id":"file-record-41"}`)})
	readDigest := ExactResourceReads(read)[0].ResourceIdentityDigest
	email := Analyze(Input{
		Tool: "send_email",
		Args: json.RawMessage(`{"recipients":["collaborator@reserved.example"],"attachments":[{"type":"file","file_id":"file-record-41"}]}`),
	})
	principalDigest := ExactArtifactTransfers(email)[0].DestinationPrincipalIdentityDigests[0]
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: test.tool, Args: json.RawMessage(test.args)})
			mutations := ExactResourceMutations(facts)
			if facts.Parse.Status != StatusComplete || len(mutations) != 1 {
				t.Fatalf("mutation projection = %+v", facts)
			}
			mutation := mutations[0]
			if mutation.Operation != test.operation || mutation.ResourceKind != "file" ||
				mutation.ResourceIdentityDigest != readDigest || !mutation.Exact {
				t.Fatalf("mutation = %+v", mutation)
			}
			if test.principal {
				if !validPrivateDigest(mutation.DestinationPrincipalIdentityDigest) ||
					mutation.DestinationPrincipalIdentityDigest != principalDigest ||
					mutation.Permission != test.permission {
					t.Fatalf("share evidence = %+v", mutation)
				}
			} else if mutation.DestinationPrincipalIdentityDigest != "" || mutation.Permission != "" {
				t.Fatalf("non-share retained destination evidence: %+v", mutation)
			}
			projection := fmt.Sprintf("%+v", facts)
			for _, raw := range []string{fileID, content, principal} {
				if strings.Contains(projection, raw) {
					t.Fatalf("raw mutation value escaped private projection: %q", raw)
				}
			}
			if test.permission == ResourceMutationPermissionReadWrite && string(mutation.Permission) == "rw" {
				t.Fatal("raw provider permission escaped private projection")
			}
		})
	}
}

func TestStructuredResourceMutationSchemasAbstainOnUnprovedInput(t *testing.T) {
	tests := []struct {
		name string
		tool string
		args string
	}{
		{name: "append missing content", tool: "append_to_file", args: `{"file_id":"file-a"}`},
		{name: "append non-string content", tool: "append_to_file", args: `{"file_id":"file-a","content":42}`},
		{name: "append dynamic ID", tool: "append_to_file", args: `{"file_id":"${file_id}","content":"literal"}`},
		{name: "append extra field", tool: "append_to_file", args: `{"file_id":"file-a","content":"literal","mode":"append"}`},
		{name: "delete missing ID", tool: "delete_file", args: `{}`},
		{name: "delete dynamic ID", tool: "delete_file", args: `{"file_id":"{{file_id}}"}`},
		{name: "delete extra field", tool: "delete_file", args: `{"file_id":"file-a","recursive":true}`},
		{name: "share missing principal", tool: "share_file", args: `{"file_id":"file-a","permission":"r"}`},
		{name: "share dynamic principal", tool: "share_file", args: `{"file_id":"file-a","email":"{{recipient}}","permission":"r"}`},
		{name: "share unsupported permission", tool: "share_file", args: `{"file_id":"file-a","email":"collaborator@reserved.example","permission":"read"}`},
		{name: "share dynamic permission", tool: "share_file", args: `{"file_id":"file-a","email":"collaborator@reserved.example","permission":"${permission}"}`},
		{name: "share extra field", tool: "share_file", args: `{"file_id":"file-a","email":"collaborator@reserved.example","permission":"rw","notify":true}`},
		{name: "share duplicate key", tool: "share_file", args: `{"file_id":"file-a","email":"collaborator@reserved.example","permission":"r","permission":"rw"}`},
		{name: "malformed", tool: "append_to_file", args: `{"file_id":`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: test.tool, Args: json.RawMessage(test.args)})
			if len(facts.ResourceMutations) != 0 || len(ExactResourceMutations(facts)) != 0 {
				t.Fatalf("unproved schema projected mutation: %+v", facts)
			}
		})
	}
}

func TestStructuredResourceMutationsRejectConflictingExecutionSources(t *testing.T) {
	for _, input := range []Input{
		{
			Tool: "append_to_file", Args: json.RawMessage(`{"file_id":"file-a","content":"literal"}`),
			Command: "append file-a",
		},
		{
			Tool: "share_file", Args: json.RawMessage(`{"file_id":"file-a","email":"collaborator@reserved.example","permission":"r"}`),
			Argv: []string{"share-file"},
		},
	} {
		facts := Analyze(input)
		if len(facts.ResourceMutations) != 0 {
			t.Fatalf("conflicting execution source projected mutation: %+v", facts)
		}
	}
}

func TestExactResourceMutationsRejectInvalidPrivateFacts(t *testing.T) {
	validDigest := strings.Repeat("a", 64)
	tests := []ResourceMutationFact{
		{Operation: "unknown", ResourceKind: "file", ResourceIdentityDigest: validDigest, Exact: true},
		{Operation: ResourceMutationDelete, ResourceKind: "file", ResourceIdentityDigest: validDigest, Permission: ResourceMutationPermissionRead, Exact: true},
		{Operation: ResourceMutationShare, ResourceKind: "file", ResourceIdentityDigest: validDigest, Permission: ResourceMutationPermissionRead, Exact: true},
		{Operation: ResourceMutationShare, ResourceKind: "file", ResourceIdentityDigest: validDigest, DestinationPrincipalIdentityDigest: validDigest, Permission: "owner", Exact: true},
		{Operation: ResourceMutationAppend, ResourceKind: "file", ResourceIdentityDigest: strings.Repeat("0", 63), Exact: true},
		{Operation: ResourceMutationAppend, ResourceKind: "file", ResourceIdentityDigest: validDigest},
	}
	for index, fact := range tests {
		if got := ExactResourceMutations(Facts{ResourceMutations: []ResourceMutationFact{fact}}); got != nil {
			t.Fatalf("invalid private mutation %d accepted: %+v", index, got)
		}
	}
}
