// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"encoding/json"
	"strings"
	"testing"
)

func validImportProvenance() ImportProvenance {
	return ImportProvenance{
		Protocol:                 ImportProtocolOTLP,
		BindingID:                "otlp.genai.span.operation.v1.chat",
		Mode:                     ImportModeImportAndDerive,
		Derivation:               ImportDerivationArithmeticMean,
		SourceAggregateCount:     Present(uint64(4)),
		AuthenticatedSource:      "codex",
		UpstreamInstanceID:       "upstream-instance-1",
		UpstreamRecordID:         "123E4567-E89B-12D3-A456-426614174000",
		UpstreamServiceName:      "upstream-service",
		UpstreamRedactionProfile: "sensitive",
		IngressHopCount:          3,
		LastHopInstanceID:        "forwarder-instance-1",
		LastHopDestination:       "otlp-primary",
	}
}

func TestImportProvenanceClosedVocabularyAndCrossFieldValidation(t *testing.T) {
	valid := []struct {
		name   string
		mutate func(*ImportProvenance)
	}{
		{
			name: "plain import",
			mutate: func(input *ImportProvenance) {
				input.Mode = ImportModeImport
				input.Derivation = ""
				input.SourceAggregateCount = Absent[uint64]()
			},
		},
		{
			name: "field value derivation",
			mutate: func(input *ImportProvenance) {
				input.Mode = ImportModeDerive
				input.Derivation = ImportDerivationFieldValue
				input.SourceAggregateCount = Absent[uint64]()
			},
		},
		{
			name: "elapsed time derivation",
			mutate: func(input *ImportProvenance) {
				input.Mode = ImportModeDerive
				input.Derivation = ImportDerivationElapsedTime
				input.SourceAggregateCount = Absent[uint64]()
			},
		},
		{
			name: "cumulative delta derivation",
			mutate: func(input *ImportProvenance) {
				input.Mode = ImportModeDerive
				input.Derivation = ImportDerivationCumulativeDelta
				input.SourceAggregateCount = Absent[uint64]()
			},
		},
		{
			name:   "uppercase canonical UUID is preserved",
			mutate: func(*ImportProvenance) {},
		},
		{
			name: "lowercase stable upstream record token",
			mutate: func(input *ImportProvenance) {
				input.UpstreamRecordID = "record.stable-01"
			},
		},
		{
			name: "bounded identifiers at exact maximum",
			mutate: func(input *ImportProvenance) {
				input.BindingID = strings.Repeat("b", MaxImportIdentifierBytes)
				input.AuthenticatedSource = strings.Repeat("a", MaxImportIdentifierBytes)
				input.UpstreamInstanceID = strings.Repeat("u", MaxImportIdentifierBytes)
				input.UpstreamServiceName = strings.Repeat("s", MaxImportIdentifierBytes)
				input.LastHopInstanceID = strings.Repeat("i", MaxImportIdentifierBytes)
				input.LastHopDestination = strings.Repeat("d", MaxImportIdentifierBytes)
			},
		},
		{
			name: "maximum aggregate count",
			mutate: func(input *ImportProvenance) {
				input.SourceAggregateCount = Present(^uint64(0))
			},
		},
	}
	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			input := validImportProvenance()
			test.mutate(&input)
			if err := input.Validate(); err != nil {
				t.Fatalf("valid import provenance rejected: %v", err)
			}
		})
	}

	invalidUTF8 := string([]byte{0xff})
	invalid := []struct {
		name   string
		mutate func(*ImportProvenance)
	}{
		{name: "missing protocol", mutate: func(input *ImportProvenance) { input.Protocol = "" }},
		{name: "unknown protocol", mutate: func(input *ImportProvenance) { input.Protocol = "grpc" }},
		{name: "missing binding ID", mutate: func(input *ImportProvenance) { input.BindingID = "" }},
		{name: "invalid binding UTF-8", mutate: func(input *ImportProvenance) { input.BindingID = invalidUTF8 }},
		{name: "overlong binding ID", mutate: func(input *ImportProvenance) { input.BindingID = strings.Repeat("b", MaxImportIdentifierBytes+1) }},
		{name: "missing authenticated source", mutate: func(input *ImportProvenance) { input.AuthenticatedSource = "" }},
		{name: "invalid authenticated source UTF-8", mutate: func(input *ImportProvenance) { input.AuthenticatedSource = invalidUTF8 }},
		{name: "overlong authenticated source", mutate: func(input *ImportProvenance) {
			input.AuthenticatedSource = strings.Repeat("s", MaxImportIdentifierBytes+1)
		}},
		{name: "unknown mode", mutate: func(input *ImportProvenance) { input.Mode = "copy" }},
		{name: "import with derivation", mutate: func(input *ImportProvenance) {
			input.Mode = ImportModeImport
			input.Derivation = ImportDerivationFieldValue
			input.SourceAggregateCount = Absent[uint64]()
		}},
		{name: "import with aggregate count", mutate: func(input *ImportProvenance) {
			input.Mode = ImportModeImport
			input.Derivation = ""
		}},
		{name: "derive without derivation", mutate: func(input *ImportProvenance) {
			input.Mode = ImportModeDerive
			input.Derivation = ""
			input.SourceAggregateCount = Absent[uint64]()
		}},
		{name: "unknown derivation", mutate: func(input *ImportProvenance) {
			input.Mode = ImportModeDerive
			input.Derivation = "histogram"
			input.SourceAggregateCount = Absent[uint64]()
		}},
		{name: "non-mean with aggregate count", mutate: func(input *ImportProvenance) {
			input.Mode = ImportModeDerive
			input.Derivation = ImportDerivationElapsedTime
		}},
		{name: "mean without aggregate count", mutate: func(input *ImportProvenance) {
			input.SourceAggregateCount = Absent[uint64]()
		}},
		{name: "mean with zero aggregate count", mutate: func(input *ImportProvenance) {
			input.SourceAggregateCount = Present(uint64(0))
		}},
		{name: "hop above fixed maximum", mutate: func(input *ImportProvenance) { input.IngressHopCount = MaxImportForwardHops + 1 }},
		{name: "noncanonical UUID shape", mutate: func(input *ImportProvenance) { input.UpstreamRecordID = "{123e4567-e89b-12d3-a456-426614174000}" }},
		{name: "uppercase non-UUID token", mutate: func(input *ImportProvenance) { input.UpstreamRecordID = "UPSTREAM-RECORD" }},
		{name: "invalid redaction profile", mutate: func(input *ImportProvenance) { input.UpstreamRedactionProfile = "Sensitive Profile" }},
	}
	optionalBounded := map[string]func(*ImportProvenance, string){
		"upstream instance ID":  func(input *ImportProvenance, value string) { input.UpstreamInstanceID = value },
		"upstream service name": func(input *ImportProvenance, value string) { input.UpstreamServiceName = value },
		"last-hop instance ID":  func(input *ImportProvenance, value string) { input.LastHopInstanceID = value },
		"last-hop destination":  func(input *ImportProvenance, value string) { input.LastHopDestination = value },
	}
	for name, set := range optionalBounded {
		name, set := name, set
		invalid = append(invalid,
			struct {
				name   string
				mutate func(*ImportProvenance)
			}{name: "invalid UTF-8 " + name, mutate: func(input *ImportProvenance) { set(input, invalidUTF8) }},
			struct {
				name   string
				mutate func(*ImportProvenance)
			}{name: "overlong " + name, mutate: func(input *ImportProvenance) { set(input, strings.Repeat("x", MaxImportIdentifierBytes+1)) }},
		)
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			input := validImportProvenance()
			test.mutate(&input)
			if err := input.Validate(); err == nil {
				t.Fatal("invalid import provenance accepted")
			}
		})
	}
}

func TestImportProvenanceNestedWireShapeAndAbsence(t *testing.T) {
	ordinary, err := NewRecord(validRecordInput())
	if err != nil {
		t.Fatal(err)
	}
	ordinaryBytes, err := ordinary.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ordinaryBytes), `"import"`) {
		t.Fatalf("ordinary provenance gained an import member: %s", ordinaryBytes)
	}

	input := validRecordInput()
	input.Provenance.Import = func() *ImportProvenance {
		value := validImportProvenance()
		return &value
	}()
	record, err := NewRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := record.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	wantImport := `"import":{"authenticated_source":"codex","binding_id":"otlp.genai.span.operation.v1.chat","derivation":"arithmetic_mean","ingress_hop_count":3,"last_hop_destination":"otlp-primary","last_hop_instance_id":"forwarder-instance-1","mode":"import_and_derive","protocol":"otlp","source_aggregate_count":4,"upstream_instance_id":"upstream-instance-1","upstream_record_id":"123E4567-E89B-12D3-A456-426614174000","upstream_redaction_profile":"sensitive","upstream_service_name":"upstream-service"}`
	if !strings.Contains(string(encoded), wantImport) {
		t.Fatalf("nested import provenance mismatch\n got: %s\nwant member: %s", encoded, wantImport)
	}

	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	provenance := wire["provenance"].(map[string]any)
	importWire := provenance["import"].(map[string]any)
	if got := importWire["source_aggregate_count"]; got != float64(4) {
		t.Fatalf("source_aggregate_count = %#v", got)
	}
	if got := importWire["upstream_record_id"]; got != "123E4567-E89B-12D3-A456-426614174000" {
		t.Fatalf("upstream UUID bytes were normalized: %#v", got)
	}

	maximum := validImportProvenance()
	maximum.SourceAggregateCount = Present(^uint64(0))
	maximumWire, err := marshalMinimalJSON(importProvenanceWire(maximum))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(maximumWire), `"source_aggregate_count":18446744073709551615`) {
		t.Fatalf("maximum uint64 count was not serialized losslessly: %s", maximumWire)
	}
	plainImport := validImportProvenance()
	plainImport.Mode = ImportModeImport
	plainImport.Derivation = ""
	plainImport.SourceAggregateCount = Absent[uint64]()
	plainWire := importProvenanceWire(plainImport)
	if _, exists := plainWire["derivation"]; exists {
		t.Fatalf("plain import serialized a derivation: %#v", plainWire)
	}
	if _, exists := plainWire["source_aggregate_count"]; exists {
		t.Fatalf("plain import serialized an aggregate-count sentinel: %#v", plainWire)
	}
}

func TestImportProvenanceIsSnapshottedAcrossInputAccessorAndClone(t *testing.T) {
	importInput := validImportProvenance()
	input := validRecordInput()
	input.Provenance.Import = &importInput
	record, err := NewRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	want, err := record.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	importInput.BindingID = "mutated-input"
	importInput.SourceAggregateCount = Present(uint64(99))
	if got, err := record.Bytes(); err != nil || string(got) != string(want) {
		t.Fatalf("constructor retained mutable import input: got=%s err=%v", got, err)
	}

	returned := record.Provenance()
	if returned.Import == nil {
		t.Fatal("import provenance missing from accessor")
	}
	returned.Import.BindingID = "mutated-accessor"
	returned.Import.SourceAggregateCount = Present(uint64(100))
	if got, err := record.Bytes(); err != nil || string(got) != string(want) {
		t.Fatalf("accessor exposed mutable import state: got=%s err=%v", got, err)
	}

	clone := record.Clone()
	clone.data.provenance.Import.BindingID = "mutated-clone"
	clone.data.provenance.Import.SourceAggregateCount = Present(uint64(101))
	if got, err := record.Bytes(); err != nil || string(got) != string(want) {
		t.Fatalf("clone retained import alias to original: got=%s err=%v", got, err)
	}
	if clone.Provenance().Import.BindingID != "mutated-clone" {
		t.Fatal("clone mutation did not remain isolated on clone")
	}
}
