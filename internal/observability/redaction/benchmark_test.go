// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

var benchmarkRedactionProjection Projection

func BenchmarkSensitiveRedaction(b *testing.B) {
	engine, err := NewEngine(bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		b.Fatal(err)
	}
	profile, ok := BuiltInProfile(ProfileSensitive)
	if !ok {
		b.Fatal("sensitive profile is unavailable")
	}
	cases := []struct {
		name    string
		body    map[string]any
		classes map[string]observability.FieldClass
	}{
		{
			name: "plain_text",
			body: map[string]any{
				"message": "Contact alice@example.test or call +1 (212) 555-0198; token=ghp_1234567890abcdefghijklmnopqrstuv.",
			},
			classes: map[string]observability.FieldClass{
				"/message": observability.FieldClassContent,
			},
		},
		{
			name: "nested_structured",
			body: map[string]any{
				"request": map[string]any{
					"messages": []any{
						map[string]any{"role": "system", "content": "Keep customer data private."},
						map[string]any{"role": "user", "content": "Email bob@example.test and use card 4111 1111 1111 1111."},
					},
					"metadata": map[string]any{
						"workspace": "workspace-17",
						"path":      "/srv/private/../models/customer.json",
					},
				},
				"credentials": map[string]any{
					"api_key": "sk-example-sensitive-value",
				},
			},
			classes: map[string]observability.FieldClass{
				"/request/messages/0/role":    observability.FieldClassMetadata,
				"/request/messages/0/content": observability.FieldClassContent,
				"/request/messages/1/role":    observability.FieldClassMetadata,
				"/request/messages/1/content": observability.FieldClassContent,
				"/request/metadata/workspace": observability.FieldClassIdentifier,
				"/request/metadata/path":      observability.FieldClassPath,
				"/credentials/api_key":        observability.FieldClassCredential,
			},
		},
	}
	for _, test := range cases {
		record := benchmarkRedactionRecord(b, test.name, test.body, test.classes)
		projection, _, err := engine.Project(record, profile)
		if err != nil {
			b.Fatalf("%s semantic projection: %v", test.name, err)
		}
		metadata := projection.Metadata()
		if metadata.State != ProjectionStateTransformed || metadata.TransformedFields == 0 {
			b.Fatalf("%s semantic projection metadata=%+v", test.name, metadata)
		}
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				projection, _, err := engine.Project(record, profile)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkRedactionProjection = projection
			}
		})
	}
}

func benchmarkRedactionRecord(
	b *testing.B,
	id string,
	body map[string]any,
	classes map[string]observability.FieldClass,
) observability.Record {
	b.Helper()
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(1_800_000_010, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "benchmark-redaction-" + id, nil }),
	)
	if err != nil {
		b.Fatal(err)
	}
	record, err := builder.BuildClassifiedLog(observability.ClassifiedLogInput{
		ProducerKind: observability.ProducerGatewayEvent,
		ProducerKey:  "diagnostic",
		ClassificationContext: observability.ClassificationContext{
			RawSeverity: "INFO",
		},
		Source: observability.SourceSystem, Action: "diagnostic",
		Outcome: observability.OutcomeCompleted,
		Provenance: observability.Provenance{
			Producer: "benchmark", BinaryVersion: "8.0.0",
			RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
			ConfigGeneration:      1,
			ConfigDigest:          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Body: body, FieldClasses: classes,
	})
	if err != nil {
		b.Fatal(err)
	}
	return record
}
