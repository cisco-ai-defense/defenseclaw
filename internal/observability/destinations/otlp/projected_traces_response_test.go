// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"testing"

	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestDecodeProjectedTraceHTTPResponseSupportsOTLPEncodings(t *testing.T) {
	t.Parallel()
	partial := &collectortracepb.ExportTraceServiceResponse{
		PartialSuccess: &collectortracepb.ExportTracePartialSuccess{
			RejectedSpans: 1,
			ErrorMessage:  "bounded diagnostic",
		},
	}
	protobufBody, err := proto.Marshal(partial)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{name: "empty protobuf without content type", body: nil},
		{name: "protobuf", contentType: "application/x-protobuf", body: protobufBody},
		{
			name:        "JSON with media type parameters",
			contentType: "application/json; charset=utf-8",
			body:        []byte(`{"partialSuccess":{"rejectedSpans":"1","errorMessage":"bounded diagnostic"}}`),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, ok := decodeProjectedTraceHTTPResponse(test.contentType, test.body)
			if !ok || got == nil {
				t.Fatal("valid OTLP response was rejected")
			}
			if len(test.body) == 0 {
				if got.PartialSuccess != nil {
					t.Fatalf("empty response = %+v", got)
				}
				return
			}
			if !proto.Equal(got, partial) {
				t.Fatalf("decoded response = %+v, want %+v", got, partial)
			}
		})
	}
}

func TestDecodeProjectedTraceHTTPResponseFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{name: "malformed JSON", contentType: "application/json", body: []byte(`{"partialSuccess":`)},
		{name: "unknown JSON field", contentType: "application/json", body: []byte(`{"accepted":true}`)},
		{name: "JSON body labeled protobuf", contentType: "application/x-protobuf", body: []byte(`{}`)},
		{name: "unsupported media type", contentType: "text/plain", body: []byte(`{}`)},
		{name: "malformed media type", contentType: `application/json; charset="`, body: []byte(`{}`)},
		{name: "empty unsupported media type", contentType: "text/plain", body: nil},
		{name: "empty malformed media type", contentType: `application/json; charset="`, body: nil},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got, ok := decodeProjectedTraceHTTPResponse(test.contentType, test.body); ok || got != nil {
				t.Fatalf("invalid response accepted: %+v", got)
			}
		})
	}
}
