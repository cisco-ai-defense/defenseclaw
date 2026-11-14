// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	collectorlogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Two records as an ateworker on E1 writes them (actor identity changed).
const usageLines = `{"time":"2026-11-12T19:52:49.279547589Z","level":"INFO","msg":"Actor usage sampled","ate.atespace":"a3-gv","ate.actor.name":"x","ate.actor.uid":"u1","ate.template.atespace":"a3-gv","ate.template.name":"t","ate.sandbox.class":"gvisor","ate.stats.source":"cgroup","ate.stats.kind":"periodic","ate.actor.epoch":1794510461096178606,"ate.stats.memory.usage":18989056,"ate.stats.cpu.time":0.989268}
{"time":"2026-11-12T19:53:00Z","level":"INFO","msg":"other line"}
not json
{"time":"2026-11-12T19:53:49.279586113Z","level":"INFO","msg":"Actor usage sampled","ate.actor.uid":"u1","ate.stats.kind":"periodic","ate.actor.epoch":1794510461096178606,"ate.stats.cpu.time":1.007638}
`

func TestUsageCPUFromWorkerLines(t *testing.T) {
	u := NewUsageCPU(func() time.Time { return time.Date(2026, 11, 12, 19, 54, 0, 0, time.UTC) })
	samples := ParseUsageLines([]byte(usageLines))
	if len(samples) != 2 || samples[0].Epoch != 1794510461096178606 {
		t.Fatalf("samples = %+v", samples)
	}
	if _, _, ok := u.CPU("u1"); ok {
		t.Fatal("a rate before any sample")
	}
	for _, s := range samples {
		u.Ingest(s)
	}
	cores, at, ok := u.CPU("u1")
	if !ok || cores < 0.0003 || cores > 0.0004 || !at.Equal(samples[1].At) {
		t.Fatalf("cores = %v at %v ok %v", cores, at, ok)
	}
	// A new activation starts over; a final record forgets the actor.
	u.Ingest(UsageSample{UID: "u1", Epoch: 2, CPUTime: 0.1, At: samples[1].At.Add(time.Minute)})
	if _, _, ok := u.CPU("u1"); ok {
		t.Fatal("the rate survived a new activation")
	}
	u.Ingest(UsageSample{UID: "u1", Epoch: 2, CPUTime: 60.1, At: samples[1].At.Add(2 * time.Minute)})
	if cores, _, _ := u.CPU("u1"); cores < 0.99 || cores > 1.01 {
		t.Fatalf("busy actor cores = %v", cores)
	}
	u.Ingest(UsageSample{UID: "u1", Epoch: 2, Kind: "final", At: samples[1].At.Add(3 * time.Minute)})
	if _, _, ok := u.CPU("u1"); ok {
		t.Fatal("final did not forget the actor")
	}
}

func otlpRequest(cpu float64, at time.Time) *collectorlogpb.ExportLogsServiceRequest {
	str := func(s string) *commonpb.AnyValue {
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
	}
	return &collectorlogpb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{
		{EventName: UsageEvent, TimeUnixNano: uint64(at.UnixNano()), Attributes: []*commonpb.KeyValue{
			{Key: "ate.actor.uid", Value: str("u2")}, {Key: "ate.stats.kind", Value: str("periodic")},
			{Key: "ate.actor.epoch", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 7}}},
			{Key: "ate.stats.cpu.time", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: cpu}}},
		}},
		{Body: str("unrelated"), TimeUnixNano: uint64(at.UnixNano())},
	}}}}}}
}

func TestUsageHandlerOTLPAndLines(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 19, 50, 0, 0, time.UTC)
	u := NewUsageCPU(func() time.Time { return t0.Add(5 * time.Minute) })
	h := u.Handler()
	post := func(ct string, body []byte) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(body))
		req.Header.Set("Content-Type", ct)
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	pbBody, _ := proto.Marshal(otlpRequest(1, t0))
	jsBody, _ := protojson.Marshal(otlpRequest(31, t0.Add(time.Minute)))
	if post("application/x-protobuf", pbBody) != 200 || post("application/json", jsBody) != 200 {
		t.Fatal("OTLP posts refused")
	}
	if cores, _, ok := u.CPU("u2"); !ok || cores < 0.49 || cores > 0.51 {
		t.Fatalf("OTLP cores = %v %v", cores, ok)
	}
	if post("application/x-ndjson", []byte(usageLines)) != http.StatusNoContent {
		t.Fatal("ndjson post refused")
	}
	if _, _, ok := u.CPU("u1"); !ok {
		t.Fatal("ndjson samples not ingested")
	}
	if post("application/x-protobuf", []byte("garbage")) != http.StatusBadRequest || post("text/html", nil) != http.StatusUnsupportedMediaType {
		t.Fatal("bad bodies accepted")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/logs", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatal("GET accepted")
	}
}
