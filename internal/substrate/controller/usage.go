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
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	collectorlogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// UsageMessage and UsageEvent identify Substrate's per-actor usage record
// (ate.actor.usage_sampled): the stdout "msg", and the OTLP event name.
const (
	UsageMessage = "Actor usage sampled"
	UsageEvent   = "ate.actor.usage_sampled"
	// usageMaxBody bounds one POST to the usage receiver.
	usageMaxBody = 8 << 20
	usageForget  = 10 * time.Minute
	// usageMaxActors caps the tracked actors; past it new actors are not
	// tracked (no CPU sample means never idle, the safe side).
	usageMaxActors  = 100000
	usageSweepEvery = time.Minute
)

// UsageSample is one usage record: CPU seconds since the activation
// (epoch) began, read at At. Kind is initial, periodic or final.
type UsageSample struct {
	UID     string
	Epoch   int64
	CPUTime float64
	At      time.Time
	Kind    string
}

// UsageCPU turns Substrate's per-actor usage records into a CPU rate (the
// CPU source of idle suspend). The rate is the CPU time between the last
// two samples of the same activation over their wall time; a new
// activation starts over, and a final record forgets the actor. It
// implements CPUSource.
type UsageCPU struct {
	mu        sync.Mutex
	m         map[string]*usageState
	now       func() time.Time
	lastSweep time.Time
}

type usageState struct {
	epoch    int64
	cpu      float64
	at       time.Time
	rate     float64
	rateAt   time.Time
	haveRate bool
}

// NewUsageCPU returns an empty tracker.
func NewUsageCPU(now func() time.Time) *UsageCPU {
	if now == nil {
		now = time.Now
	}
	return &UsageCPU{m: map[string]*usageState{}, now: now}
}

// Ingest records one sample. Out-of-order and repeated samples are ignored.
func (u *UsageCPU) Ingest(s UsageSample) {
	if s.UID == "" || s.At.IsZero() {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if s.Kind == "final" {
		delete(u.m, s.UID)
		return
	}
	// Forget stale actors on every kind of insert, not only on a rate
	// update: a flood of new UIDs must not grow the map (GAP-0105).
	if now := u.now(); now.Sub(u.lastSweep) >= usageSweepEvery || len(u.m) >= usageMaxActors {
		u.lastSweep = now
		cut := now.Add(-usageForget)
		for uid, other := range u.m {
			if other.at.Before(cut) {
				delete(u.m, uid)
			}
		}
	}
	st, ok := u.m[s.UID]
	if !ok || st.epoch != s.Epoch {
		if !ok && len(u.m) >= usageMaxActors {
			return
		}
		u.m[s.UID] = &usageState{epoch: s.Epoch, cpu: s.CPUTime, at: s.At}
		return
	}
	if !s.At.After(st.at) || s.CPUTime < st.cpu {
		return
	}
	st.rate = (s.CPUTime - st.cpu) / s.At.Sub(st.at).Seconds()
	st.rateAt, st.haveRate = s.At, true
	st.cpu, st.at = s.CPUTime, s.At
}

// Len is the number of tracked actors (tests, metrics).
func (u *UsageCPU) Len() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.m)
}

// CPU implements CPUSource: the actor's CPU use in cores, dated by the
// newer sample of the pair it came from.
func (u *UsageCPU) CPU(uid string) (float64, time.Time, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	st, ok := u.m[uid]
	if !ok || !st.haveRate {
		return 0, time.Time{}, false
	}
	return st.rate, st.rateAt, true
}

// Handler accepts usage records: OTLP/HTTP logs (POST /v1/logs, protobuf
// or JSON) from the cluster's collector, and the ateworker stdout form
// (application/x-ndjson, one record per line). Other records in a batch
// are ignored. It answers OTLP requests with an empty export response.
// It is served on loopback (a collector sidecar) or over mutual TLS (see
// the controller's --usage-listen flags); actors can't reach it, as no
// egress rule names the controller.
func (u *UsageCPU) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, usageMaxBody+1))
		if err != nil || len(body) > usageMaxBody {
			http.Error(w, "body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch ct {
		case "application/x-ndjson", "application/jsonl", "text/plain":
			for _, s := range ParseUsageLines(body) {
				u.Ingest(s)
			}
			w.WriteHeader(http.StatusNoContent)
		case "application/x-protobuf", "application/json":
			req := &collectorlogpb.ExportLogsServiceRequest{}
			if ct == "application/json" {
				err = protojson.Unmarshal(body, req)
			} else {
				err = proto.Unmarshal(body, req)
			}
			if err != nil {
				http.Error(w, "invalid OTLP logs request", http.StatusBadRequest)
				return
			}
			for _, s := range usageFromOTLP(req) {
				u.Ingest(s)
			}
			resp := &collectorlogpb.ExportLogsServiceResponse{}
			var out []byte
			if ct == "application/json" {
				out, _ = protojson.Marshal(resp)
			} else {
				out, _ = proto.Marshal(resp)
			}
			w.Header().Set("Content-Type", ct)
			_, _ = w.Write(out)
		default:
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		}
	})
}

// ParseUsageLines reads ateworker stdout records, skipping other lines.
func ParseUsageLines(body []byte) []UsageSample {
	var out []UsageSample
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' || !bytes.Contains(line, []byte(UsageMessage)) {
			continue
		}
		var rec struct {
			Time    time.Time   `json:"time"`
			Msg     string      `json:"msg"`
			UID     string      `json:"ate.actor.uid"`
			Epoch   json.Number `json:"ate.actor.epoch"`
			CPUTime *float64    `json:"ate.stats.cpu.time"`
			Kind    string      `json:"ate.stats.kind"`
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		if dec.Decode(&rec) != nil || rec.Msg != UsageMessage || rec.CPUTime == nil {
			continue
		}
		epoch, _ := rec.Epoch.Int64()
		out = append(out, UsageSample{UID: rec.UID, Epoch: epoch, CPUTime: *rec.CPUTime, At: rec.Time, Kind: rec.Kind})
	}
	return out
}

func usageFromOTLP(req *collectorlogpb.ExportLogsServiceRequest) []UsageSample {
	var out []UsageSample
	for _, rl := range req.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			for _, lr := range sl.GetLogRecords() {
				attrs := map[string]*commonpb.AnyValue{}
				for _, kv := range lr.GetAttributes() {
					attrs[kv.GetKey()] = kv.GetValue()
				}
				name := lr.GetEventName()
				if name == "" {
					name = attrs["event.name"].GetStringValue()
				}
				if name != UsageEvent && !strings.EqualFold(lr.GetBody().GetStringValue(), UsageMessage) {
					continue
				}
				cpu, ok := attrs["ate.stats.cpu.time"]
				if !ok {
					continue
				}
				ts := lr.GetTimeUnixNano()
				if ts == 0 {
					ts = lr.GetObservedTimeUnixNano()
				}
				out = append(out, UsageSample{
					UID: attrs["ate.actor.uid"].GetStringValue(), Epoch: anyInt(attrs["ate.actor.epoch"]),
					CPUTime: anyFloat(cpu), At: time.Unix(0, int64(ts)).UTC(), Kind: attrs["ate.stats.kind"].GetStringValue(),
				})
			}
		}
	}
	return out
}

func anyInt(v *commonpb.AnyValue) int64 {
	if v == nil {
		return 0
	}
	if i, ok := v.GetValue().(*commonpb.AnyValue_IntValue); ok {
		return i.IntValue
	}
	return int64(v.GetDoubleValue())
}

func anyFloat(v *commonpb.AnyValue) float64 {
	if i, ok := v.GetValue().(*commonpb.AnyValue_IntValue); ok {
		return float64(i.IntValue)
	}
	return v.GetDoubleValue()
}
