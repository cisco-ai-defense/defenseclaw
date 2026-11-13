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

package gateway

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// GAP-0225: a Bedrock invoke-with-response-stream chunk that ends partway
// through a frame is not forwarded before it can be decoded. The agent gets
// whole eventstream frames only, wherever the upstream cut its reads.

// flushRecorder notes how many bytes the client has when each flush happens.
type flushRecorder struct {
	*httptest.ResponseRecorder
	marks []int
}

func (f *flushRecorder) Flush() {
	f.marks = append(f.marks, f.Body.Len())
	f.ResponseRecorder.Flush()
}

// frameEnds are the byte offsets at which a frame of the stream ends.
func frameEnds(b []byte) map[int]bool {
	ends := map[int]bool{0: true}
	for off := 0; off+4 <= len(b); {
		off += int(binary.BigEndian.Uint32(b[off : off+4]))
		ends[off] = true
	}
	return ends
}

func TestPassthroughBedrockStreamForwardsWholeFramesAtEverySplit(t *testing.T) {
	frames := bedrockInvokeStreamFrames(t, "first "+covMarker, "second part", "third part")
	ends := frameEnds(frames)
	const path = "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke-with-response-stream"

	// One upstream and one proxy per verdict serve every split: the cuts of the
	// next reply are set before each request.
	var mu sync.Mutex
	var cuts []int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		cs := append(append([]int(nil), cuts...), len(frames))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		f, _ := w.(http.Flusher)
		prev := 0
		for _, c := range cs {
			_, _ = w.Write(frames[prev:c])
			f.Flush()
			prev = c
		}
	}))
	defer up.Close()
	newProxy := func(block bool) *GuardrailProxy {
		proxy, insp := bedrockPassthroughProxy(t, up)
		if proxy.cfg != nil {
			proxy.cfg.StreamBufferBytes = 1 // flush early, so the later reads take the post-flush path
		}
		if block {
			insp.setVerdict("completion", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "test marker"})
		} else {
			insp.setVerdict("completion", allowVerdict("mock"))
		}
		return proxy
	}
	allowProxy, blockProxy := newProxy(false), newProxy(true)
	run := func(t *testing.T, cs []int, block bool) *flushRecorder {
		mu.Lock()
		cuts = cs
		mu.Unlock()
		proxy := allowProxy
		if block {
			proxy = blockProxy
		}
		rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
		proxy.handlePassthrough(rec, bedrockRequest(up.URL, path))
		return rec
	}

	for cut := 1; cut < len(frames); cut++ {
		rec := run(t, []int{cut}, false)
		if !bytes.Equal(rec.Body.Bytes(), frames) {
			t.Fatalf("cut %d: the allowed stream changed (%d of %d bytes)", cut, rec.Body.Len(), len(frames))
		}
		for _, m := range rec.marks {
			if !ends[m] {
				t.Fatalf("cut %d: the agent had %d bytes, a part of a frame, at a flush", cut, m)
			}
		}
		if blocked := run(t, []int{cut}, true); bytes.Contains(blocked.Body.Bytes(), []byte("first ")) || bytes.Contains(blocked.Body.Bytes(), frames[:32]) {
			t.Fatalf("cut %d: a refused stream reached the agent (%d bytes)", cut, blocked.Body.Len())
		}
	}

	// One byte per read.
	every := make([]int, 0, len(frames))
	for c := 1; c < len(frames); c++ {
		every = append(every, c)
	}
	rec := run(t, every, false)
	if !bytes.Equal(rec.Body.Bytes(), frames) {
		t.Fatalf("byte-by-byte: the allowed stream changed (%d of %d bytes)", rec.Body.Len(), len(frames))
	}
	for _, m := range rec.marks {
		if !ends[m] {
			t.Fatalf("byte-by-byte: the agent had %d bytes, a part of a frame, at a flush", m)
		}
	}
}
