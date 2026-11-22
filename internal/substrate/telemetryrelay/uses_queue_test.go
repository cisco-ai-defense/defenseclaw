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

package telemetryrelay

import (
	"context"
	"testing"
	"time"
)

// S6b: a secret-injection record (an older callout posts one per bound
// secret per request) is nothing a gateway exports, so it never takes room
// in the export queue; the decisions still go.
func TestS6bInjectRecordsStayOutOfQueue(t *testing.T) {
	ctx := context.Background()
	s := &Store{}
	now := time.Now().UTC()
	in := []Record{
		{Kind: KindEgress, Atespace: "eng", Actor: "a", UID: "u1", Host: "gitlab.com", Decision: "allow", At: now},
		{Kind: KindEgress, Atespace: "eng", Actor: "a", UID: "u1", Host: "gitlab.com", Decision: "inject", At: now},
		{Kind: KindEgress, Atespace: "eng", Actor: "a", UID: "u1", Host: "x.example", Decision: "block", At: now},
	}
	if _, err := s.PostEgress(ctx, PostRequest{Records: in}); err != nil {
		t.Fatal(err)
	}
	taken, _ := s.Take(ctx, TakeRequest{})
	if len(taken.Records) != 2 {
		t.Fatalf("taken %+v, want the allow and the block", taken.Records)
	}
	for _, r := range taken.Records {
		if r.Decision == "inject" {
			t.Errorf("an injection record reached the export queue: %+v", r)
		}
	}
}
