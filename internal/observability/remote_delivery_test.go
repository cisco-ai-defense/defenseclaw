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

package observability_test

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestRemoteDeliveryOutstandingIdentitySettlesBeforeItCanBeRetried(t *testing.T) {
	delivery := observability.NewRemoteDelivery()
	delivery.BeginAttempt()
	first, ok := delivery.TryTrack("original")
	if !ok {
		t.Fatal("first offer was not admitted")
	}
	delivery.EndAttempt()

	// The reporter can begin another offer after its wait expires, while
	// the original queue is still retrying. That offer cannot reserve the
	// same identity, but can reserve a replacement.
	delivery.BeginAttempt()
	if _, ok := delivery.TryTrack("original"); ok {
		t.Fatal("second offer reserved an outstanding identity")
	}
	replacement, ok := delivery.TryTrack("replacement")
	if !ok {
		t.Fatal("second offer did not admit the replacement identity")
	}
	delivery.EndAttempt()
	replacement(true)
	if settled, _ := delivery.Settled(); settled {
		t.Fatal("replacement acknowledgement settled the original delivery")
	}
	first(false)
	if settled, delivered := delivery.Settled(); !settled || delivered {
		t.Fatalf("original refusal after a later offer: settled=%t delivered=%t", settled, delivered)
	}

	delivery.BeginAttempt()
	retry, ok := delivery.TryTrack("original")
	if !ok {
		t.Fatal("settled refusal could not be retried")
	}
	if _, ok := delivery.TryTrack("replacement"); ok {
		t.Fatal("acknowledged replacement was queued again")
	}
	delivery.EndAttempt()
	retry(true)
	if settled, delivered := delivery.Settled(); !settled || !delivered {
		t.Fatalf("retry acknowledgement: settled=%t delivered=%t", settled, delivered)
	}
}
