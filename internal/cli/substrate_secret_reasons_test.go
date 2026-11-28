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

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/substrate/reasons"
)

// TestB1CLIMessageForSecretReasons: every gateway secret reason reads as
// the table's words and fix, never the generic "the cluster refused this".
func TestB1CLIMessageForSecretReasons(t *testing.T) {
	for _, r := range reasons.Table {
		if r.Where != reasons.API {
			continue
		}
		msg := substrateAPIMessage(&api.Error{Status: r.HTTP, Reason: r.Code})
		if !strings.Contains(msg, strings.TrimSuffix(r.Words, ".")) || !strings.Contains(msg, r.Fix) || !strings.Contains(msg, "("+r.Code+")") {
			t.Errorf("%s (%d): message %q lacks the table words, fix or code", r.Code, r.HTTP, msg)
		}
		if strings.Contains(msg, "the cluster refused this") || strings.Contains(msg, "no such item") {
			t.Errorf("%s: generic fallback %q", r.Code, msg)
		}
	}
	// A code outside the table still gets the generic arm.
	if msg := substrateAPIMessage(&api.Error{Status: 403, Reason: "something_new"}); msg != "the cluster refused this (something new)" {
		t.Fatalf("generic 403 = %q", msg)
	}
}
