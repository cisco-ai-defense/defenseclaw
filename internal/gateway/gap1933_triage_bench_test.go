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
	"strings"
	"testing"
)

// BenchmarkGAP1933TriagePatterns times the prompt triage, evidence windows
// included: ordinary text, mixed-case text with a match, and non-ASCII text
// with a match.
func BenchmarkGAP1933TriagePatterns(b *testing.B) {
	for _, c := range []struct{ name, text string }{
		{"short", "Hello, can you help me write a function that parses a CSV file?"},
		{"mixed4k", strings.Repeat("Please Review The Attached Report And Summarise It. ", 80) + "find their password"},
		{"nonascii", strings.Repeat("Résumé für Ärzte, naïve café. ", 100) + "find their password"},
	} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = triagePatterns("prompt", c.text)
			}
		})
	}
}
