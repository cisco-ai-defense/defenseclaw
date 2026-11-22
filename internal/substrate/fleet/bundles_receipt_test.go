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

package fleet

import (
	"regexp"
	"strings"
	"testing"
)

// GAP-0432: the receipt has no id of its own; the documents name it by a
// stable id that depends on every field that identifies the apply, and works
// for any source (admin, inbox, a registry).
func TestReceiptIDNamesTheApplyForAnySource(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	base := ReceiptID("2026-11-13T15:00:00Z", "admin", "s-eng", sha)
	if !regexp.MustCompile(`^r-[0-9a-f]{16}$`).MatchString(base) {
		t.Fatalf("receipt id %q", base)
	}
	if again := ReceiptID("2026-11-13T15:00:00Z", "admin", "s-eng", sha); again != base {
		t.Errorf("not stable: %s vs %s", again, base)
	}
	for name, id := range map[string]string{
		"time":   ReceiptID("2026-11-13T15:00:01Z", "admin", "s-eng", sha),
		"source": ReceiptID("2026-11-13T15:00:00Z", "oci", "s-eng", sha),
		"stage":  ReceiptID("2026-11-13T15:00:00Z", "admin", "s-all", sha),
		"sha":    ReceiptID("2026-11-13T15:00:00Z", "admin", "s-eng", strings.Repeat("cd", 32)),
	} {
		if id == base {
			t.Errorf("changing the %s keeps the receipt id", name)
		}
	}
}
