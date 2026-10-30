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

package netguard

import (
	"strings"
	"testing"
)

// GAP-0666: a proxy URL without a scheme is refused with the form to use.
func TestParseEgressProxyURLNamesTheForm(t *testing.T) {
	for _, raw := range []string{"127.0.0.1:3128", "proxy.example.com:8080"} {
		_, err := ParseEgressProxyURL(raw)
		if err == nil || !strings.Contains(err.Error(), "needs a scheme: use http://host[:port] or https://host[:port]") {
			t.Fatalf("ParseEgressProxyURL(%q) = %v", raw, err)
		}
		if strings.Contains(err.Error(), "first path segment") {
			t.Fatalf("raw parser text leaked: %v", err)
		}
	}
	if _, err := ParseEgressProxyURL("http://127.0.0.1:3128"); err != nil {
		t.Fatalf("valid proxy refused: %v", err)
	}
}
