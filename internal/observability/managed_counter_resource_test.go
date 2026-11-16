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

package observability

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The gateway and the bundled collector keep the same resource attributes
// on the managed sandbox counters, and restrict the same metrics.
func TestRestrictedMetricResourceMatchesTheBundledCollector(t *testing.T) {
	raw, err := os.ReadFile("../../bundles/local_observability_stack/otel-collector/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`keep_keys\(resource\.attributes, \[([^\]]*)\]\)`).FindSubmatch(raw)
	if match == nil {
		t.Fatal("the collector has no keep_keys for the managed sandbox counters")
	}
	var collector []string
	for _, key := range strings.Split(string(match[1]), ",") {
		collector = append(collector, strings.Trim(strings.TrimSpace(key), `"`))
	}
	var gateway []string
	for key := range restrictedMetricResourceKeys {
		gateway = append(gateway, key)
	}
	sort.Strings(collector)
	sort.Strings(gateway)
	if strings.Join(collector, ",") != strings.Join(gateway, ",") {
		t.Fatalf("collector keeps %v, the gateway keeps %v", collector, gateway)
	}
	if !strings.Contains(string(raw), `IsMatch(metric.name, "^defenseclaw[.]sandbox[.]managed[.]")`) {
		t.Fatal("the collector no longer restricts defenseclaw.sandbox.managed.*")
	}
	for name := range resourceRestrictedMetrics {
		if !strings.HasPrefix(name, "defenseclaw.sandbox.managed.") {
			t.Fatalf("restricted metric %s is outside the collector branch", name)
		}
	}
}
