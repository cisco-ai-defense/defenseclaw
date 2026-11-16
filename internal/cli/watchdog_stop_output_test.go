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
)

// gateway stop and restart stop the watchdog quietly when none runs; only
// `watchdog stop` says it is not running (GAP-0007: gateway stop printed
// "Watchdog is not running" twice after a watchdog stop that said OK).
func TestStopWatchdogReportsNotRunningOnlyWhenAsked(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report bool
		want   string
	}{
		{name: "watchdog stop", report: true, want: "Watchdog is not running"},
		{name: "gateway stop", report: false, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			if err := stopWatchdogAt(t.TempDir(), &out, tc.report); err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSpace(stripANSI(out.String())); got != tc.want {
				t.Fatalf("output = %q, want %q", got, tc.want)
			}
		})
	}
}
