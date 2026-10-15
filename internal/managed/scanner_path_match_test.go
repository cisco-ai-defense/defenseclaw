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

package managed

import "testing"

func TestWindowsPathWithinProfileRoots(t *testing.T) {
	roots := []string{`C:\Users`, `D:\Profiles\sample`}
	tests := []struct {
		name, path string
		want       bool
	}{
		{"Users root", `C:\Users`, true},
		{"profile", `D:\Profiles\sample\project`, true},
		{"mixed case", `c:\uSeRs\Sample\project`, true},
		{"short child name", `C:\Users\SAMPLE~1\project`, true},
		{"trailing dots and slashes", `C:\Users.\sample.\project..\`, true},
		{"extended prefix", `\\?\C:\Users\sample`, true},
		{"forward slashes", `C:/Users/sample/project`, true},
		{"prefix is not a boundary", `C:\Users2\sample`, false},
		{"outside", `C:\src\project`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := windowsPathWithinProfileRoots(tt.path, roots); got != tt.want {
				t.Fatalf("windowsPathWithinProfileRoots(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
