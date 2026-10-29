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
	"runtime"
	"testing"
)

// A HOME value the walk could not read (export HOME=$(echo $HOME), HOME=$X,
// declare -n HOME=X) made HOME unknown, and an unknown HOME dropped every
// later ~ state write; local HOME=v and export -n HOME=v were not read, and
// a prefix HOME=v moved the ~ of the words of its own command, which the
// shell expands with the previous HOME (GAP-2476, RV-pc11-1).
func TestUnreadableHomeValueKeepsThePreviousHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"HOME=$(echo $HOME); cp a.txt ~/.defenseclaw/config.yaml", true},
		{"export HOME=$(echo $HOME); cp a.txt ~/.defenseclaw/config.yaml", true},
		{"export HOME=$(printenv HOME); cp a.txt ~/.defenseclaw/config.yaml", true},
		{"export HOME=\"$(getent passwd $USER | cut -d: -f6)\"; cp a.txt ~/.defenseclaw/config.yaml", true},
		{"export HOME=$(echo $HOME); cp a.txt ~/.defenseclaw/hooks/x.sh", true},
		{"export -n HOME=$HOME/.defenseclaw; cp a.txt ~/config.yaml", true},
		{"declare -n HOME=X; cp a.txt ~/.defenseclaw/config.yaml", true},
		{"export HOME=$X; cp a.txt ~/.defenseclaw/config.yaml", true},
		{"HOME=$X; cp a.txt ~/.defenseclaw/config.yaml", true},
		{"HOME=$X; cp a.txt $HOME/.defenseclaw/config.yaml", true},
		{"f(){ local HOME=$HOME/.defenseclaw; cp a.txt ~/config.yaml; }; f", true},
		{"HOME=/tmp cp a.txt ~/.defenseclaw/config.yaml", true},
		{"export HOME=$HOME/.defenseclaw; cp a.txt ~/config.yaml", true},
		{"export HOME=$(mktemp -d); cp a.txt ~/out.txt", false},
		{"export HOME=/home/other; cp a.txt ~/config.yaml", false},
		{"f(){ local HOME=/tmp/fakehome; cp a.txt ~/out.txt; }; f", false},
		{"HOME=/tmp/x cp a.txt ~/project/out.txt", false},
	})
}
