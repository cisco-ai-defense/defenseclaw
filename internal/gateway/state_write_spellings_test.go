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

// The runtime-operand readings of GAP-2477 knew only a bare cp, mv,
// install or ln program word: dd, tee, a program path (/bin/cp) and a
// command, env or sudo wrapper kept the partial argv that tied no path to
// the call (checker pc11).
func TestDynamicOperandWordThroughProgramPathsAndWrappers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"/bin/cp a.txt $HOME/.defenseclaw/config.yaml $(true)", true},
		{"/usr/bin/cp a.txt HOMEDIR/.defenseclaw/config.yaml `true`", true},
		{"command cp a.txt ~/.defenseclaw/config.yaml $(true)", true},
		{"env cp a.txt ~/.defenseclaw/config.yaml $(true)", true},
		{"sudo cp a.txt ~/.defenseclaw/config.yaml $(true)", true},
		{"dd if=a.txt of=$HOME/.defenseclaw/config.yaml $(true)", true},
		{"dd if=$SRC of=$HOME/.defenseclaw/config.yaml", true},
		{"tee ~/.defenseclaw/config.yaml $(true) < a.txt", true},
		{"cat a.txt | tee ~/.defenseclaw/config.yaml $X", true},
		{"/bin/cp a.txt ~/.defenseclaw/config.yaml $X", true},
		{"tee out.txt $(true) < a.txt", false},
		{"/bin/cp a.txt b.txt $(true)", false},
		{"dd if=a.txt of=out.img $(true)", false},
		{"sudo cp a.txt /tmp/x.txt $(true)", false},
		{"command -v cp $(true)", false},
	})
}

// ln, rsync and cp -s had no write fact, and a pathname pattern under
// ~/.defenseclaw named no state file, so these literal state writes were
// allowed by the gateway reading (GAP-2496).
func TestLinkRsyncAndPatternStateWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"ln -sf a.txt ~/.defenseclaw/config.yaml", true},
		{"ln -sf a.txt HOMEDIR/.defenseclaw/config.yaml", true},
		{"ln a.txt ~/.defenseclaw/config.yaml", true},
		{"ln -sfn /tmp/x ~/.defenseclaw/hooks", true},
		{"ln -s -t ~/.defenseclaw/hooks /tmp/x.sh", true},
		{"rsync a.txt ~/.defenseclaw/hooks/x.sh", true},
		{"rsync -a src/ ~/.defenseclaw/hooks/", true},
		{"rsync -avz --progress a.txt ~/.defenseclaw/config.yaml", true},
		{"cp -s a.txt ~/.defenseclaw/config.yaml", true},
		{"cp a.txt ~/.defenseclaw/config.y?ml", true},
		{"cp a.txt ~/.defenseclaw/conf*.yaml", true},
		{"cp a.txt $HOME/.defenseclaw/conf[i]g.yaml", true},
		{"ln -sf $(pwd)/a.txt ~/.local/bin/tool", false},
		{"ln -s $HOME/.defenseclaw/config.yaml ~/project/cfg-link", false},
		{"ln -s ~/.defenseclaw/config.yaml cfg", false},
		{"ln -sf ~/project/a.txt ~/project/link", false},
		{"rsync -a src/ ~/project/backup/", false},
		{"rsync -av ~/.defenseclaw/ /tmp/dcbackup/", false},
		{"rsync -a ~/project/ host:/srv/project/", false},
		{"rsync -n a.txt ~/.defenseclaw/config.yaml", false},
		{"cp -s ~/project/a.txt ~/project/slink", false},
		{"cp a.txt ~/project/*.bak", false},
		{"cp a.txt ~/.defenseclaw/nomatch*.yaml", false},
		{"ls ~/.defenseclaw/conf*.yaml", false},
	})
}
