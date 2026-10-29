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
	"time"
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

// The pattern reading listed every directory a wildcard above the home
// could reach: ls /*/*/*/*/*/.defenseclaw/x took 27 s and more, past the
// hook answer budget, so one extra word turned a blocked command into the
// fail-mode answer (RV-pod2-1, GAP-2496). Only the active home
// .defenseclaw tree is read now, and a pattern that spells that name with
// wildcards is read too.
func TestStatePatternReadsOnlyTheHomeStateTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	start := time.Now()
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"cp a.txt ~/.defenseclaw/config.yaml; ls /*/*/*/*/*/.defenseclaw/x", true},
		{"cp a.txt ~/.defenseclaw/config.yaml; ls /*/*/*/*/*/*/*/.defenseclaw/x", true},
		{"cp a.txt ~/.def*/config.yaml", true},
		{"cp a.txt ~/.defensecla[w]/config.yaml", true},
		{"ln -sf a.txt ~/.def*/config.yaml", true},
		{"cp a.txt HOMEDIR/.defenseclaw/c?nfig.yaml", true},
		{"ls /*/*/*/*/*/.defenseclaw/x", false},
		{"ls /*/*/*/*/*/*/*/.defenseclaw/x", false},
		{"ls ~/.def*/conf*.yaml", false},
		{"cp a.txt ~/.def*/nomatch.yaml", false},
		{"cp ~/.def*/config.yaml ~/project/backup.yaml", false},
	})
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("44 pattern rows took %s; the reading must not walk past the home", elapsed)
	}
}

// local HOME=v was applied to the caller with no function scope, also at
// the top level, where bash refuses local and leaves HOME as it was, and
// after the function returned, when the caller HOME is back (RV-pod2-2,
// GAP-2476).
func TestLocalHomeCountsOnlyInItsFunctionBody(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"local HOME=/tmp/x; cp a.txt ~/.defenseclaw/config.yaml", true},
		{"local HOME=/tmp/x 2>/dev/null; cp a.txt ~/.defenseclaw/config.yaml", true},
		{"f(){ local HOME=/tmp/x; }; f; cp a.txt ~/.defenseclaw/config.yaml", true},
		{"f(){ local HOME=/tmp/x; true; }; f; f; cp a.txt ~/.defenseclaw/hooks/x.sh", true},
		{"f(){ if true; then local HOME=/tmp/x; fi; }; f; cp a.txt ~/.defenseclaw/config.yaml", true},
		{"f(){ local HOME=$HOME/.defenseclaw; cp a.txt ~/config.yaml; }; f", true},
		{"g(){ cp a.txt ~/config.yaml; }; f(){ local HOME=$HOME/.defenseclaw; g; }; f", true},
		{"f(){ HOME=$HOME/.defenseclaw; }; f; cp a.txt ~/config.yaml", true},
		{"f(){ local HOME=$HOME/.defenseclaw; true; }; f; cp a.txt ~/config.yaml", false},
		{"f(){ local HOME=/tmp/fakehome; cp a.txt ~/out.txt; }; f", false},
	})
}

// A file writer run through nohup, nice, time, timeout or env NAME=value,
// through command, sudo or env with options, or after a leading word that
// may expand to nothing, tied no write to the call, while it writes what
// the plain call writes (GAP-2512, GAP-2477 checker pod2 W05-W12).
func TestWrappedFileWriterWritesWhatThePlainCallWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"nohup cp a.txt ~/.defenseclaw/config.yaml", true},
		{"nice cp a.txt ~/.defenseclaw/config.yaml", true},
		{"nice -n 5 cp a.txt ~/.defenseclaw/hooks/x.sh", true},
		{"nice -5 mv a.txt ~/.defenseclaw/config.yaml", true},
		{"time cp a.txt ~/.defenseclaw/config.yaml", true},
		{"time -p cp a.txt ~/.defenseclaw/config.yaml", true},
		{"/usr/bin/time -f %e cp a.txt ~/.defenseclaw/config.yaml", true},
		{"timeout 5 cp a.txt ~/.defenseclaw/config.yaml", true},
		{"timeout -k 2 10s install a.txt ~/.defenseclaw/hooks/x.sh", true},
		{"env NAME=v cp a.txt ~/.defenseclaw/config.yaml", true},
		{"env -i cp a.txt ~/.defenseclaw/config.yaml $(true)", true},
		{"sudo -u root cp a.txt ~/.defenseclaw/config.yaml $(true)", true},
		{"command -p cp a.txt ~/.defenseclaw/config.yaml $(true)", true},
		{"$(true) cp a.txt ~/.defenseclaw/config.yaml", true},
		{"nohup nice tee ~/.defenseclaw/config.yaml < a.txt", true},
		{"nohup ln -sf a.txt ~/.defenseclaw/config.yaml", true},
		{"nohup cp a.txt b.txt", false},
		{"env FOO=1 cp a.txt b.txt", false},
		{"nice ls -la", false},
		{"time cp a.txt ~/project/c.txt", false},
		{"timeout 60 rsync -a src/ ~/project/backup/", false},
		{"sudo -u root cp a.txt /tmp/x.txt", false},
		{"nohup cp ~/.defenseclaw/config.yaml ~/project/backup.yaml", false},
	})
}

// A static prefix wrapper that runs its child in the caller directory
// (nohup, env NAME=value) made a wrapped ln an unreadable link, so its
// destination counted as a possible keys write: nohup ln -sf $(pwd)/a.txt
// ~/.local/bin/tool blocked while the plain ln is allowed (checker p3i3
// RV-p3i3-1, GAP-2496). The wrapped ln reads like the plain ln.
func TestWrappedLinkReadsLikeThePlainLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"nohup ln -sf $(pwd)/a.txt ~/.local/bin/tool", false},
		{"env A=1 ln -s $(pwd)/a.txt ~/.local/bin/tool", false},
		{"nohup ln -sf ~/project/a.txt ~/.local/bin/tool", false},
		{"nohup ln -sf $PWD/a.txt ~/.local/bin/tool", false},
		{"nohup ln -sf `pwd`/a.txt ~/.local/bin/tool", false},
		{"nohup ln -s $(pwd)/a.txt ~/.local/bin/tool", false},
		{"ln -sf $(pwd)/a.txt ~/.local/bin/tool", false},
		{"nohup ln -sf a.txt ~/.defenseclaw/config.yaml", true},
		{"env A=1 ln -sfn /tmp/x ~/.defenseclaw/hooks", true},
		{"nohup ln -s ~/.ssh/authorized_keys k; cp a.txt k", true},
		{"env PATH=/tmp/bin ln -s ~/.ssh/authorized_keys k; cp a.txt k", true},
	})
}

// A file writer run through setsid, stdbuf, ionice, taskset, chrt, doas,
// flock FILE, caffeinate, sudo -i or -s, env -C DIR or builtin command
// tied no write to the call, while it writes what the plain call writes
// (GAP-2519, checker p3i3 X01-X06, X17, X25-X27, X32).
func TestExecRunnersWriteWhatThePlainCallWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"setsid cp a.txt ~/.defenseclaw/config.yaml", true},
		{"setsid -f cp a.txt ~/.defenseclaw/config.yaml", true},
		{"stdbuf -o0 cp a.txt ~/.defenseclaw/config.yaml", true},
		{"stdbuf -o L tee ~/.defenseclaw/config.yaml < a.txt", true},
		{"ionice -c3 cp a.txt ~/.defenseclaw/config.yaml", true},
		{"ionice -c 2 -n 7 mv a.txt ~/.defenseclaw/config.yaml", true},
		{"taskset -c 0 cp a.txt ~/.defenseclaw/config.yaml", true},
		{"taskset 0x1 install a.txt ~/.defenseclaw/hooks/x.sh", true},
		{"chrt -b 0 cp a.txt ~/.defenseclaw/config.yaml", true},
		{"doas cp a.txt ~/.defenseclaw/config.yaml", true},
		{"doas -u root cp a.txt ~/.defenseclaw/config.yaml", true},
		{"flock /tmp/zzl cp a.txt ~/.defenseclaw/config.yaml", true},
		{"flock -w 5 /tmp/zzl cp a.txt ~/.defenseclaw/config.yaml", true},
		{"caffeinate -i cp a.txt ~/.defenseclaw/config.yaml", true},
		{"sudo -i cp a.txt ~/.defenseclaw/config.yaml", true},
		{"sudo -s cp a.txt ~/.defenseclaw/config.yaml", true},
		{"env --chdir=/ cp a.txt ~/.defenseclaw/config.yaml", true},
		{"env -C / cp HOMEDIR/project/a.txt HOMEDIR/.defenseclaw/config.yaml", true},
		{"env -C HOMEDIR cp project/a.txt .defenseclaw/config.yaml", true},
		{"builtin command cp a.txt ~/.defenseclaw/config.yaml", true},
		{"setsid nohup cp a.txt ~/.ssh/authorized_keys", true},
		{"setsid cp a.txt b.txt", false},
		{"stdbuf -oL tee out.log < a.txt", false},
		{"flock /tmp/zzl make --version", false},
		{"ionice -c3 cp a.txt ~/project/backup.txt", false},
		{"env -C /tmp cp HOMEDIR/project/a.txt .defenseclaw-notes.txt", false},
		{"env -C /tmp cp HOMEDIR/project/a.txt .defenseclaw/config.yaml", false},
		{"taskset -c 0 cp ~/.defenseclaw/config.yaml ~/project/backup.yaml", false},
	})
}

// export, declare and typeset of HOME in a function body went unread when
// the action also defined a function (the exported-function reading
// refused an assignment word), and declare or typeset without -g there
// set the caller HOME, while bash makes it local to the body (checker
// p3i3 D01-D04c, D12, D18, D21, GAP-2476).
func TestHomeDeclarationInAFunctionBody(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"f(){ declare HOME=/tmp/x; }; f; cp a.txt ~/.defenseclaw/config.yaml", true},
		{"f(){ typeset HOME=/tmp/x; }; f; cp a.txt ~/.defenseclaw/config.yaml", true},
		{"f(){ declare -x HOME=/tmp/x; }; f; cp a.txt ~/.defenseclaw/config.yaml", true},
		{"f(){ declare -r HOME=/tmp/x; }; f; cp a.txt ~/.defenseclaw/config.yaml", true},
		{"f(){ declare HOME=/tmp/x; }; f; cp a.txt ~/.defenseclaw/hooks/x.sh", true},
		{"f(){ typeset -x HOME=/tmp/x; }; f; mv a.txt ~/.defenseclaw/config.yaml", true},
		{"f(){ declare HOME=$HOME/.defenseclaw; cp a.txt ~/config.yaml; }; f", true},
		{"f(){ export HOME=$HOME/.defenseclaw; cp a.txt ~/config.yaml; }; f", true},
		{"f(){ declare -g HOME=$HOME/.defenseclaw; }; f; cp a.txt ~/config.yaml", true},
		{"f(){ export HOME=$HOME/.defenseclaw; }; f; cp a.txt ~/config.yaml", true},
		{"f(){ readonly HOME=$HOME/.defenseclaw; }; f; cp a.txt ~/config.yaml", true},
		{"declare HOME=$HOME/.defenseclaw; cp a.txt ~/config.yaml", true},
		{"f(){ export HOME=/tmp/x; cp a.txt ~/.defenseclaw/config.yaml; }; f", false},
		{"f(){ declare -g HOME=/tmp/x; }; f; cp a.txt ~/.defenseclaw/config.yaml", false},
		{"f(){ declare HOME=/tmp/x; cp a.txt ~/.defenseclaw/config.yaml; }; f", false},
		{"declare HOME=/tmp/x; cp a.txt ~/out.txt", false},
		{"f(){ declare -x HOME=$(mktemp -d); cp a.txt ~/out.txt; }; f", false},
		{"f(){ export FOO=1; cp a.txt ~/project/out.txt; }; f", false},
	})
}

// A link the command itself makes to DefenseClaw state (the ~/.defenseclaw
// directory, hooks/ or a state file) is an alias of that state: a later
// write through the link name writes the state, plain or behind a static
// prefix wrapper, as the ~/.ssh alias does (GAP-1521). The wrapped forms
// blocked only through the cautious unknown-link reading before 67815d9314
// (checker pod4 RV-pod4-1, GAP-2496); the plain forms never blocked
// (GAP-2522).
func TestWriteThroughALinkToStateIsAStateWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"nohup ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"env A=1 ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"sudo ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"ln -s ~/.defenseclaw/hooks hh; cp a.txt hh/x.sh", true},
		{"nohup ln -s ~/.defenseclaw/hooks hh; cp a.txt hh/x.sh", true},
		{"ln -s ~/.defenseclaw/config.yaml c; cp a.txt c", true},
		{"nohup ln -s ~/.defenseclaw/config.yaml c; cp a.txt c", true},
		{"ln -s ~/.defenseclaw hc && echo x > hc/config.yaml", true},
		{"nohup ln -s ~/.defenseclaw hc && echo x > hc/config.yaml", true},
		{"busybox ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"sudo busybox ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"setsid ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"nohup ln -s ~/.defenseclaw hc; tee hc/config.yaml < a.txt", true},
		{"time ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"nice ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"ln -s HOMEDIR/.defenseclaw hc; mv a.txt hc/config.yaml", true},
		{"ln -sfn ~/.defenseclaw/hooks hh && cp a.txt hh/", true},
		{"ln -s ~/.ssh sd; cp a.txt sd/authorized_keys", true},
		{"nohup ln -s ~/.ssh sd; cp a.txt sd/authorized_keys", true},
		{"ln -s HOMEDIR/.defenseclaw hc; rm hc/config.yaml", true},
		{"ln -s ~/.defenseclaw hc; ln -sf HOMEDIR/project/a.txt hc/config.yaml", true},
		{"ln -s ~/.defenseclaw/config.yaml cfg-link", false},
		{"nohup ln -s ~/.defenseclaw/config.yaml cfg-link", false},
		{"sudo ln -sf ~/.defenseclaw/config.yaml cfg-link", false},
		{"ln -s ~/.defenseclaw/config.yaml c; rm c", false},
		{"ln -s ~/.defenseclaw hc; rm hc", false},
		{"ln -s ~/.defenseclaw hc; cat hc/config.yaml", false},
		{"ln -s ~/.defenseclaw hc; cp hc/config.yaml backup.yaml", false},
		{"nohup ln -s ~/.defenseclaw hc; ls hc/", false},
		{"ln -s HOMEDIR/project/src s; cp a.txt s/x.txt", false},
		{"ln -sf $(pwd)/a.txt ~/.local/bin/tool", false},
		{"nohup ln -sf $(pwd)/a.txt ~/.local/bin/tool", false},
	})
}

// env -C behind an assignment word, a flock FILE -c STRING and an env -C
// call before a later wrapped state write were read as nothing (checker
// pod4 Q03, R06, R01, R26, GAP-2519).
func TestAssignedEnvChdirAndFlockStringWriteWhatThePlainCallWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"A=1 env -C / cp HOMEDIR/project/a.txt ~/.defenseclaw/config.yaml", true},
		{"A=1 env -C / cp HOMEDIR/project/a.txt HOMEDIR/.defenseclaw/config.yaml", true},
		{"A=1 B=2 env -C HOMEDIR cp project/a.txt .defenseclaw/config.yaml", true},
		{"A=1 env -C / cp a.txt b.txt; nohup cp a.txt ~/.defenseclaw/config.yaml", true},
		{`flock /tmp/zzl -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`flock -w 5 /tmp/zzl -c "cp a.txt ~/.defenseclaw/hooks/x.sh"`, true},
		{`flock /tmp/zzl --command "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{"A=1 env -C / cp a.txt b.txt", false},
		{"A=1 env -C /tmp cp HOMEDIR/project/a.txt .defenseclaw/config.yaml", false},
		{`flock /tmp/zzl -c "make --version"`, false},
		{`flock /tmp/zzl -c "cp a.txt b.txt"`, false},
	})
}

// A named runner (setsid, flock FILE, stdbuf, ionice, caffeinate, doas,
// env -C) before sh -c STRING runs the shell with the argv the caller
// expanded, so the line writes what sh -c STRING writes (GAP-2519); and a
// wrapper with options before a writer with an extra word that may expand
// to nothing writes what the plain call writes (GAP-2477).
func TestRunnersBeforeAShellStringWriteWhatTheStringWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{`setsid sh -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`setsid -f bash -c "cp a.txt ~/.defenseclaw/hooks/x.sh"`, true},
		{`flock /tmp/zzl sh -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`flock -n /tmp/zzl bash -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`stdbuf -o0 bash -lc "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`ionice -c3 sh -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`caffeinate -i sh -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`doas -u root sh -c "cp a.txt HOMEDIR/.defenseclaw/config.yaml"`, true},
		{`env -C HOMEDIR sh -c "cp project/a.txt .defenseclaw/config.yaml"`, true},
		{`A=1 setsid nice -n 5 sh -c "tee ~/.defenseclaw/config.yaml < a.txt"`, true},
		{"$(true) cp a.txt ~/.defenseclaw/config.yaml", true},
		{"sudo -u root cp a.txt ~/.defenseclaw/config.yaml $(true)", true},
		{"env -i cp a.txt ~/.defenseclaw/config.yaml $(true)", true},
		{"command -p cp a.txt ~/.defenseclaw/config.yaml $(true)", true},
		{"nohup cp a.txt ~/.defenseclaw/config.yaml $(true)", true},
		{`setsid sh -c "npm --version"`, false},
		{`flock /tmp/zzl sh -c "make --version"`, false},
		{`flock /tmp/zzl bash -c "cp a.txt b.txt"`, false},
		{`stdbuf -oL bash -c "tee build.log < a.txt"`, false},
		{`env -C /tmp sh -c "cp HOMEDIR/project/a.txt .defenseclaw/config.yaml"`, false},
		{"sudo -u root cp a.txt b.txt $(true)", false},
		{"env -i cp a.txt b.txt $(true)", false},
	})
}

func TestShellOptionsBeforeTheStringWriteWhatTheStringWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{`sh -c -- "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`sh -c - "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`bash --norc -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`bash --noprofile -c "cp a.txt ~/.defenseclaw/hooks/x.sh"`, true},
		{`bash --login -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`bash --posix -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`bash -euo pipefail -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`bash -c -x "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`bash --rcfile /dev/null -c "tee ~/.defenseclaw/config.yaml < a.txt"`, true},
		{`setsid bash --norc -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`setsid sh -c -- "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`A=1 bash --noprofile --norc -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`env -C HOMEDIR bash --norc -c "cp project/a.txt .defenseclaw/config.yaml"`, true},
		{`bash --norc -c "make --version"`, false},
		{`sh -c -- "cp a.txt b.txt"`, false},
		{`bash -euo pipefail -c "npm --version"`, false},
		{`bash --login -c "cat ~/.defenseclaw/config.yaml"`, false},
		{`bash -- script.sh`, false},
		{`bash -n --norc -c "cp a.txt ~/.defenseclaw/config.yaml"`, false},
		{`bash -o noexec -c -- "cp a.txt ~/.defenseclaw/config.yaml"`, false},
		// +n and +o noexec turn noexec off, and the last setting wins.
		{`bash +n -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`dash +n -c "cp a.txt ~/.defenseclaw/hooks/x.sh"`, true},
		{`setsid bash +n -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`bash -n +n -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`setsid bash +o noexec -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`setsid bash -o noexec +o noexec -c "cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`bash +n -n -c "cp a.txt ~/.defenseclaw/config.yaml"`, false},
		{`setsid bash +o noexec -o noexec -c "cp a.txt ~/.defenseclaw/config.yaml"`, false},
		{`bash +n -c "make --version"`, false},
	})
}

func TestRunnersInsideAShellStringWriteWhatTheyWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{`sh -c "setsid sh -c 'cp a.txt ~/.defenseclaw/config.yaml'"`, true},
		{`setsid sh -c "setsid sh -c 'cp a.txt ~/.defenseclaw/hooks/x.sh'"`, true},
		{`bash -c "nohup bash --norc -c 'cp a.txt ~/.defenseclaw/config.yaml'"`, true},
		{`sh -c "flock /tmp/l -c 'cp a.txt ~/.defenseclaw/config.yaml'"`, true},
		{`sh -c "nohup cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`flock /tmp/l -c "setsid cp a.txt ~/.defenseclaw/config.yaml"`, true},
		{`sh -c "sh -c 'sh -c \"setsid cp a.txt ~/.defenseclaw/config.yaml\"'"`, true},
		{`sh -c "setsid sh -c 'cp a.txt b.txt'"`, false},
		{`sh -c "setsid sh -c 'make build'"`, false},
		{`sh -c "nohup cat a.txt"`, false},
		{`bash -c "nohup bash --norc -c 'cat ~/.defenseclaw/config.yaml'"`, false},
	})
}

func TestBareCopyReadsAsNoWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	judgeHomeStateWriteRows(t, []homeStateWriteRow{
		{"cp", false},
		{"ls; cp", false},
		{`sh -c "cp"`, false},
		{"cp; cp a.txt ~/.defenseclaw/config.yaml", true},
		{"cp a.txt ~/.defenseclaw/config.yaml; cp", true},
	})
}
