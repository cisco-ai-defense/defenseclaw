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

package actionfacts

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const exactPythonCPUWorker = `
import sys
import math

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

num = 2
while True:
    is_prime(num)
    num += 1
`

const exactPythonCPUWorkerWithoutSys = `
import math

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

num = 2
while True:
    is_prime(num)
    num += 1
`

func TestExtractExactPOSIXUnboundedCPUFanout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		source  string
		workers uint64
	}{
		{
			name:    "minimum colon loop",
			source:  `for worker in $(seq 1 64); do (while true; do :; done) & done`,
			workers: 64,
		},
		{
			name: "multiline constant-success loop",
			source: `for slot in $(seq 1 104); do
  (
    while :; do
      true
    done
  ) &
done`,
			workers: 104,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fact, ok := ExtractExactPOSIXUnboundedCPUFanout(test.source)
			if !ok {
				t.Fatal("expected exact fanout proof")
			}
			if fact.FanoutCount != test.workers {
				t.Fatalf("fanout count = %d, want %d", fact.FanoutCount, test.workers)
			}
		})
	}
}

func TestExtractExactPOSIXUnboundedPythonCPUFanout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		source string
	}{
		{
			name: "literal python worker with status",
			source: `for i in $(seq 1 104); do python3 -c "` + exactPythonCPUWorker +
				`" & done; echo "Started 104 prime calculation processes"`,
		},
		{
			name: "cleanup and priority wrapper",
			source: `pkill -f "python3 -c.*is_prime" 2>/dev/null; sleep 1; ` +
				`for i in $(seq 1 104); do nice -n -20 python3 -c "` + exactPythonCPUWorker +
				`" & done; echo "Started 104 high-priority prime calculation processes"`,
		},
		{
			name: "priority wrapper and read only observation",
			source: `for i in $(seq 1 104); do nice -n -20 python3 -c "` +
				exactPythonCPUWorkerWithoutSys + `" & done; ` +
				`echo "Started 104 high-priority processes"; ` +
				`ps -eo pid,ni,cmd | grep python3 | grep -v grep | head -5`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fact, ok := ExtractExactPOSIXUnboundedCPUFanout(test.source)
			if !ok {
				t.Fatal("expected exact Python fanout proof")
			}
			if fact.FanoutCount != 104 {
				t.Fatalf("fanout count = %d, want 104", fact.FanoutCount)
			}
		})
	}
}

func TestExactPOSIXUnboundedPythonCPUFanoutFailsClosed(t *testing.T) {
	t.Parallel()
	plain := func(worker string) string {
		return `for slot in $(seq 1 104); do python3 -c "` + worker +
			`" & done; echo "started"`
	}
	wrapped := func(worker string) string {
		return `for slot in $(seq 1 104); do nice -n -20 python3 -c "` + worker +
			`" & done; echo "started"; ps -eo pid,ni,cmd | grep python3 | grep -v grep | head -5`
	}
	replace := func(old, new string) string {
		return strings.Replace(exactPythonCPUWorker, old, new, 1)
	}
	tests := []struct {
		name   string
		source string
	}{
		{name: "paced worker", source: plain(replace("    is_prime(num)\n", "    is_prime(num)\n    sleep(1)\n"))},
		{name: "sleep import", source: plain(strings.Replace(exactPythonCPUWorker, "import math", "import math\nimport time", 1))},
		{name: "blocking input", source: plain(replace("    is_prime(num)\n", "    input()\n"))},
		{name: "file io", source: plain(replace("    is_prime(num)\n", "    open(num)\n"))},
		{name: "network import", source: plain(strings.Replace(exactPythonCPUWorker, "import math", "import math\nimport socket", 1))},
		{name: "await", source: plain(replace("    is_prime(num)\n", "    await is_prime(num)\n"))},
		{name: "yield", source: plain(replace("    is_prime(num)\n", "    yield is_prime(num)\n"))},
		{name: "break", source: plain(replace("    num += 1\n", "    break\n"))},
		{name: "continue without progress", source: plain(replace("    num += 1\n", "    continue\n"))},
		{name: "eval", source: plain(replace("    is_prime(num)\n", "    eval(num)\n"))},
		{name: "exec", source: plain(replace("    is_prime(num)\n", "    exec(num)\n"))},
		{name: "dynamic import", source: plain(replace("    is_prime(num)\n", "    __import__(num)\n"))},
		{name: "exception exit", source: plain(replace("    is_prime(num)\n", "    raise RuntimeError()\n"))},
		{name: "try except", source: plain(replace("    is_prime(num)\n", "    try:\n        is_prime(num)\n    except Exception:\n        break\n"))},
		{name: "finite outer loop", source: plain(strings.Replace(exactPythonCPUWorker, "while True:", "for turn in range(104):", 1))},
		{name: "conditional outer loop", source: plain(strings.Replace(exactPythonCPUWorker, "while True:", "while num < 104:", 1))},
		{name: "missing progress", source: plain(replace("    num += 1\n", ""))},
		{name: "decrementing input", source: plain(replace("    num += 1\n", "    num += 0\n"))},
		{name: "different helper call", source: plain(replace("    is_prime(num)\n", "    other(num)\n"))},
		{name: "mutated helper", source: plain(strings.Replace(exactPythonCPUWorker, "math.sqrt(n)", "math.log(n)", 1))},
		{name: "shell parameter expansion", source: plain(replace("    is_prime(num)\n", "    is_prime($worker)\n"))},
		{name: "shell command substitution", source: plain(replace("    is_prime(num)\n", "    is_prime($(id))\n"))},
		{name: "low fanout", source: strings.Replace(plain(exactPythonCPUWorker), "seq 1 104", "seq 1 63", 1)},
		{name: "dynamic fanout", source: strings.Replace(plain(exactPythonCPUWorker), "seq 1 104", `seq 1 "$workers"`, 1)},
		{name: "foreground worker", source: strings.Replace(plain(exactPythonCPUWorker), `" & done`, `"; done`, 1)},
		{name: "conditional launch", source: `if true; then ` + plain(exactPythonCPUWorker) + `; fi`},
		{name: "timeout wrapper", source: strings.Replace(plain(exactPythonCPUWorker), "python3 -c", "timeout 10 python3 -c", 1)},
		{name: "unknown wrapper", source: strings.Replace(plain(exactPythonCPUWorker), "python3 -c", "taskset -c 0 python3 -c", 1)},
		{name: "reduced priority wrapper", source: strings.Replace(wrapped(exactPythonCPUWorker), "nice -n -20", "nice -n 19", 1)},
		{name: "post launch wait", source: plain(exactPythonCPUWorker) + `; wait`},
		{name: "post launch kill", source: plain(exactPythonCPUWorker) + `; pkill python3`},
		{name: "mutating observation", source: strings.Replace(wrapped(exactPythonCPUWorker), "head -5", "xargs kill", 1)},
		{name: "resource limit prefix", source: `ulimit -t 10; ` + plain(exactPythonCPUWorker)},
		{name: "cleanup mismatch", source: `pkill -f "python3 -c.*other" 2>/dev/null; sleep 1; ` +
			`for i in $(seq 1 104); do nice -n -20 python3 -c "` + exactPythonCPUWorker + `" & done; echo "started"`},
		{name: "conditional cleanup", source: `pkill -f "python3 -c.*is_prime" 2>/dev/null && sleep 1; ` +
			`for i in $(seq 1 104); do nice -n -20 python3 -c "` + exactPythonCPUWorker + `" & done; echo "started"`},
		{name: "paced persistent worker candidate", source: `for i in $(seq 1 104); do ` +
			`(echo "worker" && while true; do python3 -c "print(1)" && sleep 1; done) & done`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if fact, ok := ExtractExactPOSIXUnboundedCPUFanout(test.source); ok {
				t.Fatalf("unexpected Python fanout proof: %#v", fact)
			}
		})
	}
}

func TestExactPOSIXUnboundedCPUFanoutFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		source string
	}{
		{name: "finite loop", source: `for worker in $(seq 1 64); do (:; :) & done`},
		{name: "low fanout", source: `for worker in $(seq 1 63); do (while true; do :; done) & done`},
		{name: "make build", source: `make -j64`},
		{name: "ninja build", source: `ninja -j 64`},
		{name: "parallel build", source: `parallel -j64 compile ::: one two three`},
		{name: "sleeping loop", source: `for worker in $(seq 1 64); do (while true; do sleep 1; done) & done`},
		{name: "waiting loop", source: `for worker in $(seq 1 64); do (while true; do wait; done) & done`},
		{name: "pipe may block", source: `for worker in $(seq 1 64); do (while true; do printf x | sha256sum; done) & done`},
		{name: "timeout wrapper", source: `for worker in $(seq 1 64); do timeout 10 sh -c 'while true; do :; done' & done`},
		{name: "ulimit", source: `ulimit -t 10; for worker in $(seq 1 64); do (while true; do :; done) & done`},
		{name: "systemd cpu quota", source: `for worker in $(seq 1 64); do systemd-run -p CPUQuota=5% sh -c 'while true; do :; done' & done`},
		{name: "container cpu limit", source: `for worker in $(seq 1 64); do docker run --cpus=.1 busybox sh -c 'while true; do :; done' & done`},
		{name: "conditional fanout", source: `if true; then for worker in $(seq 1 64); do (while true; do :; done) & done; fi`},
		{name: "conditional worker", source: `for worker in $(seq 1 64); do true && (while true; do :; done) & done`},
		{name: "dynamic upper bound", source: `for worker in $(seq 1 "$workers"); do (while true; do :; done) & done`},
		{name: "arithmetic upper bound", source: `for worker in $(seq 1 "$((cores * 8))"); do (while true; do :; done) & done`},
		{name: "dynamic iterator", source: `for worker in $workers; do (while true; do :; done) & done`},
		{name: "eval", source: `eval 'for worker in $(seq 1 64); do (while true; do :; done) & done'`},
		{name: "bash brace expansion", source: `for worker in {1..64}; do (while true; do :; done) & done`},
		{name: "foreground worker", source: `for worker in $(seq 1 64); do (while true; do :; done); done`},
		{name: "background outer loop", source: `for worker in $(seq 1 64); do (while true; do :; done); done &`},
		{name: "until loop", source: `for worker in $(seq 1 64); do (until false; do :; done) & done`},
		{name: "loop condition has arguments", source: `for worker in $(seq 1 64); do (while true ignored; do :; done) & done`},
		{name: "redirected worker", source: `for worker in $(seq 1 64); do (while true; do :; done) >/dev/null & done`},
		{name: "extra statement", source: `for worker in $(seq 1 64); do (while true; do :; done) & done; echo started`},
		{name: "noncanonical seq", source: `for worker in $(seq 1 064); do (while true; do :; done) & done`},
		{name: "seq shorthand", source: `for worker in $(seq 64); do (while true; do :; done) & done`},
		{name: "seq stride", source: `for worker in $(seq 1 2 128); do (while true; do :; done) & done`},
		{name: "alternate generator", source: `for worker in $(printf 64); do (while true; do :; done) & done`},
		{name: "command substitution has extra command", source: `for worker in $(seq 1 64; echo 65); do (while true; do :; done) & done`},
		{name: "malformed quote", source: `for worker in $(seq 1 64); do (while true; do ':'; done) & done '`},
		{name: "malformed loop", source: `for worker in $(seq 1 64); do (while true; do :; done) &`},
		{name: "empty", source: ``},
		{name: "invalid utf8", source: string([]byte{0xff, 0xfe})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if fact, ok := ExtractExactPOSIXUnboundedCPUFanout(test.source); ok {
				t.Fatalf("unexpected proof: %#v", fact)
			}
		})
	}
}

func TestUnboundedCPUFanoutFactIsValueSafe(t *testing.T) {
	t.Parallel()
	typeOfFact := reflect.TypeOf(UnboundedCPUFanoutFact{})
	if typeOfFact.NumField() != 1 || typeOfFact.Field(0).Name != "FanoutCount" ||
		typeOfFact.Field(0).Type.Kind() != reflect.Uint64 {
		t.Fatalf("unexpected fact shape: %#v", typeOfFact)
	}

	source := `for secret_name in $(seq 1 64); do (while true; do :; done) & done`
	fact, ok := ExtractExactPOSIXUnboundedCPUFanout(source)
	if !ok {
		t.Fatal("expected exact fanout proof")
	}
	encoded, err := json.Marshal(fact)
	if err != nil {
		t.Fatalf("marshal fact: %v", err)
	}
	for _, forbidden := range []string{"secret_name", "while", "seq", "worker"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("serialized fact retained source-controlled value %q: %s", forbidden, encoded)
		}
	}
}

func FuzzExtractExactPOSIXUnboundedCPUFanout(f *testing.F) {
	for _, seed := range []string{
		`for worker in $(seq 1 64); do (while true; do :; done) & done`,
		`for worker in $(seq 1 104); do python3 -c "` + exactPythonCPUWorker +
			`" & done; echo "started"`,
		`for worker in $(seq 1 104); do (while true; do python3 -c "print(1)"; sleep 1; done) & done`,
		`for worker in $(seq 1 "$workers"); do (while true; do :; done) & done`,
		`make -j64`,
		`for`,
		"\xff",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		fact, ok := ExtractExactPOSIXUnboundedCPUFanout(source)
		if ok && fact.FanoutCount < MinimumExactPOSIXUnboundedCPUFanout {
			t.Fatalf("proof below conservative threshold: %#v", fact)
		}
	})
}
