// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestInspectStdinScriptCostBenchmark is the timing guard of GAP-1088: the
// inspect of a call that hands a script to a shell on its standard input
// (a here-string or a heredoc), read by id from the actionfacts corpus, next
// to a call of the same corpus that does not. After the stdin script reading
// (rel-1-0-10:GAP-0980) these calls cost about 4x the rest of the corpus and
// under -race sat 15 ms from the 200 ms inspect scan deadline of
// TestDefenseClawControlFiveTiers.
//
// It prints ns/op and never fails on time (a time bound is flaky); it runs
// only with DC_INSPECT_BENCH=1:
//
//	DC_INSPECT_BENCH=1 go test -run ^TestInspectStdinScriptCostBenchmark$ -v ./internal/gateway
func TestInspectStdinScriptCostBenchmark(t *testing.T) {
	if os.Getenv("DC_INSPECT_BENCH") != "1" {
		t.Skip("set DC_INSPECT_BENCH=1 to time the inspect of the stdin script rows")
	}
	file, err := os.Open("../actionfacts/testdata/defenseclaw_control.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	commands := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var r struct{ ID, Command string }
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		commands[r.ID] = r.Command
	}
	a := gap0437Server(t, gap0437Packs[0], "openclaw", "action")
	workdir := t.TempDir()
	warmDefenseClawControl(t, a.handleInspectTool, "/api/v1/inspect/tool", map[string]any{
		"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": "ls", "workdir": workdir},
	})
	// g596r2-k160 is a here-string script, g596b-t20 a heredoc script, and
	// g596b-t21 a call of the same corpus with no stdin script (the baseline).
	ids := []string{"g596r2-k160", "g596b-t20", "g596b-t21"}
	if only := os.Getenv("DC_INSPECT_BENCH_ROWS"); only != "" {
		ids = strings.Split(only, ",")
	}
	for _, id := range ids {
		command, ok := commands[id]
		if !ok {
			t.Fatalf("corpus row %s is missing", id)
		}
		result := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				gap0437Inspect(t, a, workdir, command)
			}
		})
		t.Logf("%s: %d ns/op over %d runs", id, result.NsPerOp(), result.N)
	}
}
