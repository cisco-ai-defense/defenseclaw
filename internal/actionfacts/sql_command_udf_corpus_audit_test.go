// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSQLCommandUDFCorpusAudit(t *testing.T) {
	corpus := os.Getenv("BENCHMARK_SQL_UDF_AUDIT_CORPUS")
	if corpus == "" {
		t.Skip("set BENCHMARK_SQL_UDF_AUDIT_CORPUS")
	}
	file, err := os.Open(corpus)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	type event struct {
		ToolName string          `json:"tool_name"`
		Args     json.RawMessage `json:"args"`
		Outcome  string          `json:"outcome"`
	}
	type record struct {
		ID      string `json:"id"`
		Payload struct {
			Events []event `json:"events"`
		} `json:"payload"`
	}
	type projection struct {
		index      int
		operation  SQLCommandUDFOperation
		engine     string
		connection string
		function   string
	}
	trajectories := 0
	pairs := 0
	atomicCreates := 0
	atomicInvokes := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		var row record
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		projections := make([]projection, 0, len(row.Payload.Events))
		for index, item := range row.Payload.Events {
			facts := Analyze(Input{Tool: item.ToolName, Args: item.Args})
			operation, engine, connection, function, ok := ExactSQLCommandUDFOperation(facts)
			if !ok {
				continue
			}
			if operation == SQLCommandUDFCreate {
				atomicCreates++
			} else {
				atomicInvokes++
			}
			projections = append(projections, projection{index, operation, engine, connection, function})
		}
		rowPairs := 0
		for _, create := range projections {
			if create.operation != SQLCommandUDFCreate {
				continue
			}
			for _, invoke := range projections {
				if invoke.operation == SQLCommandUDFInvoke && invoke.index > create.index &&
					invoke.index-create.index <= 8 && invoke.engine == create.engine &&
					invoke.connection == create.connection && invoke.function == create.function {
					rowPairs++
					t.Logf("pair id=%s create=%d invoke=%d engine=%s outcomes=unknown", row.ID, create.index, invoke.index, create.engine)
				}
			}
		}
		if rowPairs > 0 {
			trajectories++
			pairs += rowPairs
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("summary trajectories=%d pairs=%d atomic_creates=%d atomic_invokes=%d", trajectories, pairs, atomicCreates, atomicInvokes)
}

func TestSQLCommandUDFCollisionAudit(t *testing.T) {
	pattern := os.Getenv("BENCHMARK_SQL_UDF_COLLISION_GLOB")
	if pattern == "" {
		t.Skip("set BENCHMARK_SQL_UDF_COLLISION_GLOB")
	}
	paths, err := filepath.Glob(pattern)
	if err != nil || len(paths) == 0 {
		t.Fatalf("glob=%q paths=%d err=%v", pattern, len(paths), err)
	}
	type event struct {
		ToolName string          `json:"tool_name"`
		Command  string          `json:"command"`
		Argv     []string        `json:"argv"`
		Args     json.RawMessage `json:"args"`
		Dialect  string          `json:"dialect"`
		CWD      string          `json:"cwd"`
	}
	type record struct {
		ID      string `json:"id"`
		Surface string `json:"surface"`
		Truth   struct {
			SourceTruth string `json:"source_truth"`
		} `json:"truth"`
		Payload struct {
			ToolName string          `json:"tool_name"`
			Command  string          `json:"command"`
			Argv     []string        `json:"argv"`
			Args     json.RawMessage `json:"args"`
			Dialect  string          `json:"dialect"`
			CWD      string          `json:"cwd"`
			Events   []event         `json:"events"`
		} `json:"payload"`
	}
	rows := 0
	benignRows := 0
	evaluated := 0
	matches := 0
	benignMatches := 0
	for _, corpus := range paths {
		file, err := os.Open(corpus)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			var row record
			if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
				file.Close()
				t.Fatal(err)
			}
			rows++
			if row.Truth.SourceTruth == "benign" {
				benignRows++
			}
			inputs := []Input{{
				Tool: row.Payload.ToolName, Args: row.Payload.Args,
				Command: row.Payload.Command, Argv: row.Payload.Argv,
				CWD: row.Payload.CWD, DialectHint: Dialect(row.Payload.Dialect),
			}}
			if row.Surface == "stateful" {
				inputs = inputs[:0]
				for _, item := range row.Payload.Events {
					inputs = append(inputs, Input{
						Tool: item.ToolName, Args: item.Args, Command: item.Command,
						Argv: item.Argv, CWD: item.CWD, DialectHint: Dialect(item.Dialect),
					})
				}
			}
			for _, input := range inputs {
				if input.Tool == "" && len(input.Args) == 0 && input.Command == "" && len(input.Argv) == 0 {
					continue
				}
				evaluated++
				operation, _, _, _, ok := ExactSQLCommandUDFOperation(Analyze(input))
				if !ok || operation != SQLCommandUDFCreate {
					continue
				}
				matches++
				if row.Truth.SourceTruth == "benign" {
					benignMatches++
				}
				t.Logf("collision-audit match id=%s truth=%s", row.ID, row.Truth.SourceTruth)
			}
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("collision summary files=%d rows=%d benign_rows=%d evaluated_actions=%d create_matches=%d benign_matches=%d",
		len(paths), rows, benignRows, evaluated, matches, benignMatches)
}
