// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This benchmark reads normalized agent-trace records. A trace can contain
// examples, tests, or actual attacks, so its is_attack label is not used as
// ground truth. The test reports detector hits for manual adjudication, not a
// measured false-positive rate. It never calls an LLM or executes trace tools.
type compactionHFRecord struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Surface   string `json:"surface"`
	Content   string `json:"content"`
	Dataset   string `json:"dataset"`
	Connector string `json:"connector"`
}

type compactionHFCounts struct {
	toolResults              int
	eligibleResults          int
	invalidSessions          int
	oversizedResults         int
	strictCandidateRecords   int
	genericCandidateRecords  int
	candidateSessions        int
	syntheticWarningEvents   int
	syntheticActionWarnings  int
	syntheticGenericWarnings int
}

type compactionHFSession struct {
	guard     compactionGuardStore
	candidate bool
}

// TestCompactionHFTraceCandidateBenchmark is opt-in because its normalized
// JSONL corpus is not checked into this worktree. Set
// DEFENSECLAW_HF_COMPACTION_CORPUS_DIR to the corpus directory and run this
// test with -v. Only tool_result records for Codex and Claude Code are scored.
// A synthetic PreCompact/PostCompact follows every positive tool result; that
// is an intentionally aggressive warning upper-bound proxy, not an observed
// compaction. Claude Code's actual summary-correlated warning rate cannot be
// measured without genuine compact_summary fields.
func TestCompactionHFTraceCandidateBenchmark(t *testing.T) {
	dir := strings.TrimSpace(os.Getenv("DEFENSECLAW_HF_COMPACTION_CORPUS_DIR"))
	if dir == "" {
		t.Skip("set DEFENSECLAW_HF_COMPACTION_CORPUS_DIR to a normalized JSONL corpus directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus directory: %v", err)
	}

	counts := map[string]*compactionHFCounts{
		"codex":      {},
		"claudecode": {},
		"total":      {},
	}
	sessions := make(map[string]*compactionHFSession)
	const sampleLimit = 64
	var positiveSamples []string
	positiveCount := 0
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".jsonl") {
			continue
		}
		if !entry.Type().IsRegular() {
			t.Fatalf("corpus JSONL entry %q is not a regular file", name)
		}
		files++
		path := filepath.Join(dir, name)
		file, err := os.Open(path)
		if err != nil {
			t.Fatalf("open corpus file %q: %v", name, err)
		}
		lineNumber := 0
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			lineNumber++
			line := scanner.Bytes()
			trimmed := strings.TrimSpace(string(line))
			if trimmed == "" || strings.HasPrefix(trimmed, "//") {
				continue
			}
			var record compactionHFRecord
			if err := json.Unmarshal(line, &record); err != nil {
				file.Close()
				t.Fatalf("parse %q line %d: %v", name, lineNumber, err)
			}
			if record.Surface != "tool_result" {
				continue
			}
			connector := strings.ToLower(strings.TrimSpace(record.Connector))
			connectorCounts := counts[connector]
			if connector != "codex" && connector != "claudecode" {
				continue
			}
			for _, c := range []*compactionHFCounts{connectorCounts, counts["total"]} {
				c.toolResults++
			}
			if strings.TrimSpace(record.SessionID) == "" || len(record.SessionID) > 256 {
				for _, c := range []*compactionHFCounts{connectorCounts, counts["total"]} {
					c.invalidSessions++
				}
				continue
			}
			for _, c := range []*compactionHFCounts{connectorCounts, counts["total"]} {
				c.eligibleResults++
				if len(record.Content) > compactionGuardMaxInput {
					c.oversizedResults++
				}
			}

			// Hash the source identity into a valid hook session ID. This keeps
			// independent datasets separate without retaining or logging their
			// raw session IDs. Each session owns a store so the live 256-session
			// process cache cannot evict earlier corpus sessions during replay.
			dataset := record.Dataset
			if dataset == "" {
				dataset = name
			}
			sessionHash := sha256.Sum256([]byte(dataset + "\x00" + connector + "\x00" + record.SessionID))
			sessionID := hex.EncodeToString(sessionHash[:])
			sessionKey := connector + "\x00" + sessionID
			session := sessions[sessionKey]
			if session == nil {
				session = &compactionHFSession{}
				sessions[sessionKey] = session
			}
			strict := session.guard.observeToolResult(connector, sessionID, record.Content)
			generic := session.guard.observeInstructionResult(connector, sessionID, record.Content)
			if !strict && !generic {
				continue
			}
			if !session.candidate {
				session.candidate = true
				for _, c := range []*compactionHFCounts{connectorCounts, counts["total"]} {
					c.candidateSessions++
				}
			}
			for _, c := range []*compactionHFCounts{connectorCounts, counts["total"]} {
				if strict {
					c.strictCandidateRecords++
				}
				if generic {
					c.genericCandidateRecords++
				}
			}
			positiveCount++
			if len(positiveSamples) < sampleLimit {
				id := record.ID
				if id == "" {
					id = fmt.Sprintf("%s:%d", name, lineNumber)
				}
				idHash := sha256.Sum256([]byte(id))
				kind := "generic"
				if strict {
					kind = "strict"
				}
				positiveSamples = append(positiveSamples, fmt.Sprintf("connector=%s kind=%s file=%s id_sha256_prefix=%x", connector, kind, name, idHash[:8]))
			}

			// This simulates the most warning-prone cadence: a compaction
			// immediately after each candidate-bearing result. The corpus does
			// not establish any real compaction, user approval, or summary.
			session.guard.preCompact(connector, sessionID)
			activation := session.guard.postCompact(connector, sessionID)
			for _, c := range []*compactionHFCounts{connectorCounts, counts["total"]} {
				if activation.actionWarn || activation.instructionWarn {
					c.syntheticWarningEvents++
				}
				if activation.actionWarn {
					c.syntheticActionWarnings++
				}
				if activation.instructionWarn {
					c.syntheticGenericWarnings++
				}
			}
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			t.Fatalf("scan %q line %d: %v", name, lineNumber, err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close %q: %v", name, err)
		}
	}
	if files == 0 {
		t.Fatalf("no .jsonl files in corpus directory %q", dir)
	}

	t.Logf("compaction HF trace benchmark: %d JSONL files; labels are not treated as ground truth", files)
	t.Log("synthetic warning events assume immediate compaction after every positive tool result; they are an upper-bound proxy, not observed warnings or a false-positive rate")
	t.Log("Claude Code summary-correlated warning and exact-action block rates are not measured by this corpus-only test")
	for _, connector := range []string{"codex", "claudecode", "total"} {
		c := counts[connector]
		t.Logf("%s: tool_results=%d eligible=%d invalid_session=%d oversized=%d strict_candidate_records=%d generic_candidate_records=%d candidate_sessions=%d synthetic_warning_events=%d (strict=%d generic=%d)",
			connector, c.toolResults, c.eligibleResults, c.invalidSessions, c.oversizedResults,
			c.strictCandidateRecords, c.genericCandidateRecords, c.candidateSessions,
			c.syntheticWarningEvents, c.syntheticActionWarnings, c.syntheticGenericWarnings)
	}
	for _, sample := range positiveSamples {
		t.Logf("positive: %s", sample)
	}
	if positiveCount > len(positiveSamples) {
		t.Logf("positive IDs omitted after first %d of %d; no trace content is logged", len(positiveSamples), positiveCount)
	}
}
