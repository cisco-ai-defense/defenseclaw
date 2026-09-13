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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestToolValueLineageSQLRowsetObservedPythonShape(t *testing.T) {
	t.Parallel()
	key := toolValueLineageTestKey(0xa1)
	const (
		password = "Fixture-Pass_Alpha123!"
		access   = "fixture_access_Alpha123"
		refresh  = "fixture_refresh_Beta456"
	)

	credentials, ok := toolValueLineageSQLRowsetDigests(
		key,
		actionfacts.SensitiveSQLTableCredentials,
		[]byte("[{'id': 1, 'service': 'fixture', 'username': 'robot', 'password': '"+
			password+"'}, {'id': 2, 'service': 'empty', 'username': None, 'password': ''}]"),
	)
	if !ok || len(credentials) != 1 {
		t.Fatalf("credential projection = (%d, %t), want (1, true)", len(credentials), ok)
	}

	oauth, ok := toolValueLineageSQLRowsetDigests(
		key,
		actionfacts.SensitiveSQLTableOAuthTokens,
		[]byte("[{'id': 1, 'provider': 'fixture', 'access_token': '"+access+
			"', 'refresh_token': '"+refresh+
			"', 'expires': '2099-01-01', 'user_id': None}]"),
	)
	if !ok || len(oauth) != 2 {
		t.Fatalf("OAuth projection = (%d, %t), want (2, true)", len(oauth), ok)
	}

	ssns, ok := toolValueLineageSQLRowsetDigests(
		key,
		actionfacts.SensitiveSQLTableEmployees,
		[]byte("[{'id': 1, 'name': 'Synthetic Person', 'ssn': '482-37-9156', 'salary': 95000.0}, {'id': 2, 'name': 'Other Person', 'ssn': '731-58-2064', 'salary': -1}]"),
	)
	if !ok || len(ssns) != 2 {
		t.Fatalf("SSN projection = (%d, %t), want (2, true)", len(ssns), ok)
	}
}

func TestToolValueLineageSQLRowsetStrictJSONArray(t *testing.T) {
	t.Parallel()
	key := toolValueLineageTestKey(0xa2)
	const value = "fixture_access_Alpha123"
	digests, ok := toolValueLineageSQLRowsetDigests(
		key,
		actionfacts.SensitiveSQLTableOAuthTokens,
		[]byte(`[{"id":1,"provider":"fixture","access_token":"`+value+`","active":true}]`),
	)
	if !ok || len(digests) != 1 {
		t.Fatalf("JSON projection = (%d, %t), want (1, true)", len(digests), ok)
	}
	want := toolValueLineageMustSourceDigest(
		t,
		key,
		toolValueLineageSourceSingleToken,
		value,
	)
	if !toolValueLineageContainsDigest(digests, want) {
		t.Fatal("JSON SQL result did not preserve exact token identity")
	}
}

func TestToolValueLineageStructuredPersistenceCrossFormatJoins(t *testing.T) {
	t.Parallel()
	key := toolValueLineageTestKey(0xa3)
	const (
		password = "Fixture-Pass_Alpha123!"
		ssn      = "482-37-9156"
	)
	passwordSource, ok := toolValueLineageSQLRowsetDigests(
		key,
		actionfacts.SensitiveSQLTableCredentials,
		[]byte("[{'password': '"+password+"'}]"),
	)
	if !ok || len(passwordSource) != 1 {
		t.Fatalf("password source = (%d, %t)", len(passwordSource), ok)
	}
	ssnSource, ok := toolValueLineageSQLRowsetDigests(
		key,
		actionfacts.SensitiveSQLTableEmployees,
		[]byte("[{'ssn': '"+ssn+"'}]"),
	)
	if !ok || len(ssnSource) != 1 {
		t.Fatalf("SSN source = (%d, %t)", len(ssnSource), ok)
	}

	fileInput := actionfacts.Input{
		Tool: "write_file",
		Args: json.RawMessage(`{"path":"/synthetic/report.txt","content":"Credential snapshot: ` +
			password + `\nEmployee reference: ` + ssn + `"}`),
		ToolResourceIdentity: "mcp://filesystem/synthetic-workspace",
	}
	fileDigests, ok := toolValueLineageStructuredPersistenceDigests(key, fileInput)
	if !ok || !toolValueLineageContainsDigest(fileDigests, passwordSource[0]) ||
		!toolValueLineageContainsDigest(fileDigests, ssnSource[0]) {
		t.Fatal("write_file literals did not join both SQL source domains")
	}

	entityInput := actionfacts.Input{
		Tool: "create_entities",
		Args: json.RawMessage(`{"entities":[{"name":"synthetic report","entityType":"SyntheticReport","observations":["credential=` +
			password + `","employee_ssn=` + ssn + `"]}]}`),
		ToolResourceIdentity: "mcp://memory/synthetic-graph",
	}
	entityDigests, ok := toolValueLineageStructuredPersistenceDigests(key, entityInput)
	if !ok || !toolValueLineageContainsDigest(entityDigests, passwordSource[0]) ||
		!toolValueLineageContainsDigest(entityDigests, ssnSource[0]) {
		t.Fatal("create_entities literals did not join both SQL source domains")
	}
}

func TestToolValueLineageSQLRowsetRejectsMalformedAndAmbiguousInput(t *testing.T) {
	t.Parallel()
	key := toolValueLineageTestKey(0xa4)
	valid := []byte(`[{'password': 'Fixture-Pass_Alpha123!'}]`)
	tests := []struct {
		name  string
		table actionfacts.SensitiveSQLTableClass
		raw   []byte
	}{
		{name: "unknown table", table: "other", raw: valid},
		{name: "zero rows", table: actionfacts.SensitiveSQLTableCredentials, raw: []byte(`[]`)},
		{name: "object envelope", table: actionfacts.SensitiveSQLTableCredentials, raw: []byte(`{"password":"Fixture-Pass_Alpha123!"}`)},
		{name: "duplicate JSON key", table: actionfacts.SensitiveSQLTableCredentials, raw: []byte(`[{"password":"Fixture-Pass_Alpha123!","Password":"Fixture-Pass_Beta456!"}]`)},
		{name: "nested JSON", table: actionfacts.SensitiveSQLTableCredentials, raw: []byte(`[{"password":"Fixture-Pass_Alpha123!","meta":{"source":"fixture"}}]`)},
		{name: "Python escape", table: actionfacts.SensitiveSQLTableCredentials, raw: []byte(`[{"password": 'Fixture\\-Pass_Alpha123!'}]`)},
		{name: "Python trailing comma", table: actionfacts.SensitiveSQLTableCredentials, raw: []byte(`[{'password': 'Fixture-Pass_Alpha123!'},]`)},
		{name: "Python boolean", table: actionfacts.SensitiveSQLTableCredentials, raw: []byte(`[{'password': 'Fixture-Pass_Alpha123!', 'active': True}]`)},
		{name: "Python nested", table: actionfacts.SensitiveSQLTableCredentials, raw: []byte(`[{'password': 'Fixture-Pass_Alpha123!', 'meta': {'source': 'fixture'}}]`)},
		{name: "Python duplicate key", table: actionfacts.SensitiveSQLTableCredentials, raw: []byte(`[{'password': 'Fixture-Pass_Alpha123!', 'Password': 'Fixture-Pass_Beta456!'}]`)},
		{name: "dynamic value", table: actionfacts.SensitiveSQLTableCredentials, raw: []byte(`[{'password': '${FIXTURE_VALUE}'}]`)},
		{name: "short value", table: actionfacts.SensitiveSQLTableCredentials, raw: []byte(`[{'password': 'short'}]`)},
		{name: "wrong sensitive type", table: actionfacts.SensitiveSQLTableCredentials, raw: []byte(`[{'password': None}]`)},
		{name: "invalid SSN", table: actionfacts.SensitiveSQLTableEmployees, raw: []byte(`[{'ssn': '482-XX-XXXX'}]`)},
		{name: "zero SSN group", table: actionfacts.SensitiveSQLTableEmployees, raw: []byte(`[{'ssn': '000-37-9156'}]`)},
		{name: "oversized", table: actionfacts.SensitiveSQLTableCredentials, raw: []byte(strings.Repeat("x", toolValueLineageMaxInputBytes+1))},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if digests, ok := toolValueLineageSQLRowsetDigests(key, test.table, test.raw); ok || digests != nil {
				t.Fatalf("projection = (%v, %t), want (nil, false)", digests, ok)
			}
		})
	}
	if digests, ok := toolValueLineageSQLRowsetDigests(
		[toolValueLineageKeyBytes]byte{},
		actionfacts.SensitiveSQLTableCredentials,
		valid,
	); ok || digests != nil {
		t.Fatal("zero HMAC key was accepted")
	}
}

func TestToolValueLineageSQLRowsetRejectsExcessCardinality(t *testing.T) {
	t.Parallel()
	rows := make([]map[string]any, 0, toolValueLineageMaxTokens+1)
	for index := 0; index <= toolValueLineageMaxTokens; index++ {
		rows = append(rows, map[string]any{
			"password": "Fixture-Pass_Alpha" + string(rune('A'+index)) + "123!",
		})
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if digests, ok := toolValueLineageSQLRowsetDigests(
		toolValueLineageTestKey(0xa5),
		actionfacts.SensitiveSQLTableCredentials,
		raw,
	); ok || digests != nil {
		t.Fatal("excess sensitive-value cardinality was accepted")
	}
}

func TestToolValueLineageStructuredPersistenceRejectsUnprovenOrOpenInput(t *testing.T) {
	t.Parallel()
	key := toolValueLineageTestKey(0xa6)
	tests := []actionfacts.Input{
		{Tool: "write_file", Args: json.RawMessage(`{"path":"/synthetic/out","content":"Fixture-Pass_Alpha123!"}`)},
		{Tool: "write_file", Args: json.RawMessage(`{"path":"/synthetic/out","content":"ordinary prose without a candidate"}`), ToolResourceIdentity: "mcp://filesystem/synthetic"},
		{Tool: "write_file", Args: json.RawMessage(`{"path":"/synthetic/out","content":"${FIXTURE_VALUE}"}`), ToolResourceIdentity: "mcp://filesystem/synthetic"},
		{Tool: "write_file", Args: json.RawMessage(`{"path":"/synthetic/out","path":"/synthetic/other","content":"Fixture-Pass_Alpha123!"}`), ToolResourceIdentity: "mcp://filesystem/synthetic"},
		{Tool: "create_entities", Args: json.RawMessage(`{"entities":[{"name":"report","entityType":"SyntheticReport","observations":[{"text":"Fixture-Pass_Alpha123!"}]}]}`), ToolResourceIdentity: "mcp://memory/synthetic"},
		{Tool: "create_entities", Args: json.RawMessage(`{"entities":[{"name":"report","entityType":"SyntheticReport","observations":["{{FIXTURE_VALUE}}"]}]}`), ToolResourceIdentity: "mcp://memory/synthetic"},
		{Tool: "other", Args: json.RawMessage(`{"value":"Fixture-Pass_Alpha123!"}`), ToolResourceIdentity: "mcp://other/synthetic"},
		{
			Tool: "write_file",
			Args: mustSQLLineageJSON(t, map[string]any{
				"path":    "/synthetic/out",
				"content": strings.Repeat("Fixture-Pass_Alpha123!", toolValueLineageMaxInputBytes),
			}),
			ToolResourceIdentity: "mcp://filesystem/synthetic",
		},
	}
	for index, input := range tests {
		if digests, ok := toolValueLineageStructuredPersistenceDigests(key, input); ok || digests != nil {
			t.Fatalf("case %d projection = (%v, %t), want (nil, false)", index, digests, ok)
		}
	}
}

func TestToolValueLineageStructuredPersistenceRejectsExcessCandidates(t *testing.T) {
	t.Parallel()
	values := make([]string, 0, toolValueLineageMaxTokens+1)
	for index := 0; index <= toolValueLineageMaxTokens; index++ {
		values = append(values, "Fixture-Pass_Alpha"+string(rune('A'+index))+"123!")
	}
	input := actionfacts.Input{
		Tool: "write_file",
		Args: mustSQLLineageJSON(t, map[string]any{
			"path":    "/synthetic/out",
			"content": strings.Join(values, "\n"),
		}),
		ToolResourceIdentity: "mcp://filesystem/synthetic",
	}
	if digests, ok := toolValueLineageStructuredPersistenceDigests(
		toolValueLineageTestKey(0xa7),
		input,
	); ok || digests != nil {
		t.Fatal("excess sink candidate cardinality was accepted")
	}
}

func TestToolValueLineageSQLDigestsAreContentFreeAndDomainSeparated(t *testing.T) {
	t.Parallel()
	key := toolValueLineageTestKey(0xa8)
	const ssn = "482-37-9156"
	digests, ok := toolValueLineageSQLRowsetDigests(
		key,
		actionfacts.SensitiveSQLTableEmployees,
		[]byte("[{'ssn': '"+ssn+"'}]"),
	)
	if !ok || len(digests) != 1 {
		t.Fatalf("SSN projection = (%d, %t)", len(digests), ok)
	}
	if strings.Contains(hex.EncodeToString(digests[0][:]), ssn) {
		t.Fatal("digest exposed source text")
	}
	if global, globalOK := toolValueLineageDigestTokens(key, []string{ssn}); globalOK || global != nil {
		t.Fatal("global minimum token length was weakened for SSNs")
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(toolValueLineageDomain))
	_, _ = mac.Write([]byte{0})
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(ssn)))
	_, _ = mac.Write(length[:])
	_, _ = mac.Write([]byte(ssn))
	if hmac.Equal(digests[0][:], mac.Sum(nil)) {
		t.Fatal("SSN digest reused the global HMAC domain")
	}
}

func TestToolValueLineageSQLMCPHuntPublicResultFormats(t *testing.T) {
	root := os.Getenv("DEFENSECLAW_MCPHUNT_PUBLIC_DIR")
	if root == "" {
		t.Skip("set DEFENSECLAW_MCPHUNT_PUBLIC_DIR to validate public result_full formats")
	}
	files, err := filepath.Glob(filepath.Join(root, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("MCPHunt files = %d, err = %v", len(files), err)
	}

	key := toolValueLineageTestKey(0xa9)
	var exactReads, projected, emptyResults, nonRowsetResults, rejected int
	var exactSinks, projectedSinks, joinedTraces int
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			if typed["tool"] == "read_query" {
				args, argsOK := typed["args"].(map[string]any)
				result, resultOK := typed["result_full"].(string)
				if argsOK && resultOK {
					rawArgs, marshalErr := json.Marshal(args)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					facts := actionfacts.Analyze(actionfacts.Input{
						Tool: "read_query", Args: rawArgs,
						ToolResourceIdentity: "mcp://sqlite/public-format-validation",
					})
					reads := actionfacts.ExactSensitiveSQLRowsetReads(facts)
					if len(reads) == 1 {
						exactReads++
						switch {
						case result == "[]":
							emptyResults++
						case !strings.HasPrefix(result, "["):
							nonRowsetResults++
						default:
							if _, ok := toolValueLineageSQLRowsetDigests(key, reads[0].TableClass, []byte(result)); ok {
								projected++
							} else {
								rejected++
							}
						}
					}
				}
			}
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	for _, path := range files {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var document any
		if unmarshalErr := json.Unmarshal(raw, &document); unmarshalErr != nil {
			t.Fatal(unmarshalErr)
		}
		walk(document)
		sinks, projectedSinkCount, joins := toolValueLineageSQLPublicTraceCoverage(t, key, document)
		exactSinks += sinks
		projectedSinks += projectedSinkCount
		joinedTraces += joins
	}
	if exactReads == 0 || projected == 0 || rejected != 0 {
		t.Fatalf(
			"public formats: exact=%d projected=%d empty=%d non_rowset=%d rejected=%d",
			exactReads, projected, emptyResults, nonRowsetResults, rejected,
		)
	}
	t.Logf(
		"public formats: exact_reads=%d projected_reads=%d empty=%d non_rowset=%d rejected=%d exact_sinks=%d projected_sinks=%d joined_traces=%d",
		exactReads, projected, emptyResults, nonRowsetResults, rejected,
		exactSinks, projectedSinks, joinedTraces,
	)
}

func toolValueLineageSQLPublicTraceCoverage(
	t *testing.T,
	key [toolValueLineageKeyBytes]byte,
	document any,
) (int, int, int) {
	t.Helper()
	top, ok := document.(map[string]any)
	if !ok {
		t.Fatal("public corpus top level is not an object")
	}
	traces, ok := top["traces"].([]any)
	if !ok {
		t.Fatal("public corpus traces is not an array")
	}
	type sourceProjection struct {
		index   int
		digests []toolValueLineageDigest
	}
	var exactSinks, projectedSinks, joinedTraces int
	for _, rawTrace := range traces {
		trace, ok := rawTrace.(map[string]any)
		if !ok {
			t.Fatal("public trace is not an object")
		}
		events, ok := trace["events"].([]any)
		if !ok {
			continue
		}
		var sources []sourceProjection
		joined := false
		for index, rawEvent := range events {
			event, ok := rawEvent.(map[string]any)
			if !ok {
				continue
			}
			tool, toolOK := event["tool"].(string)
			args, argsOK := event["args"].(map[string]any)
			if !toolOK || !argsOK {
				continue
			}
			rawArgs, marshalErr := json.Marshal(args)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			input := actionfacts.Input{
				Tool: tool, Args: rawArgs,
				ToolResourceIdentity: "mcp://public-format/" + tool,
			}
			facts := actionfacts.Analyze(input)
			reads := actionfacts.ExactSensitiveSQLRowsetReads(facts)
			if len(reads) == 1 {
				result, resultOK := event["result_full"].(string)
				if resultOK {
					if digests, projectedOK := toolValueLineageSQLRowsetDigests(
						key,
						reads[0].TableClass,
						[]byte(result),
					); projectedOK {
						sources = append(sources, sourceProjection{index: index, digests: digests})
					}
				}
			}
			if len(actionfacts.ExactStructuredLiteralPersistences(facts)) == 0 {
				continue
			}
			exactSinks++
			sink, sinkOK := toolValueLineageStructuredPersistenceDigests(key, input)
			if !sinkOK {
				continue
			}
			projectedSinks++
			if joined {
				continue
			}
			for _, source := range sources {
				if index-source.index > 8 {
					continue
				}
				if toolValueLineageSQLDigestIntersection(source.digests, sink) {
					joined = true
					joinedTraces++
					break
				}
			}
		}
	}
	return exactSinks, projectedSinks, joinedTraces
}

func toolValueLineageSQLDigestIntersection(
	left []toolValueLineageDigest,
	right []toolValueLineageDigest,
) bool {
	for _, leftDigest := range left {
		if toolValueLineageContainsDigest(right, leftDigest) {
			return true
		}
	}
	return false
}

func mustSQLLineageJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
