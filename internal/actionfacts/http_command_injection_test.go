// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPCommandInjectionClosedRequestSchemas(t *testing.T) {
	tests := []struct {
		name string
		args string
	}{
		{
			name: "structured query corpus shape",
			args: `{"body":{},"method":"GET","path":"/api/admin/ping","query":{"host":"localhost; id"}}`,
		},
		{
			name: "structured body corpus shape",
			args: `{"body":{"address":"123 Main St; id","product_id":1,"qty":1},"method":"POST","path":"/api/orders","query":{}}`,
		},
		{
			name: "structured body omitted",
			args: `{"method":"GET","path":"/api/admin/ping","query":{"host":"localhost; id"}}`,
		},
		{
			name: "URL query whoami",
			args: `{"method":"GET","url":"https://app.invalid/ping?host=localhost; whoami"}`,
		},
		{
			name: "URL JSON body whoami",
			args: `{"method":"POST","url":"https://app.invalid/ping","headers":{"Content-Type":"application/json"},"body":"{\"host\":\"localhost; whoami\"}"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "http_request", Args: json.RawMessage(test.args)})
			if !facts.Authoritative() || !ExactHTTPCommandInjection(facts) ||
				len(facts.HTTPCommandInjections) != 1 {
				t.Fatalf("status=%s issues=%v proof=%v", facts.Parse.Status, facts.Parse.Issues, facts.HTTPCommandInjections)
			}
		})
	}
}

func TestHTTPCommandInjectionReviewedLiteralControls(t *testing.T) {
	for _, value := range []string{
		"host;id",
		"host; whoami",
		"host && id",
		"host || whoami",
		"host | id",
	} {
		if !exactHTTPCommandInjectionValue(value) {
			t.Errorf("reviewed literal was rejected: %q", value)
		}
	}
}

func TestHTTPCommandInjectionRejectsAmbiguousInputs(t *testing.T) {
	oversized := strings.Repeat("a", maxScalarBytes) + "; id"
	tests := []struct {
		name string
		tool string
		args string
	}{
		{name: "direct proof command lacks control syntax", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":"id"}}`},
		{name: "unknown proof command", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":"localhost; uname"}}`},
		{name: "proof command arguments", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":"localhost; id -u"}}`},
		{name: "second shell control", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":"localhost; id; whoami"}}`},
		{name: "dynamic value", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":"${host}; id"}}`},
		{name: "interpolated command", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":"localhost; $(whoami)"}}`},
		{name: "percent encoded", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":"localhost%3B%20id"}}`},
		{name: "JSON unicode encoded", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":"localhost\u003b id"}}`},
		{name: "control character", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":"localhost;\nid"}}`},
		{name: "control character in prefix", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":"local\nhost; id"}}`},
		{name: "unknown request field", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":"localhost; id"},"timeout":1}`},
		{name: "unknown method", tool: "http_request", args: `{"method":"CONNECT","path":"/ping","query":{"host":"localhost; id"}}`},
		{name: "mixed URL and path schema", tool: "http_request", args: `{"method":"GET","url":"https://app.invalid/ping?host=localhost; id","path":"/ping","query":{}}`},
		{name: "nested query", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":{"value":"localhost; id"}}}`},
		{name: "nested body", tool: "http_request", args: `{"method":"POST","path":"/ping","query":{},"body":{"host":{"value":"localhost; id"}}}`},
		{name: "array body", tool: "http_request", args: `{"method":"POST","path":"/ping","query":{},"body":["localhost; id"]}`},
		{name: "duplicate query key", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":"safe","host":"localhost; id"}}`},
		{name: "encoded path", tool: "http_request", args: `{"method":"GET","path":"/api%2fping","query":{"host":"localhost; id"}}`},
		{name: "path value is not scanned", tool: "http_request", args: `{"method":"GET","path":"/localhost; id","query":{}}`},
		{name: "oversized scalar", tool: "http_request", args: `{"method":"GET","path":"/ping","query":{"host":` + mustJSONQuote(t, oversized) + `}}`},
		{name: "wrong tool", tool: "write_file", args: `{"method":"GET","path":"/ping","query":{"host":"localhost; id"}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: test.tool, Args: json.RawMessage(test.args)})
			if ExactHTTPCommandInjection(facts) || len(facts.HTTPCommandInjections) != 0 {
				t.Fatalf("unexpected proof=%v status=%s issues=%v", facts.HTTPCommandInjections, facts.Parse.Status, facts.Parse.Issues)
			}
		})
	}
}

func TestHTTPCommandInjectionFactDoesNotSerializeRequestValues(t *testing.T) {
	const marker = "request-value-must-not-cross-boundary"
	facts := Analyze(Input{
		Tool: "http_request",
		Args: json.RawMessage(`{"method":"GET","path":"/ping","query":{"host":"` + marker + `; id"}}`),
	})
	if !ExactHTTPCommandInjection(facts) {
		t.Fatal("expected exact private fact")
	}
	encoded, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), marker) || strings.Contains(string(encoded), "HTTPCommand") {
		t.Fatalf("serialized facts retained private HTTP command-injection data: %s", encoded)
	}
}

func TestHTTPCommandInjectionPublicClosedProofCorpus(t *testing.T) {
	path := os.Getenv("DEFENSECLAW_HTTP_COMMAND_INJECTION_CORPUS")
	if path == "" {
		t.Skip("set DEFENSECLAW_HTTP_COMMAND_INJECTION_CORPUS to run the external public corpus check")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	type corpusRow struct {
		Payload struct {
			ToolName string          `json:"tool_name"`
			Args     json.RawMessage `json:"args"`
		} `json:"payload"`
		Truth struct {
			Categories []string `json:"categories"`
		} `json:"truth"`
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	selected, matched := 0, 0
	for scanner.Scan() {
		var row corpusRow
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		if !containsExactString(row.Truth.Categories, "request_syntax_command_injection") {
			continue
		}
		selected++
		facts := Analyze(Input{Tool: row.Payload.ToolName, Args: row.Payload.Args})
		if facts.Authoritative() && ExactHTTPCommandInjection(facts) {
			matched++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if selected != 3 || matched != selected {
		t.Fatalf("selected=%d matched=%d", selected, matched)
	}
}

func TestHTTPCommandInjectionExternalBenignCorporaHaveNoProofs(t *testing.T) {
	rawPaths := os.Getenv("DEFENSECLAW_HTTP_COMMAND_INJECTION_BENIGN_CORPORA")
	if rawPaths == "" {
		t.Skip("set DEFENSECLAW_HTTP_COMMAND_INJECTION_BENIGN_CORPORA to run external benign-corpus checks")
	}
	type corpusRow struct {
		ID      string `json:"id"`
		Payload struct {
			ToolName string          `json:"tool_name"`
			Args     json.RawMessage `json:"args"`
		} `json:"payload"`
		Truth struct {
			DeterministicTruth string `json:"deterministic_truth"`
		} `json:"truth"`
	}
	benign := 0
	for _, path := range filepath.SplitList(rawPaths) {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
		for scanner.Scan() {
			var row corpusRow
			if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
				file.Close()
				t.Fatal(err)
			}
			if row.Truth.DeterministicTruth != "benign" {
				continue
			}
			benign++
			facts := Analyze(Input{Tool: row.Payload.ToolName, Args: row.Payload.Args})
			if facts.Authoritative() && ExactHTTPCommandInjection(facts) {
				file.Close()
				t.Fatalf("external benign case produced exact HTTP command-injection proof: %s", row.ID)
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
	if benign == 0 {
		t.Fatal("external corpora contained no deterministic benign cases")
	}
	t.Logf("checked %d deterministic benign cases", benign)
}

func mustJSONQuote(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
