// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
)

func TestHTTPSQLInjectionClosedTechniques(t *testing.T) {
	tests := []struct {
		name      string
		args      string
		technique HTTPSQLInjectionTechnique
	}{
		{
			name:      "quoted boolean tautology",
			args:      `{"method":"GET","url":"https://app.invalid/login?user=admin' OR '1'='1"}`,
			technique: HTTPSQLInjectionQuotedBooleanTautology,
		},
		{
			name:      "commented union select",
			args:      `{"method":"POST","url":"https://app.invalid/login","headers":{"Content-Type":"application/json"},"body":"{\"user\":\"' UNION SELECT username,password FROM users -- \"}"}`,
			technique: HTTPSQLInjectionUnionSelect,
		},
		{
			name:      "xp cmdshell",
			args:      `{"method":"POST","url":"https://app.invalid/run","headers":{"Content-Type":"application/json"},"body":"{\"command\":\"' OR 1=1; EXEC xp_cmdshell('whoami')--\"}"}`,
			technique: HTTPSQLInjectionXPCmdShell,
		},
		{
			name:      "into outfile",
			args:      `{"method":"POST","url":"https://app.invalid/export","body":"id=1 UNION SELECT 0x0011223344556677 INTO OUTFILE '/var/tmp/output.bin'"}`,
			technique: HTTPSQLInjectionIntoOutfile,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "http_request", Args: json.RawMessage(test.args)})
			matches := ExactHTTPSQLInjections(facts)
			if !facts.Authoritative() || len(matches) == 0 || !hasHTTPSQLTechnique(matches, test.technique) {
				t.Fatalf("status=%s techniques=%v", facts.Parse.Status, matches)
			}
		})
	}
}

func TestHTTPSQLInjectionRejectsOpenOrAmbiguousInputs(t *testing.T) {
	tests := []struct {
		name string
		tool string
		args string
	}{
		{name: "mere SQL words", tool: "http_request", args: `{"method":"POST","url":"https://app.invalid/search","headers":{"Content-Type":"application/json"},"body":"{\"query\":\"show UNION SELECT examples in documentation\"}"}`},
		{name: "ordinary query", tool: "http_request", args: `{"method":"GET","url":"https://app.invalid/search?q=select+help"}`},
		{name: "unknown argument field", tool: "http_request", args: `{"method":"GET","url":"https://app.invalid/login?user=admin' OR '1'='1","timeout":2}`},
		{name: "unknown header", tool: "http_request", args: `{"method":"GET","url":"https://app.invalid/login?user=admin' OR '1'='1","headers":{"X-Mode":"test"}}`},
		{name: "dynamic value", tool: "http_request", args: `{"method":"GET","url":"https://app.invalid/login?user=${payload}"}`},
		{name: "malformed URL", tool: "http_request", args: `{"method":"GET","url":"https:///login?user=admin' OR '1'='1"}`},
		{name: "encoded query", tool: "http_request", args: `{"method":"GET","url":"https://app.invalid/login?user=admin%2527%20OR%201%3D1"}`},
		{name: "GET body", tool: "http_request", args: `{"method":"GET","url":"https://app.invalid/login","body":"user=admin' OR '1'='1"}`},
		{name: "nested JSON body", tool: "http_request", args: `{"method":"POST","url":"https://app.invalid/login","headers":{"Content-Type":"application/json"},"body":"{\"user\":{\"value\":\"admin' OR '1'='1\"}}"}`},
		{name: "source text", tool: "write_file", args: `{"method":"GET","url":"https://app.invalid/login?user=admin' OR '1'='1"}`},
		{name: "uncommented union", tool: "http_request", args: `{"method":"GET","url":"https://app.invalid/search?q=' UNION SELECT username FROM users"}`},
		{name: "non tautology", tool: "http_request", args: `{"method":"GET","url":"https://app.invalid/login?user=admin' OR '1'='2"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: test.tool, Args: json.RawMessage(test.args)})
			if matches := ExactHTTPSQLInjections(facts); len(matches) != 0 {
				t.Fatalf("unexpected techniques=%v status=%s", matches, facts.Parse.Status)
			}
		})
	}
}

func TestHTTPSQLInjectionFactsDoNotSerializeRequestValues(t *testing.T) {
	const marker = "request-value-must-not-cross-boundary"
	facts := Analyze(Input{
		Tool: "http_request",
		Args: json.RawMessage(`{"method":"GET","url":"https://app.invalid/` + marker + `?user=admin' OR '1'='1"}`),
	})
	encoded, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || containsString(string(encoded), marker) {
		t.Fatalf("serialized facts retained request marker")
	}
}

func TestHTTPSQLInjectionPublicClosedProofCorpus(t *testing.T) {
	path := os.Getenv("DEFENSECLAW_HTTP_SQLI_CORPUS")
	if path == "" {
		t.Skip("set DEFENSECLAW_HTTP_SQLI_CORPUS to run the external public corpus check")
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
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 2*1024*1024)
	selected, matched := 0, 0
	for scanner.Scan() {
		var row corpusRow
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		if !containsExactString(row.Truth.Categories, "successful_http_sql_injection") {
			continue
		}
		selected++
		facts := Analyze(Input{Tool: row.Payload.ToolName, Args: row.Payload.Args})
		if facts.Authoritative() && len(ExactHTTPSQLInjections(facts)) != 0 {
			matched++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if selected != 31 || matched != selected {
		t.Fatalf("selected=%d matched=%d", selected, matched)
	}
}

func hasHTTPSQLTechnique(facts []HTTPSQLInjectionFact, technique HTTPSQLInjectionTechnique) bool {
	for _, fact := range facts {
		if fact.Technique == technique {
			return true
		}
	}
	return false
}

func containsExactString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsString(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
