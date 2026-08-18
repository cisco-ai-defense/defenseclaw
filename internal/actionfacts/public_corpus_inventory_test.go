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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

const (
	publicShellInventoryInputSchema  = "defenseclaw.public-shell-inventory.input.v1"
	publicShellInventoryOutputSchema = "defenseclaw.public-shell-inventory.output.v1"
	publicShellInventoryInputEnv     = "DEFENSECLAW_PUBLIC_SHELL_INVENTORY_INPUT"
	publicShellInventoryOutputEnv    = "DEFENSECLAW_PUBLIC_SHELL_INVENTORY_OUTPUT"
	publicShellInventoryMaxLineBytes = 1 << 20
	publicShellInventoryMaxRecords   = 250_000
	publicShellInventoryMaxIDBytes   = 128
	publicShellInventoryUnsafeName   = "<unsafe-name>"
	publicShellInventoryUnknown      = "<unknown>"
)

var (
	publicShellInventoryIdentifier = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._:+-]*$`,
	)
	publicShellInventoryProgram = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._+-]*$`,
	)
	publicShellInventoryOption = regexp.MustCompile(
		`^-{1,2}[A-Za-z0-9][A-Za-z0-9._+-]*$`,
	)
)

var publicShellInventoryEnvelopeFields = map[string]struct{}{
	"schema":        {},
	"id":            {},
	"source":        {},
	"privacy_class": {},
	"platform":      {},
	"tool":          {},
	"command":       {},
	"argv":          {},
}

var publicShellInventoryRequiredFields = [...]string{
	"schema",
	"id",
	"source",
	"privacy_class",
	"platform",
	"tool",
}

type publicShellInventoryEnvelope struct {
	Schema       string   `json:"schema"`
	ID           string   `json:"id"`
	Source       string   `json:"source"`
	PrivacyClass string   `json:"privacy_class"`
	Platform     string   `json:"platform"`
	Tool         string   `json:"tool"`
	Command      string   `json:"command"`
	Argv         []string `json:"argv"`

	hasCommand bool
	hasArgv    bool
}

// publicShellInventoryReport intentionally contains only a fixed schema and
// aggregate counters. Validated source identifiers and sanitized
// program/option buckets are map dimensions; record identifiers and all
// command material are discarded.
type publicShellInventoryReport struct {
	Schema           string                       `json:"schema"`
	Records          uint64                       `json:"records"`
	ParseStatuses    map[string]uint64            `json:"parse_statuses"`
	ParseIssues      map[string]uint64            `json:"parse_issues"`
	Dialects         map[string]uint64            `json:"dialects"`
	Programs         map[string]uint64            `json:"programs"`
	ProgramOptions   map[string]map[string]uint64 `json:"program_options"`
	ProgramsBySource map[string]map[string]uint64 `json:"programs_by_source"`
	Sources          map[string]uint64            `json:"sources"`
	Commands         uint64                       `json:"commands"`
	Pipelines        uint64                       `json:"pipelines"`
	PipelineCommands uint64                       `json:"pipeline_commands"`
	Wrappers         uint64                       `json:"wrappers"`
	Redirects        uint64                       `json:"redirects"`
	ArgvComplete     uint64                       `json:"argv_complete"`
	ArgvIncomplete   uint64                       `json:"argv_incomplete"`
}

// TestPublicShellCorpusInventory is an explicitly enabled, test-only corpus
// runner. It reads public Linux shell records, calls Analyze directly, and
// writes one aggregate-only JSON document. It never invokes a dispatcher,
// gateway, router, connector, network client, or command execution path.
func TestPublicShellCorpusInventory(t *testing.T) {
	inputPath, inputSet := os.LookupEnv(publicShellInventoryInputEnv)
	outputPath, outputSet := os.LookupEnv(publicShellInventoryOutputEnv)
	if !inputSet && !outputSet {
		t.Skip("public shell inventory paths are not configured")
	}
	if !inputSet || strings.TrimSpace(inputPath) == "" ||
		!outputSet || strings.TrimSpace(outputPath) == "" {
		t.Fatalf(
			"%s and %s must both be set",
			publicShellInventoryInputEnv,
			publicShellInventoryOutputEnv,
		)
	}

	if err := writePublicShellInventoryFile(inputPath, outputPath); err != nil {
		t.Fatal(err)
	}
}

func newPublicShellInventoryReport() publicShellInventoryReport {
	return publicShellInventoryReport{
		Schema:           publicShellInventoryOutputSchema,
		ParseStatuses:    make(map[string]uint64),
		ParseIssues:      make(map[string]uint64),
		Dialects:         make(map[string]uint64),
		Programs:         make(map[string]uint64),
		ProgramOptions:   make(map[string]map[string]uint64),
		ProgramsBySource: make(map[string]map[string]uint64),
		Sources:          make(map[string]uint64),
	}
}

func writePublicShellInventoryFile(inputPath, outputPath string) error {
	inputAbsolute, err := filepath.Abs(inputPath)
	if err != nil {
		return fmt.Errorf("resolve public shell inventory input")
	}
	outputAbsolute, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve public shell inventory output")
	}
	if filepath.Clean(inputAbsolute) == filepath.Clean(outputAbsolute) {
		return fmt.Errorf("public shell inventory input and output must differ")
	}

	input, err := os.Open(inputAbsolute)
	if err != nil {
		return fmt.Errorf("open public shell inventory input")
	}
	defer input.Close()
	inputInfo, err := input.Stat()
	if err != nil {
		return fmt.Errorf("stat public shell inventory input")
	}
	if outputInfo, statErr := os.Stat(outputAbsolute); statErr == nil {
		if os.SameFile(inputInfo, outputInfo) {
			return fmt.Errorf("public shell inventory input and output must differ")
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("stat public shell inventory output")
	}

	report, err := collectPublicShellInventory(input)
	if err != nil {
		return err
	}
	payload, err := encodePublicShellInventory(report)
	if err != nil {
		return err
	}

	temporary, err := os.CreateTemp(
		filepath.Dir(outputAbsolute),
		"."+filepath.Base(outputAbsolute)+".tmp-*",
	)
	if err != nil {
		return fmt.Errorf("create public shell inventory output")
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect public shell inventory output")
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write public shell inventory output")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync public shell inventory output")
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close public shell inventory output")
	}
	if err := os.Rename(temporaryName, outputAbsolute); err != nil {
		return fmt.Errorf("publish public shell inventory output")
	}
	committed = true
	return nil
}

func collectPublicShellInventory(input io.Reader) (publicShellInventoryReport, error) {
	return collectPublicShellInventoryWithLimits(
		input,
		publicShellInventoryMaxRecords,
		publicShellInventoryMaxLineBytes,
	)
}

func collectPublicShellInventoryWithLimits(
	input io.Reader,
	maxRecords int,
	maxLineBytes int,
) (publicShellInventoryReport, error) {
	report := newPublicShellInventoryReport()
	if input == nil || maxRecords <= 0 || maxLineBytes <= 0 {
		return report, fmt.Errorf("invalid public shell inventory limits")
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), maxLineBytes+1)
	seenIDs := make(map[string]struct{})
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if lineNumber > maxRecords {
			return report, fmt.Errorf("public shell inventory record limit exceeded")
		}
		line := scanner.Bytes()
		if len(line) > maxLineBytes {
			return report, fmt.Errorf(
				"public shell inventory line %d exceeds the byte limit",
				lineNumber,
			)
		}
		envelope, err := decodePublicShellInventoryEnvelope(line)
		if err != nil {
			return report, fmt.Errorf(
				"public shell inventory line %d: %w",
				lineNumber,
				err,
			)
		}
		if _, duplicate := seenIDs[envelope.ID]; duplicate {
			return report, fmt.Errorf(
				"public shell inventory line %d: duplicate id",
				lineNumber,
			)
		}
		seenIDs[envelope.ID] = struct{}{}

		facts := analyzePublicShellInventoryInput(envelope.actionFactsInput())
		report.add(envelope.Source, facts)
	}
	if err := scanner.Err(); err != nil {
		return report, fmt.Errorf(
			"read public shell inventory near line %d",
			lineNumber+1,
		)
	}
	return report, nil
}

func decodePublicShellInventoryEnvelope(
	line []byte,
) (publicShellInventoryEnvelope, error) {
	if len(line) == 0 || len(bytes.TrimSpace(line)) == 0 {
		return publicShellInventoryEnvelope{}, fmt.Errorf("empty JSONL record")
	}
	if len(line) > publicShellInventoryMaxLineBytes {
		return publicShellInventoryEnvelope{}, fmt.Errorf("JSONL record exceeds the byte limit")
	}
	if !utf8.Valid(line) {
		return publicShellInventoryEnvelope{}, fmt.Errorf("JSONL record is not valid UTF-8")
	}
	if issue := validateJSONWithStringLimit(line, maxCommandBytes); issue != "" {
		return publicShellInventoryEnvelope{}, fmt.Errorf("invalid inventory envelope")
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil || fields == nil {
		return publicShellInventoryEnvelope{}, fmt.Errorf("inventory envelope must be an object")
	}
	for field := range fields {
		if _, allowed := publicShellInventoryEnvelopeFields[field]; !allowed {
			return publicShellInventoryEnvelope{}, fmt.Errorf("unknown inventory envelope field")
		}
	}
	for _, required := range publicShellInventoryRequiredFields {
		if _, present := fields[required]; !present {
			return publicShellInventoryEnvelope{}, fmt.Errorf("missing inventory envelope field")
		}
	}
	_, hasCommand := fields["command"]
	_, hasArgv := fields["argv"]
	if hasCommand == hasArgv {
		return publicShellInventoryEnvelope{}, fmt.Errorf("exactly one action representation is required")
	}
	if len(fields) != len(publicShellInventoryRequiredFields)+1 {
		return publicShellInventoryEnvelope{}, fmt.Errorf("invalid inventory envelope fields")
	}

	var envelope publicShellInventoryEnvelope
	if err := json.Unmarshal(line, &envelope); err != nil {
		return publicShellInventoryEnvelope{}, fmt.Errorf("invalid inventory envelope values")
	}
	envelope.hasCommand = hasCommand
	envelope.hasArgv = hasArgv

	if envelope.Schema != publicShellInventoryInputSchema {
		return publicShellInventoryEnvelope{}, fmt.Errorf("unsupported or missing inventory schema")
	}
	if envelope.PrivacyClass != "public_untrusted" {
		return publicShellInventoryEnvelope{}, fmt.Errorf("invalid inventory privacy class")
	}
	if envelope.Platform != "linux" {
		return publicShellInventoryEnvelope{}, fmt.Errorf("invalid inventory platform")
	}
	if !validPublicShellInventoryIdentifier(envelope.ID) ||
		!validPublicShellInventoryIdentifier(envelope.Source) ||
		!validPublicShellInventoryIdentifier(envelope.Tool) ||
		validateToolName(envelope.Tool) != "" {
		return publicShellInventoryEnvelope{}, fmt.Errorf("invalid inventory identifier")
	}
	// Action material that is structurally valid JSON but invalid shell input
	// belongs in the benchmark. Analyze classifies those records as invalid or
	// limit-exceeded; rejecting them here would erase the parser's denominator.
	// The envelope validator still enforces UTF-8, duplicate-key, depth, member,
	// line, and per-string byte bounds before this point.
	if envelope.hasArgv && !publicShellInventoryArgvWithinLimits(envelope.Argv) {
		return publicShellInventoryEnvelope{}, fmt.Errorf("invalid inventory argv")
	}
	return envelope, nil
}

func publicShellInventoryArgvWithinLimits(argv []string) bool {
	if len(argv) == 0 || len(argv) > maxArgvItems {
		return false
	}
	total := 0
	for _, argument := range argv {
		if !utf8.ValidString(argument) || len(argument) > maxScalarBytes {
			return false
		}
		total += len(argument)
		if total > maxArgvBytes {
			return false
		}
	}
	return true
}

func validPublicShellInventoryIdentifier(value string) bool {
	return len(value) > 0 &&
		len(value) <= publicShellInventoryMaxIDBytes &&
		publicShellInventoryIdentifier.MatchString(value)
}

func (envelope publicShellInventoryEnvelope) actionFactsInput() Input {
	input := Input{
		Tool: envelope.Tool,
	}
	if envelope.hasCommand {
		input.Command = envelope.Command
		input.DialectHint = DialectPOSIX
	} else {
		input.Argv = append([]string(nil), envelope.Argv...)
		input.DialectHint = DialectArgv
	}
	return input
}

// analyzePublicShellInventoryInput is intentionally a one-call boundary. The
// corpus runner has no dispatcher abstraction and invokes ActionFacts only.
func analyzePublicShellInventoryInput(input Input) Facts {
	return Analyze(input)
}

func (report *publicShellInventoryReport) add(source string, facts Facts) {
	report.Records++
	report.Sources[source]++
	if _, present := report.ProgramsBySource[source]; !present {
		report.ProgramsBySource[source] = make(map[string]uint64)
	}
	report.ParseStatuses[publicShellInventoryStatusBucket(facts.Parse.Status)]++
	report.Dialects[publicShellInventoryDialectBucket(facts.Parse.Dialect)]++
	for _, issue := range facts.Parse.Issues {
		report.ParseIssues[publicShellInventoryIssueBucket(issue)]++
	}

	pipelines := make(map[int64]struct{})
	for _, command := range facts.Commands {
		report.Commands++
		if command.PipelineID > 0 {
			report.PipelineCommands++
			pipelines[command.PipelineID] = struct{}{}
		}
		report.Wrappers += uint64(len(command.Wrappers))
		report.Redirects += uint64(len(command.Redirects))
		if command.Kind != CommandKindProcess {
			continue
		}
		if command.ArgvComplete {
			report.ArgvComplete++
		} else {
			report.ArgvIncomplete++
		}

		program := publicShellInventoryProgramBucket(command.Program)
		report.Programs[program]++
		report.ProgramsBySource[source][program]++
		if !command.ArgvComplete || len(command.Argv) <= 1 {
			continue
		}
		for _, argument := range command.Argv[1:] {
			option, ok := publicShellInventoryOptionBucket(argument)
			if !ok {
				continue
			}
			if _, present := report.ProgramOptions[program]; !present {
				report.ProgramOptions[program] = make(map[string]uint64)
			}
			report.ProgramOptions[program][option]++
		}
	}
	report.Pipelines += uint64(len(pipelines))
}

func publicShellInventoryProgramBucket(program string) string {
	if len(program) == 0 || len(program) > maxScalarBytes ||
		!publicShellInventoryProgram.MatchString(program) {
		return publicShellInventoryUnsafeName
	}
	return program
}

func publicShellInventoryOptionBucket(argument string) (string, bool) {
	option, _, _ := strings.Cut(argument, "=")
	if !publicShellInventoryOption.MatchString(option) {
		return "", false
	}
	return option, true
}

func publicShellInventoryStatusBucket(status ParseStatus) string {
	switch status {
	case StatusNotApplicable,
		StatusComplete,
		StatusPartial,
		StatusUnsupported,
		StatusInvalid,
		StatusLimitExceeded,
		StatusAmbiguous:
		return string(status)
	default:
		return publicShellInventoryUnknown
	}
}

func publicShellInventoryDialectBucket(dialect Dialect) string {
	switch dialect {
	case DialectNone,
		DialectArgv,
		DialectPOSIX,
		DialectPowerShell,
		DialectCMD,
		DialectMixed:
		return string(dialect)
	default:
		return publicShellInventoryUnknown
	}
}

func publicShellInventoryIssueBucket(issue IssueCode) string {
	switch issue {
	case IssueInvalidJSON,
		IssueInvalidUTF8,
		IssueInvalidSyntax,
		IssueDynamicWord,
		IssueUnsupportedConstruct,
		IssueOpaqueArtifact,
		IssueUnknownOperandGrammar,
		IssueConflictingSources,
		IssueInputLimit,
		IssueNodeLimit,
		IssueDepthLimit,
		IssueFactLimit,
		IssueWrapperLimit,
		IssueDuplicateJSONKey,
		IssueInternalParserFailure:
		return string(issue)
	default:
		return publicShellInventoryUnknown
	}
}

func encodePublicShellInventory(report publicShellInventoryReport) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return nil, fmt.Errorf("encode public shell inventory output")
	}
	return output.Bytes(), nil
}

func TestPublicShellInventoryNoExecutionAndRedaction(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "must-not-exist-private-canary")
	secret := "private-option-value-7a912"
	line := mustPublicShellInventoryLine(t, map[string]any{
		"schema":        publicShellInventoryInputSchema,
		"id":            "no-execution-001",
		"source":        "public-test",
		"privacy_class": "public_untrusted",
		"platform":      "linux",
		"tool":          "shell",
		"command":       "touch --marker=" + secret + " " + canary,
	})

	report, err := collectPublicShellInventory(bytes.NewReader(line))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(canary); !os.IsNotExist(err) {
		t.Fatal("inventory analysis executed the proposed command")
	}
	payload, err := encodePublicShellInventory(report)
	if err != nil {
		t.Fatal(err)
	}
	for index, forbidden := range []string{
		canary,
		filepath.Base(canary),
		secret,
		"--marker=" + secret,
	} {
		if bytes.Contains(payload, []byte(forbidden)) {
			t.Fatalf("aggregate output contains forbidden command material at check %d", index)
		}
	}
	if report.Records != 1 || report.Programs["touch"] != 1 ||
		report.ProgramOptions["touch"]["--marker"] != 1 {
		t.Fatalf("unexpected aggregate report: %+v", report)
	}
}

func TestPublicShellInventoryDynamicProgramHasNoOptionSlicePanic(t *testing.T) {
	line := mustPublicShellInventoryLine(t, map[string]any{
		"schema":        publicShellInventoryInputSchema,
		"id":            "dynamic-program-001",
		"source":        "public-test",
		"privacy_class": "public_untrusted",
		"platform":      "linux",
		"tool":          "shell",
		"command":       `${PROGRAM} --secret=must-not-appear`,
	})

	report, err := collectPublicShellInventory(bytes.NewReader(line))
	if err != nil {
		t.Fatal(err)
	}
	if report.Records != 1 || report.Commands != 1 || report.ArgvIncomplete != 1 {
		t.Fatalf("unexpected dynamic-command aggregate: %+v", report)
	}
	if len(report.ProgramOptions) != 0 {
		t.Fatalf("dynamic argv contributed option counts: %+v", report.ProgramOptions)
	}
	payload, err := encodePublicShellInventory(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("must-not-appear")) {
		t.Fatal("dynamic option value leaked into aggregate output")
	}
}

func TestPublicShellInventoryRetainsInvalidActionForParserDenominator(t *testing.T) {
	line := mustPublicShellInventoryLine(t, map[string]any{
		"schema":        publicShellInventoryInputSchema,
		"id":            "invalid-action-001",
		"source":        "public-test",
		"privacy_class": "public_untrusted",
		"platform":      "linux",
		"tool":          "shell",
		"command":       "\u0001",
	})

	report, err := collectPublicShellInventory(bytes.NewReader(line))
	if err != nil {
		t.Fatal(err)
	}
	if report.Records != 1 || report.ParseStatuses[string(StatusInvalid)] != 1 ||
		report.ParseIssues[string(IssueInvalidSyntax)] != 1 {
		t.Fatalf("invalid action did not reach ActionFacts: %+v", report)
	}
	payload, err := encodePublicShellInventory(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("\\u0001")) {
		t.Fatal("invalid action material leaked into aggregate output")
	}
}

func TestPublicShellInventoryStrictValidation(t *testing.T) {
	validCommand := `{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-001","source":"linuxarena","privacy_class":"public_untrusted","platform":"linux","tool":"bash","command":"true"}`
	validArgv := `{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-002","source":"trace-commons","privacy_class":"public_untrusted","platform":"linux","tool":"shell","argv":["true"]}`
	for _, line := range []string{validCommand, validArgv} {
		if _, err := decodePublicShellInventoryEnvelope([]byte(line)); err != nil {
			t.Fatalf("valid envelope rejected: %v", err)
		}
	}

	tests := []struct {
		name string
		line []byte
	}{
		{
			name: "duplicate key",
			line: []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-001","source":"linuxarena","privacy_class":"public_untrusted","platform":"linux","tool":"bash","command":"true"}`),
		},
		{
			name: "unknown field",
			line: []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-001","source":"linuxarena","privacy_class":"public_untrusted","platform":"linux","tool":"bash","command":"true","extra":false}`),
		},
		{
			name: "both representations",
			line: []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-001","source":"linuxarena","privacy_class":"public_untrusted","platform":"linux","tool":"bash","command":"true","argv":["true"]}`),
		},
		{
			name: "missing representation",
			line: []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-001","source":"linuxarena","privacy_class":"public_untrusted","platform":"linux","tool":"bash"}`),
		},
		{
			name: "private input",
			line: []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-001","source":"linuxarena","privacy_class":"local_private","platform":"linux","tool":"bash","command":"true"}`),
		},
		{
			name: "non Linux input",
			line: []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-001","source":"linuxarena","privacy_class":"public_untrusted","platform":"darwin","tool":"bash","command":"true"}`),
		},
		{
			name: "unsafe id",
			line: []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"../case","source":"linuxarena","privacy_class":"public_untrusted","platform":"linux","tool":"bash","command":"true"}`),
		},
		{
			name: "unsafe source",
			line: []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-001","source":"private/source","privacy_class":"public_untrusted","platform":"linux","tool":"bash","command":"true"}`),
		},
		{
			name: "unsafe tool",
			line: []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-001","source":"linuxarena","privacy_class":"public_untrusted","platform":"linux","tool":"bash shell","command":"true"}`),
		},
		{
			name: "empty argv",
			line: []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-001","source":"linuxarena","privacy_class":"public_untrusted","platform":"linux","tool":"bash","argv":[]}`),
		},
		{
			name: "NaN",
			line: []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-001","source":"linuxarena","privacy_class":"public_untrusted","platform":"linux","tool":"bash","command":NaN}`),
		},
		{
			name: "positive infinity",
			line: []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-001","source":"linuxarena","privacy_class":"public_untrusted","platform":"linux","tool":"bash","command":Infinity}`),
		},
		{
			name: "negative infinity",
			line: []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"case-001","source":"linuxarena","privacy_class":"public_untrusted","platform":"linux","tool":"bash","command":-Infinity}`),
		},
		{
			name: "malformed UTF-8",
			line: append([]byte(`{"schema":"`), 0xff, '}'),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodePublicShellInventoryEnvelope(test.line); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}

	oversizedCommand := mustPublicShellInventoryLine(t, map[string]any{
		"schema":        publicShellInventoryInputSchema,
		"id":            "oversized-command",
		"source":        "linuxarena",
		"privacy_class": "public_untrusted",
		"platform":      "linux",
		"tool":          "bash",
		"command":       strings.Repeat("x", maxCommandBytes+1),
	})
	if _, err := decodePublicShellInventoryEnvelope(bytes.TrimSpace(oversizedCommand)); err == nil {
		t.Fatal("oversized command accepted")
	}
	oversizedArgument := mustPublicShellInventoryLine(t, map[string]any{
		"schema":        publicShellInventoryInputSchema,
		"id":            "oversized-argument",
		"source":        "linuxarena",
		"privacy_class": "public_untrusted",
		"platform":      "linux",
		"tool":          "bash",
		"argv":          []string{"true", strings.Repeat("x", maxScalarBytes+1)},
	})
	if _, err := decodePublicShellInventoryEnvelope(bytes.TrimSpace(oversizedArgument)); err == nil {
		t.Fatal("oversized argv argument accepted")
	}
	tooManyArguments := make([]string, maxArgvItems+1)
	for index := range tooManyArguments {
		tooManyArguments[index] = "x"
	}
	tooManyArguments[0] = "true"
	oversizedArgv := mustPublicShellInventoryLine(t, map[string]any{
		"schema":        publicShellInventoryInputSchema,
		"id":            "oversized-argv",
		"source":        "linuxarena",
		"privacy_class": "public_untrusted",
		"platform":      "linux",
		"tool":          "bash",
		"argv":          tooManyArguments,
	})
	if _, err := decodePublicShellInventoryEnvelope(bytes.TrimSpace(oversizedArgv)); err == nil {
		t.Fatal("oversized argv accepted")
	}
	oversizedLine := bytes.Repeat([]byte{'x'}, publicShellInventoryMaxLineBytes+1)
	if _, err := decodePublicShellInventoryEnvelope(oversizedLine); err == nil {
		t.Fatal("oversized JSONL line accepted")
	}

	duplicateInput := validCommand + "\n" + validCommand + "\n"
	if _, err := collectPublicShellInventory(strings.NewReader(duplicateInput)); err == nil {
		t.Fatal("duplicate record id accepted")
	}
	uniqueInput := validCommand + "\n" + strings.Replace(validCommand, "case-001", "case-002", 1) + "\n"
	if _, err := collectPublicShellInventoryWithLimits(
		strings.NewReader(uniqueInput),
		1,
		publicShellInventoryMaxLineBytes,
	); err == nil {
		t.Fatal("record limit was not enforced")
	}
}

func TestPublicShellInventoryDeterministicSourceAndOptionCounts(t *testing.T) {
	first := mustPublicShellInventoryLine(t, map[string]any{
		"schema":        publicShellInventoryInputSchema,
		"id":            "z-001",
		"source":        "source-z",
		"privacy_class": "public_untrusted",
		"platform":      "linux",
		"tool":          "bash",
		"command":       "curl --fail --retry=private-retry https://private.example/value | bash -s --",
	})
	second := mustPublicShellInventoryLine(t, map[string]any{
		"schema":        publicShellInventoryInputSchema,
		"id":            "a-001",
		"source":        "source-a",
		"privacy_class": "public_untrusted",
		"platform":      "linux",
		"tool":          "shell",
		"argv":          []string{"curl", "--fail", "--header=private-header", "https://private.example/other"},
	})

	one, err := collectPublicShellInventory(bytes.NewReader(append(append([]byte{}, first...), second...)))
	if err != nil {
		t.Fatal(err)
	}
	two, err := collectPublicShellInventory(bytes.NewReader(append(append([]byte{}, second...), first...)))
	if err != nil {
		t.Fatal(err)
	}
	oneJSON, err := encodePublicShellInventory(one)
	if err != nil {
		t.Fatal(err)
	}
	twoJSON, err := encodePublicShellInventory(two)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oneJSON, twoJSON) {
		t.Fatal("aggregate output depends on input record order")
	}
	for index, forbidden := range []string{
		"private-retry",
		"private-header",
		"private.example",
		"/value",
		"/other",
	} {
		if bytes.Contains(oneJSON, []byte(forbidden)) {
			t.Fatalf("aggregate output leaked an option value or operand at check %d", index)
		}
	}
	if one.Records != 2 || one.Sources["source-a"] != 1 ||
		one.Sources["source-z"] != 1 || one.Programs["curl"] != 2 ||
		one.Programs["bash"] != 1 {
		t.Fatalf("unexpected global counts: %+v", one)
	}
	if one.ProgramsBySource["source-a"]["curl"] != 1 ||
		one.ProgramsBySource["source-z"]["curl"] != 1 ||
		one.ProgramsBySource["source-z"]["bash"] != 1 {
		t.Fatalf("unexpected per-source program counts: %+v", one.ProgramsBySource)
	}
	if one.ProgramOptions["curl"]["--fail"] != 2 ||
		one.ProgramOptions["curl"]["--retry"] != 1 ||
		one.ProgramOptions["curl"]["--header"] != 1 ||
		one.ProgramOptions["bash"]["-s"] != 1 {
		t.Fatalf("unexpected option counts: %+v", one.ProgramOptions)
	}
	if bytes.Index(oneJSON, []byte(`"source-a"`)) >
		bytes.Index(oneJSON, []byte(`"source-z"`)) {
		t.Fatal("source map keys are not deterministically ordered")
	}
}

func TestPublicShellInventoryUnsafeProgramBucket(t *testing.T) {
	line := mustPublicShellInventoryLine(t, map[string]any{
		"schema":        publicShellInventoryInputSchema,
		"id":            "unsafe-program-001",
		"source":        "source-a",
		"privacy_class": "public_untrusted",
		"platform":      "linux",
		"tool":          "shell",
		"argv":          []string{"bad$name", "--safe=private-value", "private-operand"},
	})
	report, err := collectPublicShellInventory(bytes.NewReader(line))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodePublicShellInventory(report)
	if err != nil {
		t.Fatal(err)
	}
	if report.Programs[publicShellInventoryUnsafeName] != 1 ||
		report.ProgramsBySource["source-a"][publicShellInventoryUnsafeName] != 1 ||
		report.ProgramOptions[publicShellInventoryUnsafeName]["--safe"] != 1 {
		t.Fatalf("unsafe program was not bucketed: %+v", report)
	}
	for index, forbidden := range []string{"bad$name", "private-value", "private-operand"} {
		if bytes.Contains(payload, []byte(forbidden)) {
			t.Fatalf("unsafe program aggregate leaked input at check %d", index)
		}
	}
}

func TestPublicShellInventoryAtomicModeAndSingleDocument(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "input.jsonl")
	outputPath := filepath.Join(directory, "output.json")
	line := mustPublicShellInventoryLine(t, map[string]any{
		"schema":        publicShellInventoryInputSchema,
		"id":            "atomic-001",
		"source":        "source-a",
		"privacy_class": "public_untrusted",
		"platform":      "linux",
		"tool":          "shell",
		"argv":          []string{"true"},
	})
	if err := os.WriteFile(inputPath, line, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writePublicShellInventoryFile(inputPath, outputPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode = %o, want 600", info.Mode().Perm())
	}
	payload, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var report publicShellInventoryReport
	if err := decoder.Decode(&report); err != nil {
		t.Fatalf("decode aggregate output: %v", err)
	}
	if report.Schema != publicShellInventoryOutputSchema || report.Records != 1 {
		t.Fatalf("unexpected aggregate identity: schema=%q records=%d", report.Schema, report.Records)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatal("aggregate output contains more than one JSON document")
	}
}

func TestPublicShellInventoryCallsAnalyzeDirectly(t *testing.T) {
	input := Input{
		Tool:        "shell",
		Argv:        []string{"printf", "%s", "private-value"},
		DialectHint: DialectArgv,
	}
	got := analyzePublicShellInventoryInput(input)
	want := Analyze(input)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inventory analyzer differs from direct ActionFacts analysis")
	}
}

func mustPublicShellInventoryLine(t *testing.T, value map[string]any) []byte {
	t.Helper()
	line, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(line, '\n')
}
