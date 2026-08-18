// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	publicASRProjectionInputEnv  = "DEFENSECLAW_PUBLIC_ASR_PROJECTION_INPUT"
	publicASRProjectionOutputEnv = "DEFENSECLAW_PUBLIC_ASR_PROJECTION_OUTPUT_FIFO"

	publicASRProjectionOutputSchema  = "defenseclaw.public-asr-projection.output.v1"
	publicASRProjectionTrailerSchema = "defenseclaw.public-asr-projection.trailer.v1"
)

type publicASRProjectionTrailer struct {
	Schema       string `json:"schema"`
	Records      int    `json:"records"`
	StreamSHA256 string `json:"stream_sha256"`
}

// publicASRProjectionRecord is deliberately a test-only, value-bearing
// handoff for records that are already public and export-authorized. It must
// never be used for private sessions, telemetry, or production enforcement.
// It carries no Facts graph beyond the parse result and process-node ASR
// projection needed to create public semantic-label inputs.
type publicASRProjectionRecord struct {
	Schema          string                    `json:"schema"`
	EventID         string                    `json:"event_id"`
	SourceFamilyID  string                    `json:"source_family_id"`
	PrivacyClass    string                    `json:"privacy_class"`
	Representation  string                    `json:"representation"`
	Command         *string                   `json:"command"`
	Argv            []string                  `json:"argv"`
	PayloadDigest   string                    `json:"payload_digest"`
	ParseStatus     ParseStatus               `json:"parse_status"`
	ParseIssueCodes []IssueCode               `json:"parse_issue_codes"`
	ProcessNodes    []publicASRProjectionNode `json:"process_nodes"`
}

// publicASRProjectionNode retains exactly the raw public argv supplied to the
// parser and bounded, value-free projection metadata. A node is included for
// every ActionFacts process command, including non-projectable candidates.
type publicASRProjectionNode struct {
	CommandID              int64               `json:"command_id"`
	Program                string              `json:"program"`
	Surface                ASRCommandSurface   `json:"surface"`
	Argv                   []string            `json:"argv"`
	ArgvComplete           bool                `json:"argv_complete"`
	Eligible               bool                `json:"eligible"`
	CandidateAuthoritative bool                `json:"candidate_authoritative"`
	ProjectionReason       ASRProjectionReason `json:"projection_reason"`
}

// TestPublicASRProjectionStream is an explicitly enabled, test-only public
// corpus runner. It processes inert JSONL envelopes exclusively through
// Analyze and ProjectASRCommandNodes. It has no dispatch, connector, router,
// process, network, or command-execution path. Value-bearing output is
// permitted only to a pre-existing, owner-only FIFO so it cannot accidentally
// become a durable artifact in the worktree.
func TestPublicASRProjectionStream(t *testing.T) {
	inputPath, inputSet := os.LookupEnv(publicASRProjectionInputEnv)
	outputPath, outputSet := os.LookupEnv(publicASRProjectionOutputEnv)
	if !inputSet && !outputSet {
		t.Skip("public ASR projection paths are not configured")
	}
	if !inputSet || strings.TrimSpace(inputPath) == "" ||
		!outputSet || strings.TrimSpace(outputPath) == "" {
		t.Fatalf(
			"%s and %s must both be set",
			publicASRProjectionInputEnv,
			publicASRProjectionOutputEnv,
		)
	}
	if err := writePublicASRProjectionFIFO(inputPath, outputPath); err != nil {
		t.Fatal(err)
	}
}

// writePublicASRProjectionFIFO opens a verified public input shard and an
// already-existing FIFO. It never creates, truncates, renames, or publishes a
// value-bearing file. Opening the FIFO for writing intentionally requires the
// caller to have already attached a private collector.
func writePublicASRProjectionFIFO(inputPath, outputPath string) error {
	input, err := openPublicASRProjectionInput(inputPath)
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := openPublicASRProjectionFIFO(outputPath)
	if err != nil {
		return err
	}
	defer output.Close()

	return streamPublicASRProjections(input, output)
}

func openPublicASRProjectionInput(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat public ASR projection input")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("public ASR projection input must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open public ASR projection input")
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("public ASR projection input changed while opening")
	}
	return file, nil
}

func openPublicASRProjectionFIFO(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat public ASR projection output FIFO")
	}
	if info.Mode()&os.ModeSymlink != 0 ||
		info.Mode()&os.ModeNamedPipe == 0 ||
		info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("public ASR projection output must be a pre-existing mode-0600 FIFO")
	}

	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open public ASR projection output FIFO")
	}
	opened, err := file.Stat()
	if err != nil || opened.Mode()&os.ModeNamedPipe == 0 ||
		opened.Mode().Perm() != 0o600 || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("public ASR projection output FIFO changed while opening")
	}
	return file, nil
}

// streamPublicASRProjections is intentionally kept independent from the
// environment/file boundary so unit tests can prove inert handling without a
// filesystem writer. It accepts only the public inventory envelope decoder,
// whose privacy_class and platform validation rejects private and non-Linux
// records before ActionFacts sees their action representation.
func streamPublicASRProjections(input io.Reader, output io.Writer) error {
	if input == nil || output == nil {
		return fmt.Errorf("public ASR projection input and output are required")
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), publicShellInventoryMaxLineBytes+1)
	seenIDs := make(map[string]struct{})
	streamDigest := sha256.New()
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if lineNumber > publicShellInventoryMaxRecords {
			return fmt.Errorf("public ASR projection record limit exceeded")
		}
		line := scanner.Bytes()
		if len(line) > publicShellInventoryMaxLineBytes {
			return fmt.Errorf("public ASR projection line %d exceeds the byte limit", lineNumber)
		}
		envelope, err := decodePublicShellInventoryEnvelope(line)
		if err != nil {
			return fmt.Errorf("public ASR projection line %d: invalid inventory envelope", lineNumber)
		}
		if _, duplicate := seenIDs[envelope.ID]; duplicate {
			return fmt.Errorf("public ASR projection line %d: duplicate id", lineNumber)
		}
		seenIDs[envelope.ID] = struct{}{}

		record, err := projectPublicASREnvelope(envelope)
		if err != nil {
			return fmt.Errorf("public ASR projection line %d: projection failed", lineNumber)
		}
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(record); err != nil {
			return fmt.Errorf("encode public ASR projection record")
		}
		if _, err := output.Write(encoded.Bytes()); err != nil {
			return fmt.Errorf("write public ASR projection record")
		}
		if _, err := streamDigest.Write(encoded.Bytes()); err != nil {
			return fmt.Errorf("hash public ASR projection record")
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read public ASR projection near line %d", lineNumber+1)
	}
	trailer := publicASRProjectionTrailer{
		Schema:       publicASRProjectionTrailerSchema,
		Records:      lineNumber,
		StreamSHA256: hex.EncodeToString(streamDigest.Sum(nil)),
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(trailer); err != nil {
		return fmt.Errorf("write public ASR projection trailer")
	}
	return nil
}

func projectPublicASREnvelope(
	envelope publicShellInventoryEnvelope,
) (publicASRProjectionRecord, error) {
	payloadDigest, err := publicASRProjectionPayloadSHA256(envelope)
	if err != nil {
		return publicASRProjectionRecord{}, err
	}

	provenance := ASRCommandProvenanceActionFactsStaticPOSIX
	if envelope.hasArgv {
		provenance = ASRCommandProvenanceStructuredArgv
	}
	facts := analyzePublicShellInventoryInput(envelope.actionFactsInput())
	projection := ProjectASRCommandNodes(facts, ASRProjectionContext{
		Platform:   ASRPlatformLinux,
		Profile:    ASRProfileUniversalLinux,
		Provenance: provenance,
	})
	if !projection.ContextValid || projection.Reason != ASRProjectionReasonReady {
		return publicASRProjectionRecord{}, fmt.Errorf("invalid fixed projection context")
	}

	candidates := make(map[int64]ASRCommandCandidate, len(projection.Candidates))
	for _, candidate := range projection.Candidates {
		if _, duplicate := candidates[candidate.CommandID]; duplicate {
			return publicASRProjectionRecord{}, fmt.Errorf("duplicate projected command id")
		}
		candidates[candidate.CommandID] = candidate
	}

	record := publicASRProjectionRecord{
		Schema:         publicASRProjectionOutputSchema,
		EventID:        envelope.ID,
		SourceFamilyID: envelope.Source,
		PrivacyClass:   envelope.PrivacyClass,
		Command:        nil,
		Argv:           nil,
		PayloadDigest:  payloadDigest,
		ParseStatus:    facts.Parse.Status,
		ParseIssueCodes: append(
			make([]IssueCode, 0, len(facts.Parse.Issues)),
			facts.Parse.Issues...,
		),
		ProcessNodes: make([]publicASRProjectionNode, 0),
	}
	if envelope.hasCommand {
		command := envelope.Command
		record.Command = &command
		record.Representation = "command"
	} else {
		record.Argv = append([]string(nil), envelope.Argv...)
		record.Representation = "argv"
	}
	sort.Slice(record.ParseIssueCodes, func(i, j int) bool {
		return record.ParseIssueCodes[i] < record.ParseIssueCodes[j]
	})

	for _, command := range facts.Commands {
		if command.Kind != CommandKindProcess {
			continue
		}
		candidate, present := candidates[command.ID]
		if !present {
			return publicASRProjectionRecord{}, fmt.Errorf("missing projected process command")
		}
		record.ProcessNodes = append(record.ProcessNodes, publicASRProjectionNode{
			CommandID: command.ID,
			Program:   command.Program,
			Surface:   candidate.Surface,
			Argv: append(
				make([]string, 0, len(command.Argv)),
				command.Argv...,
			),
			ArgvComplete:           command.ArgvComplete,
			Eligible:               candidate.Projectable,
			CandidateAuthoritative: candidate.Authoritative,
			ProjectionReason:       candidate.Reason,
		})
	}
	return record, nil
}

// publicASRProjectionPayloadSHA256 implements the public replay identity
// contract: SHA-256 over canonical JSON with exactly command and argv keys,
// sorted lexically, compact separators, and unescaped UTF-8.
func publicASRProjectionPayloadSHA256(
	envelope publicShellInventoryEnvelope,
) (string, error) {
	var command any
	var argv any
	if envelope.hasCommand {
		command = envelope.Command
	} else if envelope.hasArgv {
		argv = envelope.Argv
	} else {
		return "", fmt.Errorf("missing action representation")
	}

	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(map[string]any{
		"argv":    argv,
		"command": command,
	}); err != nil {
		return "", fmt.Errorf("encode canonical public payload")
	}
	canonical := bytes.TrimSuffix(payload.Bytes(), []byte{'\n'})
	// encoding/json always escapes the two JavaScript line separators even
	// when HTML escaping is disabled. The cross-language identity contract is
	// UTF-8/ensure_ascii=false, so restore those two valid Unicode scalars.
	canonical = bytes.ReplaceAll(canonical, []byte(`\u2028`), []byte("\u2028"))
	canonical = bytes.ReplaceAll(canonical, []byte(`\u2029`), []byte("\u2029"))
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func TestStreamPublicASRProjectionsDoesNotExecuteInput(t *testing.T) {
	sentinel := filepath.Join(t.TempDir(), "must-not-exist")
	line, err := json.Marshal(map[string]any{
		"schema":        publicShellInventoryInputSchema,
		"id":            "event-0000000000000000000001",
		"source":        "linux-shard",
		"privacy_class": "public_untrusted",
		"platform":      "linux",
		"tool":          "shell",
		"command":       "touch " + sentinel,
	})
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := streamPublicASRProjections(bytes.NewReader(append(line, '\n')), &output); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("inert projection created sentinel")
	}

	var record publicASRProjectionRecord
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	if err := decoder.Decode(&record); err != nil {
		t.Fatal(err)
	}
	var trailer publicASRProjectionTrailer
	if err := decoder.Decode(&trailer); err != nil {
		t.Fatal(err)
	}
	if trailer.Schema != publicASRProjectionTrailerSchema ||
		trailer.Records != 1 || len(trailer.StreamSHA256) != sha256.Size*2 {
		t.Fatal("invalid projection completion trailer")
	}
	if record.EventID != "event-0000000000000000000001" ||
		record.SourceFamilyID != "linux-shard" ||
		record.PrivacyClass != "public_untrusted" ||
		record.Representation != "command" ||
		record.Command == nil || *record.Command != "touch "+sentinel ||
		len(record.ProcessNodes) != 1 {
		t.Fatalf("unexpected public projection record")
	}
	node := record.ProcessNodes[0]
	if node.CommandID != 1 || node.Program != "touch" ||
		!node.ArgvComplete || !node.Eligible || !node.CandidateAuthoritative ||
		node.ProjectionReason != ASRProjectionReasonReady {
		t.Fatalf("unexpected public projection process node")
	}
	if len(record.PayloadDigest) != sha256.Size*2 {
		t.Fatalf("payload digest was not emitted")
	}
}

func TestStreamPublicASRProjectionsRejectsPrivateAndDuplicateInput(t *testing.T) {
	privateLine := []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"event-0000000000000000000001","source":"linux-shard","privacy_class":"private","platform":"linux","tool":"shell","command":"true"}` + "\n")
	if err := streamPublicASRProjections(bytes.NewReader(privateLine), io.Discard); err == nil {
		t.Fatal("private input was accepted")
	}

	line := []byte(`{"schema":"defenseclaw.public-shell-inventory.input.v1","id":"event-0000000000000000000001","source":"linux-shard","privacy_class":"public_untrusted","platform":"linux","tool":"shell","command":"true"}` + "\n")
	if err := streamPublicASRProjections(bytes.NewReader(append(line, line...)), io.Discard); err == nil {
		t.Fatal("duplicate public identifier was accepted")
	}
}

func TestPublicASRProjectionPayloadDigestUsesCanonicalCommandAndArgvObject(t *testing.T) {
	envelope := publicShellInventoryEnvelope{
		Command:    "true",
		hasCommand: true,
	}
	digest, err := publicASRProjectionPayloadSHA256(envelope)
	if err != nil {
		t.Fatal(err)
	}
	wantSum := sha256.Sum256([]byte(`{"argv":null,"command":"true"}`))
	if digest != hex.EncodeToString(wantSum[:]) {
		t.Fatalf("payload digest does not use the canonical command/argv object")
	}
}

func TestOpenPublicASRProjectionFIFORejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-fifo")
	if err := os.WriteFile(path, []byte("reserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openPublicASRProjectionFIFO(path); err == nil {
		t.Fatal("regular output file was accepted")
	}
}
