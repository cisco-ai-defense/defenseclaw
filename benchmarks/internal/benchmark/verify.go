// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package benchmark

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
)

var requiredOutputFiles = []string{
	"classification.sha256",
	"corpus-manifest.json",
	"coverage.csv",
	"datasets.lock.json",
	"environment.json",
	"inventory.json",
	"methodology.md",
	"predictions.jsonl",
	"results.json",
	"summary.csv",
}

// ClassificationSHA256 hashes only deterministic classification fields.
// Runtime duration and the caller-selected run ID remain reportable but cannot
// make two otherwise equal runs or hosts look behaviorally different.
func ClassificationSHA256(predictions []Prediction) (string, error) {
	stable := append([]Prediction(nil), predictions...)
	for index := range stable {
		stable[index].RunID = ""
		stable[index].DurationMicros = 0
	}
	var data bytes.Buffer
	if err := WritePredictions(&data, stable); err != nil {
		return "", err
	}
	sum := sha256.Sum256(data.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// VerifyOutput checks checksums, strict JSON records, cross-file run identity,
// and the value-safe prediction projection. It never opens source payloads.
func VerifyOutput(dir string, requirePublicationEligible bool) error {
	root, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	checksums, err := parseChecksums(filepath.Join(root, "checksums.txt"))
	if err != nil {
		return err
	}
	for _, name := range requiredOutputFiles {
		expected, ok := checksums[name]
		if !ok {
			return fmt.Errorf("checksums.txt is missing %s", name)
		}
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("output %s is not a regular file", name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		actual := sha256.Sum256(data)
		if hex.EncodeToString(actual[:]) != expected {
			return fmt.Errorf("checksum mismatch for %s", name)
		}
	}
	if len(checksums) != len(requiredOutputFiles) {
		return fmt.Errorf("checksums.txt contains unexpected or duplicate entries")
	}

	predictionFile, err := os.Open(filepath.Join(root, "predictions.jsonl"))
	if err != nil {
		return err
	}
	predictions, loadErr := LoadPredictions(predictionFile)
	closeErr := predictionFile.Close()
	if loadErr != nil {
		return loadErr
	}
	if closeErr != nil {
		return closeErr
	}
	digest, err := ClassificationSHA256(predictions)
	if err != nil {
		return err
	}
	digestFile, err := os.ReadFile(filepath.Join(root, "classification.sha256"))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(digestFile)) != digest {
		return fmt.Errorf("classification digest mismatch")
	}

	var environment Environment
	if err := decodeStrictFile(filepath.Join(root, "environment.json"), &environment); err != nil {
		return err
	}
	if environment.RunID == "" || environment.ClassificationSHA256 != digest {
		return fmt.Errorf("environment identity or classification digest mismatch")
	}
	if environment.CaseCount <= 0 || environment.PredictionCount != len(predictions) {
		return fmt.Errorf("environment case or prediction count mismatch")
	}
	var corpusManifest CorpusManifest
	if err := decodeStrictFile(filepath.Join(root, "corpus-manifest.json"), &corpusManifest); err != nil {
		return err
	}
	if corpusManifest.SchemaVersion != SchemaVersion || corpusManifest.Cases != environment.CaseCount ||
		corpusManifest.CorpusSHA256 != environment.CorpusSHA256 ||
		corpusManifest.TruthCorpusSHA256 != environment.TruthCorpusSHA256 {
		return fmt.Errorf("corpus manifest identity differs from environment")
	}
	if environment.TruthCorpusSHA256 != "" && !validSHA256(environment.TruthCorpusSHA256) {
		return fmt.Errorf("environment truth corpus digest is invalid")
	}
	for _, prediction := range predictions {
		if prediction.RunID != environment.RunID {
			return fmt.Errorf("prediction run %q differs from environment run %q", prediction.RunID, environment.RunID)
		}
	}
	if requirePublicationEligible {
		if environment.Dirty {
			return fmt.Errorf("publication requires a clean DefenseClaw worktree")
		}
		if environment.DefenseClawCommit == "" || environment.DefenseClawCommit == "unknown" {
			return fmt.Errorf("publication requires a resolved DefenseClaw commit")
		}
	}

	lockData, err := os.ReadFile(filepath.Join(root, "datasets.lock.json"))
	if err != nil {
		return err
	}
	if _, err := ParseDatasetLock(lockData); err != nil {
		return err
	}
	var summary Summary
	if err := decodeStrictFile(filepath.Join(root, "results.json"), &summary); err != nil {
		return err
	}
	if summary.SchemaVersion != SchemaVersion || summary.RunID != environment.RunID {
		return fmt.Errorf("results identity differs from environment")
	}
	return nil
}

func parseChecksums(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	out := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		parts := strings.Split(scanner.Text(), "  ")
		if len(parts) != 2 || len(parts[0]) != sha256.Size*2 {
			return nil, fmt.Errorf("checksums.txt line %d is invalid", lineNumber)
		}
		if _, err := hex.DecodeString(parts[0]); err != nil {
			return nil, fmt.Errorf("checksums.txt line %d has invalid digest", lineNumber)
		}
		name := parts[1]
		if name != filepath.Base(name) || strings.ContainsAny(name, "\\/") {
			return nil, fmt.Errorf("checksums.txt line %d has unsafe path", lineNumber)
		}
		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("checksums.txt contains duplicate %s", name)
		}
		out[name] = parts[0]
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeStrictFile(path string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", filepath.Base(path), err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode %s: %w", filepath.Base(path), err)
	}
	return nil
}

func sortedRequiredOutputFiles() []string {
	out := append([]string(nil), requiredOutputFiles...)
	sort.Strings(out)
	return out
}
