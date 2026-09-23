// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package benchmark

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

const maxCaseBytes = 2 << 20

func LoadCases(r io.Reader) ([]Case, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxCaseBytes)
	seen := make(map[string]int)
	var cases []Case
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || bytes.HasPrefix(line, []byte("//")) {
			continue
		}
		var item Case
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&item); err != nil {
			return nil, fmt.Errorf("line %d: decode: %w", lineNumber, err)
		}
		if err := requireJSONEOF(decoder); err != nil {
			return nil, fmt.Errorf("line %d: decode: %w", lineNumber, err)
		}
		if err := item.Validate(); err != nil {
			return nil, fmt.Errorf("line %d case %q: %w", lineNumber, item.ID, err)
		}
		if prior, ok := seen[item.ID]; ok {
			return nil, fmt.Errorf("line %d: duplicate case ID %q (first at line %d)", lineNumber, item.ID, prior)
		}
		seen[item.ID] = lineNumber
		cases = append(cases, item)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read corpus: %w", err)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("corpus is empty")
	}
	sort.SliceStable(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	return cases, nil
}

func WritePredictions(w io.Writer, predictions []Prediction) error {
	sort.SliceStable(predictions, func(i, j int) bool {
		if predictions[i].Profile != predictions[j].Profile {
			return predictions[i].Profile < predictions[j].Profile
		}
		if predictions[i].CaseID != predictions[j].CaseID {
			return predictions[i].CaseID < predictions[j].CaseID
		}
		return predictions[i].Engine < predictions[j].Engine
	})
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	for _, prediction := range predictions {
		if err := encoder.Encode(prediction); err != nil {
			return fmt.Errorf("encode prediction %q: %w", prediction.CaseID, err)
		}
	}
	return nil
}

func LoadPredictions(r io.Reader) ([]Prediction, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxCaseBytes)
	var out []Prediction
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var item Prediction
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&item); err != nil {
			return nil, fmt.Errorf("line %d: decode prediction: %w", lineNumber, err)
		}
		if err := requireJSONEOF(decoder); err != nil {
			return nil, fmt.Errorf("line %d: decode prediction: %w", lineNumber, err)
		}
		if err := item.Validate(); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		out = append(out, item)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read predictions: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("predictions are empty")
	}
	return out, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}
