// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

// Contributor-only, uncontained fixed --version diagnostic. No default launch.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const scope = "fixed_windows_uncontained_claude_application_path_control"

type report struct {
	Scope                   string       `json:"scope"`
	Completed               bool         `json:"measurement_completed"`
	ProductionQualification bool         `json:"production_qualification"`
	Containment             bool         `json:"sandbox_containment"`
	ImageSHA                string       `json:"image_sha256"`
	ReceiptSHA              string       `json:"local_image_receipt_sha256"`
	FixtureRetained         bool         `json:"fresh_fixture_retained"`
	Cases                   []caseReport `json:"cases"`
	Error                   string       `json:"error,omitempty"`
	Elapsed                 float64      `json:"elapsed_seconds"`
}

func fixedSelector(arguments []string) bool {
	return len(arguments) == 1 && arguments[0] == "--run-fixed"
}

func execute() (result report, resultErr error) {
	started := time.Now()
	result = report{Scope: scope, ImageSHA: imageSHA, ReceiptSHA: receiptSHA}
	defer func() {
		result.Elapsed = time.Since(started).Seconds()
		if resultErr != nil {
			// All errors emitted by this helper are fixed public classifications.
			result.Error = resultErr.Error()
			result.Completed = false
		}
	}()
	self, err := os.Executable()
	if err != nil {
		return result, errors.New("helper executable lookup refused")
	}
	fixture, err := prepareFixture(filepath.Dir(self), &result.FixtureRetained)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, fixture.close()) }()
	inputs, err := fixedInputs(fixture)
	if err != nil {
		return result, err
	}
	// The independent root controller must enforce 30 s over the WHOLE helper,
	// including regular-file setup calls which a Go context cannot interrupt.
	deadline := started.Add(25 * time.Second)
	for _, application := range fixture.applications {
		item, err := runCase(application, inputs, fixture.image, deadline)
		result.Cases = append(result.Cases, item)
		if err != nil {
			return result, err
		}
	}
	result.Completed = len(result.Cases) == 3
	return result, nil
}

func main() {
	if !fixedSelector(os.Args[1:]) {
		fmt.Fprintln(os.Stderr, "only the exact fixed --run-fixed selector is accepted")
		os.Exit(2)
	}
	result, err := execute()
	if json.NewEncoder(os.Stdout).Encode(result) != nil || err != nil {
		os.Exit(1)
	}
}
