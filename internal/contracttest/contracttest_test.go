// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package contracttest

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// fatalRecorder is a testing.TB whose Fatalf records the failure and ends
// the goroutine, so a test can see Validate reject a document.
type fatalRecorder struct {
	testing.TB
	message string
}

func (r *fatalRecorder) Helper() {}

func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.message = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

// validateFailure runs Validate and returns its failure message, "" when
// the document passed.
func validateFailure(t *testing.T, s Schemas, name, document string) string {
	t.Helper()
	r := &fatalRecorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Validate(r, name, []byte(document))
	}()
	<-done
	return r.message
}

func TestValidateRequiresExactlyOneDocument(t *testing.T) {
	s := Compile(t)
	const name = "bundle-status.schema.json#/$defs/ref"
	ref := `{"bundle_id":"b-01ARZ3NDEKTSV4RRFFQ69G5FAV","version":1,"manifest_sha256":"` +
		strings.Repeat("0", 64) + `","dir":"d"}`
	for _, document := range []string{ref, ref + "\n", " " + ref + " \r\n"} {
		if failure := validateFailure(t, s, name, document); failure != "" {
			t.Errorf("one document %q rejected: %s", document, failure)
		}
	}
	for _, trailing := range []string{"]", "}", " ]\n", "\n}", ref, " x"} {
		if failure := validateFailure(t, s, name, ref+trailing); failure == "" {
			t.Errorf("%q after the document was accepted", trailing)
		}
	}
}
