// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// A release of a change event reservation that could not be flushed is
// surfaced as change_release_unflushed, with its cause, on the run's
// stderr; a durable release prints nothing.
func TestChangeReleaseUnflushedIsAWarning(t *testing.T) {
	var out bytes.Buffer
	warnChangeReleaseUnflushed(&out, nil)
	if out.Len() != 0 {
		t.Fatalf("a durable release printed %q", out.String())
	}
	warnChangeReleaseUnflushed(&out, errors.New("fsync: input/output error"))
	if got := out.String(); !strings.HasPrefix(got, "warning: change_release_unflushed: ") ||
		!strings.Contains(got, "fsync: input/output error") || !strings.Contains(got, "interrupted change") {
		t.Fatalf("warning = %q", got)
	}
	if w := changeReleaseUnflushedWarning(errors.New("x")); w.Code != codeChangeReleaseUnflushed {
		t.Fatalf("code = %q", w.Code)
	}
}
