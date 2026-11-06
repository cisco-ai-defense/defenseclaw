// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
package gateway

import (
	"os"
	"strings"
	"sync"
	"testing"
)

// Every row of the independent round-four probe has a pinned eight-cell
// (or four-cell OpenCode patch) verdict. W requires the visible Possible
// finding in rv5oClass, and each connector constructs its own client header.
var rv5Expected struct {
	sync.Once
	rows map[string]string
	err  error
}

func rv5AssertCells(t *testing.T, key string, cells []string) {
	t.Helper()
	rv5Expected.Do(func() {
		data, err := os.ReadFile("testdata/gx054_review5_expected.tsv")
		rv5Expected.err = err
		rv5Expected.rows = make(map[string]string)
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "\t")
			if ok {
				rv5Expected.rows[key] = value
			}
		}
	})
	if rv5Expected.err != nil {
		t.Fatal(rv5Expected.err)
	}
	want, ok := rv5Expected.rows[key]
	if !ok {
		t.Fatalf("missing reviewer oracle for %s", key)
	}
	var parts []string
	for _, segment := range cells {
		parts = append(parts, strings.Fields(segment)...)
	}
	got := strings.Join(parts, " ")
	if got != want {
		t.Errorf("%s: got %s, want %s", key, got, want)
	}
}
