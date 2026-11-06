// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"strings"
	"sync"
	"testing"
)

var rv4Expected struct {
	sync.Once
	rows map[string]string
	err  error
}

func rv4AssertCells(t *testing.T, suite, id string, cells []string) {
	t.Helper()
	rv4Expected.Do(func() {
		data, err := os.ReadFile("testdata/gx054_review4_expected.tsv")
		rv4Expected.err = err
		rv4Expected.rows = map[string]string{}
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "\t")
			if ok {
				rv4Expected.rows[key] = value
			}
		}
	})
	if rv4Expected.err != nil {
		t.Fatal(rv4Expected.err)
	}
	key := suite + "/" + id
	expected, ok := rv4Expected.rows[key]
	if !ok {
		t.Fatalf("missing reviewer oracle for %s", key)
	}
	var actual []string
	for _, cell := range cells {
		for _, code := range strings.Fields(cell) {
			switch {
			case code == "A":
				actual = append(actual, "A")
			case strings.Contains(code, "+"):
				actual = append(actual, "D+")
			default:
				actual = append(actual, "D")
			}
		}
	}
	got := strings.Join(actual, " ")
	if got != expected {
		t.Errorf("%s: cells %s, want %s", key, got, expected)
	}
}
