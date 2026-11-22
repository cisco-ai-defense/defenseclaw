// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0454: values.yaml says the try-out collector shows the records in its
// log, but its debug exporter ran at verbosity basic, which prints only
// record counts. It runs at detailed, which prints each record and its
// attributes.
func TestGAP0454ChartCollectorPrintsTheRecords(t *testing.T) {
	chart := filepath.Join("..", "..", "..", "deploy", "helm", "defenseclaw-substrate")
	values, err := os.ReadFile(filepath.Join(chart, "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(values), "records show in the collector's log") {
		t.Fatal("values.yaml no longer says what the try-out collector shows; update this test with it")
	}
	tmpl, err := os.ReadFile(filepath.Join(chart, "templates", "observability", "collector.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tmpl), "debug: {verbosity: detailed}") {
		t.Fatalf("the try-out collector's debug exporter does not print records (want verbosity detailed):\n%s", tmpl)
	}
}
