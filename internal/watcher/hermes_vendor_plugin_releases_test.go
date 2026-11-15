// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// extractHermesRelease writes testdata/hermes-vendor/<file> to dir. Each file
// is the git archive of one shipped plugin at a Hermes release tag, byte for
// byte (hermes-agent, MIT License, Copyright (c) 2025 Nous Research).
func extractHermesRelease(t *testing.T, file, dir string) {
	t.Helper()
	in, err := os.Open(filepath.Join("testdata", "hermes-vendor", file))
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	archive := tar.NewReader(in)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		writePluginFile(t, filepath.Join(dir, filepath.FromSlash(header.Name)), string(data))
	}
}

// hermesReleasePlugin writes the model-providers/xai plugin of a Hermes
// release into the shipped plugin root and gives it a HIGH finding whenever
// it is scanned.
func (f *hermesPluginFixture) hermesReleasePlugin(release string) string {
	f.t.Helper()
	path := filepath.Join(f.bundledRoot, "model-providers", "xai")
	extractHermesRelease(f.t, "model-providers-xai-"+release+".tar", path)
	f.scan.findings[path] = []scanner.Finding{{
		ID: "review-xai", RuleID: "PLUGIN-REVIEW", Severity: scanner.SeverityHigh, Title: "Review plugin source",
	}}
	return path
}

// rel-1-0-10:GAP-0765: the digests pinned one Hermes commit, so after a Hermes
// update (0.21.5 to 0.23.1) no shipped plugin matched and the gateway scanned
// all of them at start. The unchanged plugin of every Hermes release in the
// digest table is vendor content: not scanned, no stored scan.
func TestHermesShippedPluginOfEachSupportedReleaseIsVendor(t *testing.T) {
	for _, release := range []string{"0.21.5", "0.23.1"} {
		t.Run(release, func(t *testing.T) {
			f := newHermesPluginFixture(t)
			path := f.hermesReleasePlugin(release)
			f.w.runRescanCycle(context.Background())
			f.w.runRescanCycle(context.Background())
			f.unscannedVendor(path)
		})
	}
}

// rel-1-0-10:GAP-0765: more releases do not loosen the match. A release tree
// with one byte changed, or with a file added, matches no release digest: it
// is scanned on first sight, and when it was vendor content before, it is
// admitted and refused for its HIGH finding.
func TestHermesShippedPluginChangedFromItsReleaseIsScanned(t *testing.T) {
	tampers := map[string]func(t *testing.T, path string){
		"same-size edit": func(t *testing.T, path string) {
			file := filepath.Join(path, "__init__.py")
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			at := bytes.IndexByte(data, 0x0a)
			if at < 1 {
				t.Fatalf("%s has no line to edit", file)
			}
			data[at-1] ^= 0x01
			writePluginFile(t, file, string(data))
		},
		"added file": func(t *testing.T, path string) {
			writePluginFile(t, filepath.Join(path, "helper.py"), "import os\n")
		},
	}
	for name, tamper := range tampers {
		t.Run(name+" after vendor content", func(t *testing.T) {
			f := newHermesPluginFixture(t)
			path := f.hermesReleasePlugin("0.23.1")
			f.w.runRescanCycle(context.Background())
			f.unscannedVendor(path)
			tamper(t, path)
			f.w.runRescanCycle(context.Background())
			if n := f.scan.scans(path); n != 1 {
				t.Fatalf("changed release plugin scans = %d, want 1", n)
			}
			f.refused(path)
		})
		t.Run(name+" on first sight", func(t *testing.T) {
			f := newHermesPluginFixture(t)
			path := f.hermesReleasePlugin("0.23.1")
			tamper(t, path)
			f.w.runRescanCycle(context.Background())
			if n := f.scan.scans(path); n != 1 {
				t.Fatalf("changed release plugin scans = %d, want 1", n)
			}
		})
	}
}

// The release list doctor and status read (the Python twin) is the release
// list of the Go digest table, row for row, and every entry is a SHA-256.
func TestHermesVendorPluginReleasesMatchPythonTwin(t *testing.T) {
	goSource, err := os.ReadFile("hermes_vendor_plugin_digests.go")
	if err != nil {
		t.Fatal(err)
	}
	pySource, err := os.ReadFile(filepath.Join("..", "..", "cli", "defenseclaw", "hermes_vendor_plugin_releases.py"))
	if err != nil {
		t.Fatal(err)
	}
	goRows := regexp.MustCompile(`(?m)^//\t([0-9.]+)\t(v[0-9.]+)\t([0-9a-f]{40})\r?$`).FindAllStringSubmatch(string(goSource), -1)
	pyRows := regexp.MustCompile(`(?m)^    \("([0-9.]+)", "(v[0-9.]+)", "([0-9a-f]{40})"\),\r?$`).FindAllStringSubmatch(string(pySource), -1)
	if len(goRows) == 0 || !slices.EqualFunc(goRows, pyRows, func(a, b []string) bool { return slices.Equal(a[1:], b[1:]) }) {
		t.Fatalf("Go digest table releases %q, Python twin releases %q: run scripts/hermes_vendor_plugin_digests.py", goRows, pyRows)
	}
	sha256Hex := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for name, digests := range hermesPluginVendorDigests {
		if name == "" || len(digests) == 0 || !slices.IsSorted(digests) {
			t.Fatalf("plugin %q digests %q: want a name and a sorted, non-empty list", name, digests)
		}
		for _, digest := range digests {
			if !sha256Hex.MatchString(digest) {
				t.Fatalf("plugin %q digest %q is not a SHA-256", name, digest)
			}
		}
	}
}
