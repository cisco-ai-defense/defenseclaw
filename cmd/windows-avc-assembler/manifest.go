// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/setuppayload"
)

// distributionFlavor is the flavor tag stamped into both manifest.json
// and provenance.json. It must match the value the runtime loader
// (loadEnterprisePayload in cmd/defenseclaw-enterprise-setup/main.go)
// asserts against: "managed-enterprise" for AVC-signed kits, or
// "managed-enterprise-unsigned" when the -AllowUnsigned developer path
// is taken.
const (
	distributionFlavorSigned   = "managed-enterprise"
	distributionFlavorUnsigned = "managed-enterprise-unsigned"
)

// manifestFile is one row in manifest.json's `files` array. Fields
// match the runtime's enterprisePayloadManifestFile — a schema drift
// on either side is a boot-time failure.
type manifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// manifestDocument is the manifest.json shape written to the trailer.
// Fields match cmd/defenseclaw-enterprise-setup/main.go
// enterprisePayloadManifest.
type manifestDocument struct {
	DistributionFlavor string         `json:"distribution_flavor"`
	Files              []manifestFile `json:"files"`
	SchemaVersion      int            `json:"schema_version"`
	SourceCommit       string         `json:"source_commit"`
	Unsigned           bool           `json:"unsigned"`
	Version            string         `json:"version"`
}

// buildManifestAndEntries hashes every payload file and returns the
// canonical manifest JSON plus the ordered setuppayload.Entry slice
// the trailer writer needs. The two are produced together so the
// per-file SHA-256 recorded in the manifest is the same digest the
// trailer's per-entry header will carry — a runtime hash mismatch is
// impossible by construction.
func buildManifestAndEntries(payloadDir string, opts options) ([]byte, []setuppayload.Entry, error) {
	files := make([]manifestFile, 0, len(requiredPayloadFiles))
	entries := make([]setuppayload.Entry, 0, len(requiredPayloadFiles))
	for _, name := range requiredPayloadFiles {
		contents, digest, err := readAndHash(filepath.Join(payloadDir, name))
		if err != nil {
			return nil, nil, &ioError{msg: fmt.Sprintf("read+hash %s: %s", name, err)}
		}
		files = append(files, manifestFile{
			Name:   name,
			SHA256: digest,
			Size:   int64(len(contents)),
		})
		entries = append(entries, setuppayload.Entry{Name: name, Contents: contents})
	}
	// Both slices sorted by Name — the runtime's manifest.Files loop
	// and the trailer archive both observe alphabetical order, so
	// keeping the JSON in the same order avoids user-visible drift.
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	doc := manifestDocument{
		DistributionFlavor: flavorFor(opts.AllowUnsigned),
		Files:              files,
		SchemaVersion:      1,
		SourceCommit:       opts.SourceCommit,
		Unsigned:           opts.AllowUnsigned,
		Version:            opts.Version,
	}
	body, err := marshalCanonical(doc)
	if err != nil {
		return nil, nil, &buildError{msg: fmt.Sprintf("marshal manifest: %s", err)}
	}
	return body, entries, nil
}

// readAndHash slurps a file into memory (payload files are single-digit
// MB at worst) and returns both the bytes and the hex SHA-256 digest.
// One pass, single allocation for both outputs.
func readAndHash(path string) ([]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	h := sha256.New()
	var buf bytes.Buffer
	if _, err := io.Copy(io.MultiWriter(h, &buf), f); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), hex.EncodeToString(h.Sum(nil)), nil
}

// marshalCanonical writes a JSON document with sorted keys, two-space
// indent, LF line endings, and a trailing LF. Matches
// cmd/windows-repro-manifest/serialize.go writeSortedJSON so a
// diff between this assembler's output and the old emitter's output
// is exactly what changed at the field level, not whitespace.
func marshalCanonical(v any) ([]byte, error) {
	// Round-trip via map[string]any so encoding/json sorts keys
	// alphabetically instead of struct-declaration order. This mirrors
	// the emit-manifest path from cmd/windows-repro-manifest.
	tmp, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var asMap map[string]any
	if err := json.Unmarshal(tmp, &asMap); err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(asMap, "", "  ")
	if err != nil {
		return nil, err
	}
	out = append(out, '\n')
	return out, nil
}

// flavorFor picks the distribution_flavor tag based on -AllowUnsigned.
// The runtime's identity gate keys off the same rule.
func flavorFor(allowUnsigned bool) string {
	if allowUnsigned {
		return distributionFlavorUnsigned
	}
	return distributionFlavorSigned
}

// writeProvenance emits provenance.json alongside the assembled EXE.
// setup_sha256 is left empty and setup_size zero — AVC signs the EXE
// after the assembler runs, and the finalize.ps1 helper (unchanged
// since spec 002) fills the fields in-place with the signed EXE's
// SHA-256 after signtool has run.
func writeProvenance(path string, opts options) error {
	doc := map[string]any{
		"distribution_flavor": flavorFor(opts.AllowUnsigned),
		"schema_version":      1,
		"setup_sha256":        "",
		"setup_size":          0,
		"source_commit":       opts.SourceCommit,
		"unsigned":            opts.AllowUnsigned,
		"version":             opts.Version,
	}
	body, err := marshalCanonical(doc)
	if err != nil {
		return &buildError{msg: fmt.Sprintf("marshal provenance: %s", err)}
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return &ioError{msg: fmt.Sprintf("write provenance: %s", err)}
	}
	return nil
}
