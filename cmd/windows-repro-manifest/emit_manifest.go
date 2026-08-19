// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// runEmitManifest emits manifest.json for a directory of signed payload
// files. Every file directly under --payload-dir is hashed with SHA-256
// and included; subdirectories are ignored to keep the schema flat and
// stable. The output JSON has sorted keys and a stable file-list order
// (alphabetical by name), so two independent runs against the same
// signed payload produce byte-identical output.
func runEmitManifest(args []string) error {
	fs := flag.NewFlagSet("emit-manifest", flag.ContinueOnError)
	schemaVersion := fs.Int("schema-version", 1, "manifest schema version")
	version := fs.String("version", "", "release version, e.g. 0.9.0")
	sourceCommit := fs.String("source-commit", "", "40-char lowercase git commit sha")
	distributionFlavor := fs.String("distribution-flavor", "managed-enterprise", "distribution flavor tag")
	payloadDir := fs.String("payload-dir", "", "directory whose regular-file children are hashed")
	out := fs.String("out", "", "output path for manifest.json")
	// --unsigned stamps `"unsigned": true` into the manifest and appends
	// "-unsigned" to distribution_flavor unless the caller explicitly
	// passes --distribution-flavor. Used by the spec 002 assemble path
	// when running under --allow-unsigned for the local developer loop;
	// the runtime hash gate at stageEnterprisePayload keys off the
	// same field to refuse non-disposable-scope installs.
	unsigned := fs.Bool("unsigned", false, "mark this manifest as an unsigned developer build")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireFlags(map[string]string{
		"version":       *version,
		"source-commit": *sourceCommit,
		"payload-dir":   *payloadDir,
		"out":           *out,
	}); err != nil {
		return err
	}
	if err := validateSourceCommit(*sourceCommit); err != nil {
		return err
	}

	files, err := hashPayloadDir(*payloadDir)
	if err != nil {
		return fmt.Errorf("hash payload dir %s: %w", *payloadDir, err)
	}
	if len(files) == 0 {
		return fmt.Errorf("payload dir %s contains no regular files", *payloadDir)
	}

	entries := make([]any, 0, len(files))
	for _, f := range files {
		entries = append(entries, map[string]any{
			"name":   f.name,
			"sha256": f.sha256,
			"size":   f.size,
		})
	}
	flavor := *distributionFlavor
	if *unsigned && flavor == "managed-enterprise" {
		// Only auto-suffix the default flavor. A caller that passes an
		// explicit --distribution-flavor is trusted to have shaped the
		// string already (e.g. downstream test harnesses).
		flavor = "managed-enterprise-unsigned"
	}
	doc := map[string]any{
		"distribution_flavor": flavor,
		"files":               entries,
		"schema_version":      *schemaVersion,
		"source_commit":       *sourceCommit,
		"unsigned":            *unsigned,
		"version":             *version,
	}
	return writeSortedJSON(*out, doc)
}

// payloadFile records the byte-stable identity of one signed payload
// file: its base name (relative to --payload-dir), the SHA-256 hex
// digest of its contents, and its size in bytes. Directories and
// symlinks are refused by hashPayloadDir before this type is
// constructed, so `size` is always the on-disk regular-file size.
type payloadFile struct {
	name   string
	sha256 string
	size   int64
}

// hashPayloadDir returns the payload children of dir, sorted by name.
// It refuses subdirectories and symlinks so the schema stays flat and
// the byte-stability contract does not depend on filesystem walk
// order.
func hashPayloadDir(dir string) ([]payloadFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]payloadFile, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		// The manifest's `name` field is embedded verbatim into
		// manifest.json. encoding/json would replace invalid UTF-8 bytes
		// with U+FFFD on marshal, which silently mutates the recorded
		// name and breaks the byte-identity between the file on disk and
		// the string a verifier will compare against. Reject up front so
		// the failure is loud and located, not smeared over the artefact.
		if !utf8.ValidString(name) {
			return nil, fmt.Errorf("refusing payload entry with non-UTF-8 name: %q", name)
		}
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing symlink in payload dir: %s", name)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("refusing subdirectory in payload dir: %s", name)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing non-regular file in payload dir: %s", name)
		}
		digest, err := sha256File(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		out = append(out, payloadFile{
			name:   name,
			sha256: digest,
			size:   info.Size(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// sha256File streams path through a SHA-256 hasher and returns the
// lowercase hex digest. Streaming (rather than ReadFile) keeps peak
// memory bounded regardless of file size.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// requireFlags returns a combined error listing every empty required
// flag, so a caller that omitted three of them sees all three in one
// error rather than fixing them one at a time.
func requireFlags(flags map[string]string) error {
	names := make([]string, 0, len(flags))
	for name, val := range flags {
		if strings.TrimSpace(val) == "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return fmt.Errorf("missing required flag(s): --%s", strings.Join(names, ", --"))
}

// validateSourceCommit refuses anything but a 40-char lowercase hex
// git OID. This is the same shape scripts/build-windows-installer.ps1
// asserts for gateway-source-commit.txt.
func validateSourceCommit(sha string) error {
	if len(sha) != 40 {
		return errors.New("--source-commit must be a 40-char lowercase git OID")
	}
	for _, r := range sha {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return errors.New("--source-commit must be a 40-char lowercase git OID")
		}
	}
	return nil
}
