// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"io"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

const claudeVersionSuite = "claude-version"
const claudeVersionOutput = "2.1.292 (Claude Code)\n"
const claudeVersionScope = "fixed_linux_native_claude_2_1_292_version_only_v1"
const claudeImageSHA = "d23f28ef84f5459a25d2d4cf999a7debd41df83507160446983d4ca65554e50f"
const claudeImageSize = 245203032
const claudeLoaderSHA = "76b812138a1d4be51ae095e94920e1fd1c5d25f793651baf834d05a2c455c040"
const claudeLoaderSize = 853616
const claudeLoaderLeaf = "claude-runtime-loader"

// The caller supplies a fresh descriptor for the held private fixture root.
// A positive Readdirnames limit can return its last nonempty batch with nil;
// require a separate bounded end-of-directory observation in that case.
func verifyInitialFixtureEntries(directory *os.File, withLoader bool) error {
	entries, err := directory.Readdirnames(2)
	if err != nil && err != io.EOF {
		return err
	}
	want := 0
	if withLoader {
		want = 1
	}
	if len(entries) != want || withLoader && entries[0] != claudeLoaderLeaf {
		return errors.New("fixed fixture initial entries differ")
	}
	if err == nil {
		tail, end := directory.Readdirnames(1)
		if len(tail) != 0 || end != io.EOF {
			return errors.New("fixed fixture directory end was not observed")
		}
	}
	return nil
}

// These fixed signed-release facts came from the independently reviewed inert
// official inspector. They are not a full dlopen or agent compatibility claim.
type claudeReleaseIdentity struct {
	Version              string `json:"version"`
	Platform             string `json:"platform"`
	URL                  string `json:"url"`
	ManifestSHA          string `json:"manifest_sha256"`
	SignatureSHA         string `json:"signature_sha256"`
	KeySHA               string `json:"key_sha256"`
	Signer               string `json:"signer_fingerprint"`
	InspectionArchiveSHA string `json:"inspection_archive_sha256"`
}

func fixedClaudeRelease() claudeReleaseIdentity {
	return claudeReleaseIdentity{
		Version: "2.1.292", Platform: "linux-x64-musl",
		URL:                  "https://downloads.claude.ai/claude-code-releases/2.1.292/linux-x64-musl/claude",
		ManifestSHA:          "64f5abe05a43151810acf8c25169872e41293c96d3ae73d6508733a8b336e2b1",
		SignatureSHA:         "537e1a8bcca1646fd5e52d3dc8d16509395a88f6f18b13765b2c085d057567ea",
		KeySHA:               "bd70a5e4a268002704024ceba7f8446024114e94f3f0bdd11c23a9e592be81c6",
		Signer:               "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE",
		InspectionArchiveSHA: "d150b40d90cc201eb45223d73221c4d626598e269d003974f45aa4beb5ba28c2",
	}
}

// Only these reviewed inputs are selectable for this separate finite canary.
// This source entry still needs its own wrapper/driver build and run review.
func fixedClaudeVersionRegistry() reviewedRegistry {
	r := fixedContributorRegistry()
	r.ReceiptSHA = "e24ee1736320e9df281e0ab7049b2df8cbacbf27d81d31fc46e21cef09b165b7"
	v := &r.Receipt
	v.Scope, v.PayloadSourceSHA = claudeVersionScope, ""
	v.Builds[1] = buildIdentity{Role: "shared_musl_loader", Commit: "0ad2618803ecd69a7a1df782c70f38b699d74d13", Run: 39193900521, Artifact: 12161286875,
		ArchiveSHA: "4001eaf9cf2321ba9d695fe49d53168192f9d6b4649d715c1f88c12242da8060", ProvenanceSHA: "f533f74bfff81d5cf36b7f6975a7a41d06ccbcc97be114ba09c2835b821bcf41"}
	v.Images[2] = imageIdentity{Role: "claude_musl", Path: "images/claude-musl", SHA: claudeImageSHA, Size: claudeImageSize}
	release := fixedClaudeRelease()
	v.ClaudeVersion = &release
	v.Loader = &imageIdentity{Role: "shared_musl_loader", Path: "images/musl-loader", SHA: claudeLoaderSHA, Size: claudeLoaderSize}
	v.LoaderClosureSHA = "ff3aaad09bd59f623fac2fdffccd7ddfaef44bf2b5ba42508e9b20bf37280e92"
	return r
}

func registryForSuite(suite string) reviewedRegistry {
	if suite == claudeVersionSuite {
		return fixedClaudeVersionRegistry()
	}
	return liveRegistry
}

func (v artifactReceipt) validateClaudeVersion() error {
	if v.PayloadSourceSHA != "" || v.ClaudeVersion == nil || *v.ClaudeVersion != fixedClaudeRelease() ||
		v.LoaderClosureSHA != "ff3aaad09bd59f623fac2fdffccd7ddfaef44bf2b5ba42508e9b20bf37280e92" ||
		v.Loader == nil || *v.Loader != (imageIdentity{Role: "shared_musl_loader", Path: "images/musl-loader", SHA: claudeLoaderSHA, Size: claudeLoaderSize}) ||
		len(v.Images) != 3 || v.Images[2].SHA != claudeImageSHA || v.Images[2].Size != claudeImageSize {
		return errors.New("fixed Claude release or loader identity differs")
	}
	return nil
}

func (r reviewedRegistry) supportsSuite(suite string) bool {
	return r.Receipt.Scope == harnessScope && (suite == "baseline" || suite == "lifecycle") ||
		r.Receipt.Scope == claudeVersionScope && suite == claudeVersionSuite
}

// This plan has no caller image, argv, environment or filesystem selector.
// Registry/held-input admission remains separate and mandatory; these constants
// do not qualify a wrapper build or any actual native execution.
func claudeVersionPlan() (bridgeproto.Preparation, error) {
	plan := bridgeproto.Preparation{
		Backend: "bubblewrap", Argv: []string{"/.defenseclaw/payload", "--version"},
		Environment: []bridgeproto.Variable{{Name: "HOME", Value: "/home"}, {Name: "TMPDIR", Value: "/tmp"}},
		Workdir:     "/work", Offline: true, TimeoutMS: 10000, OutputLimit: 4096,
		Filesystem: bridgeproto.Filesystem{
			Read:  []string{"/lib/ld-musl-x86_64.so.1", "/lib/libc.musl-x86_64.so.1"},
			Write: []string{"/work", "/home", "/tmp"}, Deny: []string{},
		},
	}
	return plan, plan.Validate()
}

// These are the two existing fixture capabilities followed by the one new
// ordinary loader capability. ExtraFiles remaps this tail after four private
// worker FDs, so the worker receives parent7/root8/loader9.
func versionFixtureInputs(parent, root, loader *os.File) []*os.File {
	files := []*os.File{parent, root}
	if loader != nil {
		files = append(files, loader)
	}
	return files
}
