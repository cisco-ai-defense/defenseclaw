//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// #1296: the trusted CAs of openshell.trusted_ca_bundle go into the image's
// system store, first, one file per certificate, and the content hash, the
// tag and a label name them; an image without any is the image it was.
func TestTrustedCAsAreBakedIntoTheSystemStore(t *testing.T) {
	h, _ := harness.Get("claudecode")
	plain := mustContext(t, testSpec(h))
	empty := testSpec(h)
	empty.TrustedCAs = []byte{}
	if c := mustContext(t, empty); c.ContentHash != plain.ContentHash || !bytes.Equal(c.Dockerfile, plain.Dockerfile) {
		t.Fatal("an empty trusted CA bundle changed the image")
	}
	if strings.Contains(string(plain.Dockerfile), "update-ca-certificates") || plain.Labels[LabelTrustedCAs] != "" {
		t.Fatalf("an image without trusted CAs carries the CA step:\n%s", plain.Dockerfile)
	}

	root, issuing := openshelltest.NewCA(t, "Corp Root CA"), openshelltest.NewCA(t, "Corp Issuing CA")
	spec := testSpec(h)
	spec.TrustedCAs = append(append(append([]byte(nil), root.PEM...), issuing.PEM...), root.PEM...)
	c := mustContext(t, spec)
	if c.ContentHash == plain.ContentHash || c.Tag == plain.Tag {
		t.Fatal("trusted CAs did not change the content hash and tag")
	}
	if len(c.TrustedCAs.Certs) != 2 || !bytes.Equal(c.Spec.TrustedCAs, c.TrustedCAs.PEM) {
		t.Fatalf("trusted CAs = %v", c.TrustedCAs.Subjects())
	}
	if c.Labels[LabelTrustedCAs] != c.TrustedCAs.Digest() {
		t.Fatalf("label = %q", c.Labels[LabelTrustedCAs])
	}
	files := map[string][]byte{}
	for _, f := range c.Files {
		files[f.Name] = f.Data
		if strings.HasPrefix(f.Name, "trusted-ca/") && (f.Mode != 0o644 || f.UID != 0 || f.GID != 0) {
			t.Errorf("%s: mode %v owner %d:%d", f.Name, f.Mode, f.UID, f.GID)
		}
	}
	if !bytes.Equal(files["trusted-ca/defenseclaw-trusted-ca-01.crt"], root.PEM) || !bytes.Equal(files["trusted-ca/defenseclaw-trusted-ca-02.crt"], issuing.PEM) ||
		files["trusted-ca/defenseclaw-trusted-ca-03.crt"] != nil {
		t.Fatalf("context files: %v", c.Files)
	}
	df := string(c.Dockerfile)
	dir := openshell.SandboxTrustedCADir
	for _, want := range []string{
		"RUN install -d -o root -g root -m 0755 " + dir + "\n",
		"COPY --chown=0:0 --chmod=0644 trusted-ca/defenseclaw-trusted-ca-01.crt " + dir + "/defenseclaw-trusted-ca-01.crt\n",
		"COPY --chown=0:0 --chmod=0644 trusted-ca/defenseclaw-trusted-ca-02.crt " + dir + "/defenseclaw-trusted-ca-02.crt\n",
		"update-ca-certificates >/dev/null",
		`grep -qxF -- "$line" ` + openshell.SandboxSystemCABundle,
		"the base image has no update-ca-certificates",
	} {
		if !strings.Contains(df, want) {
			t.Errorf("Dockerfile lacks %q", want)
		}
	}
	// Before any download: right after USER root, ahead of the jq/curl step.
	if ca, tools := strings.Index(df, "update-ca-certificates"), strings.Index(df, "for tool in jq curl"); ca < 0 || ca > tools ||
		strings.Index(df, "USER root\n") > strings.Index(df, "RUN install -d -o root -g root -m 0755 "+dir) {
		t.Fatalf("the CA step is not first:\n%s", df)
	}

	other := testSpec(h)
	other.TrustedCAs = issuing.PEM
	if mustContext(t, other).ContentHash == c.ContentHash {
		t.Fatal("another CA bundle has the same content hash")
	}

	// The record carries them, so the context renders again from it
	// (runimage baseDirs), and a record without them is not current.
	rec := Record{Tag: c.Tag, ContentHash: c.ContentHash, Connector: h.Name, HarnessVersion: c.HarnessVersion, HookContract: c.Contract,
		BaseImage: c.Spec.BaseImage, UID: 1000, GID: 1000, IngressPort: 18971, DefenseClawVersion: "1.2.3", FailMode: c.Spec.FailMode,
		Owner: testOwner, TrustedCAs: string(c.TrustedCAs.PEM)}
	if !recordMatches(rec, c) {
		t.Fatal("the record of the image does not match its context")
	}
	if _, err := baseDirs(rec); err != nil {
		t.Fatalf("baseDirs: %v", err)
	}
	stale := rec
	stale.TrustedCAs = ""
	if recordMatches(stale, c) {
		t.Fatal("a record without the trusted CAs matches")
	}
}

func TestNewContextRefusesBadTrustedCAs(t *testing.T) {
	h, _ := harness.Get("codex")
	spec := testSpec(h)
	spec.TrustedCAs = []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
	if _, err := NewContext(spec); err == nil || !strings.Contains(err.Error(), openshell.TrustedCAKey) {
		t.Fatalf("err = %v", err)
	}
}

// TrustedCAsFor: the managed gateway's relayed CAs (or its reason), else the
// configured file; any problem fails closed.
func TestTrustedCAsFor(t *testing.T) {
	ca := openshelltest.NewCA(t, "Corp Root CA")
	file := filepath.Join(t.TempDir(), "corp.pem")
	if err := os.WriteFile(file, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := TrustedCAsFor(nil); err != nil || got != nil {
		t.Fatalf("nil config: %q %v", got, err)
	}
	cfg := &config.Config{}
	if got, err := TrustedCAsFor(cfg); err != nil || got != nil {
		t.Fatalf("unset: %q %v", got, err)
	}
	cfg.OpenShell.TrustedCABundle = file
	if got, err := TrustedCAsFor(cfg); err != nil || !bytes.Equal(got, ca.PEM) {
		t.Fatalf("file: %q %v", got, err)
	}
	cfg.OpenShell.TrustedCABundle = file + ".missing"
	if _, err := TrustedCAsFor(cfg); err == nil || !strings.Contains(err.Error(), openshell.TrustedCAKey) {
		t.Fatalf("missing file: %v", err)
	}
	// A managed computer's daemon: only what the gateway relayed counts.
	cfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	cfg.OpenShell.TrustedCABundle = ""
	cfg.OpenShell.TrustedCAPEM = string(ca.PEM)
	if got, err := TrustedCAsFor(cfg); err != nil || !bytes.Equal(got, ca.PEM) {
		t.Fatalf("relayed: %q %v", got, err)
	}
	cfg.OpenShell.TrustedCAError = "openshell.trusted_ca_bundle /etc/corp.pem: writable by group staff"
	if _, err := TrustedCAsFor(cfg); err == nil || !strings.Contains(err.Error(), "writable by group staff") {
		t.Fatalf("relayed error: %v", err)
	}
	cfg.OpenShell.TrustedCAError, cfg.OpenShell.TrustedCAPEM = "", "not pem"
	if _, err := TrustedCAsFor(cfg); err == nil {
		t.Fatal("a relayed bundle that does not parse was accepted")
	}
	// The administrator's own file: absolute, administrator-owned.
	cfg.OpenShell.TrustedCAPEM, cfg.OpenShell.TrustedCABundle = "", "~/corp.pem"
	if _, err := TrustedCAsFor(cfg); err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("managed ~ path: %v", err)
	}
}

// GAP-0192: the build's downloads trust the CAs too. The system store holds
// them, but npm (the pinned Codex install), pip and uv read their own
// roots, so the Dockerfile of an image with CAs points every one of them at
// the system bundle, before any download and for the build only (ARG, never
// ENV); an image without CAs has none of it.
func TestTrustedCAsReachEveryBuildDownload(t *testing.T) {
	for _, name := range []string{"codex", "copilot", "claudecode"} {
		h, ok := harness.Get(name)
		if !ok {
			t.Fatalf("no harness %s", name)
		}
		plain := string(mustContext(t, testSpec(h)).Dockerfile)
		spec := testSpec(h)
		spec.TrustedCAs = openshelltest.NewCA(t, "Corp Inspection Root").PEM
		df := string(mustContext(t, spec).Dockerfile)
		verified := strings.Index(df, "update-ca-certificates did not add")
		first := len(df)
		for _, marker := range []string{"for tool in jq curl", "npm pack", "npm install", "uv tool install", "curl -fsSL"} {
			if i := strings.Index(df, marker); i >= 0 && i < first {
				first = i
			}
		}
		for _, v := range BuildCAEnv {
			arg := "\nARG " + v + "=" + openshell.SandboxSystemCABundle + "\n"
			i := strings.Index(df, arg)
			if i < 0 {
				t.Errorf("%s: Dockerfile lacks %q", name, strings.TrimSpace(arg))
				continue
			}
			if i < verified || i > first {
				t.Errorf("%s: %s is not set between the CA check and the first download:\n%s", name, v, df)
			}
			if strings.Contains(df, "ENV "+v) || strings.Contains(plain, v+"=") {
				t.Errorf("%s: %s is in the image environment or in the image without CAs", name, v)
			}
		}
		if name == "codex" && !strings.Contains(df[first:], "npm pack") {
			t.Fatalf("codex: the npm download is not after the CA ARGs:\n%s", df)
		}
	}
	for _, need := range []string{"NODE_EXTRA_CA_CERTS", "npm_config_cafile", "SSL_CERT_FILE", "PIP_CERT"} {
		if !slices.Contains(BuildCAEnv, need) {
			t.Errorf("BuildCAEnv lacks %s", need)
		}
	}
}
