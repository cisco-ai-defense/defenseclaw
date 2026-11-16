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

package openshell_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

func TestParseTrustedCAsNormalizesAndDedupes(t *testing.T) {
	a := openshelltest.NewCA(t, "Corp Root CA")
	b := openshelltest.NewCA(t, "Corp Issuing CA")
	// CRLF line ends, a comment line between blocks and a repeated root.
	in := append([]byte("# corporate roots\r\n"), bytes.ReplaceAll(a.PEM, []byte("\n"), []byte("\r\n"))...)
	in = append(in, []byte("\n")...)
	in = append(in, b.PEM...)
	in = append(in, a.PEM...)
	cas, err := openshell.ParseTrustedCAs(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := cas.Subjects(); len(got) != 2 || got[0] != "Corp Root CA" || got[1] != "Corp Issuing CA" {
		t.Fatalf("subjects = %v", got)
	}
	if want := append(append([]byte(nil), a.PEM...), b.PEM...); !bytes.Equal(cas.PEM, want) {
		t.Fatalf("PEM is not the normalized bundle:\n%s", cas.PEM)
	}
	if files := cas.Files(); len(files) != 2 || !bytes.Equal(files[0], a.PEM) || !bytes.Equal(files[1], b.PEM) {
		t.Fatalf("files = %q", files)
	}
	if d := cas.Digest(); !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
		t.Fatalf("digest = %q", d)
	}
	if exp := cas.Expired(time.Now()); len(exp) != 0 {
		t.Fatalf("expired = %v", exp)
	}
	if exp := cas.Expired(time.Now().Add(20 * 365 * 24 * time.Hour)); len(exp) != 2 {
		t.Fatalf("expired in 20 years = %v", exp)
	}
}

func TestParseTrustedCAsRefuses(t *testing.T) {
	leaf := openshelltest.NewLeaf(t, openshelltest.NewCA(t, "Corp Root CA"), "proxy.corp.example")
	good := openshelltest.NewCA(t, "Corp Root CA").PEM
	second := openshelltest.NewCA(t, "Corp Issuing CA").PEM
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	truncated := second[:len(second)/2] // a copy cut off mid-certificate: no END line
	badBase64 := []byte("-----BEGIN CERTIFICATE-----\n!!!!not base64!!!!\n-----END CERTIFICATE-----\n")
	brokenKey := []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n") // no END line
	const damaged = "truncated or damaged"
	for name, tc := range map[string]struct {
		in   []byte
		want string
	}{
		"empty":       {nil, "no PEM certificate"},
		"not pem":     {[]byte("hello"), "no PEM certificate"},
		"private key": {[]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), `"PRIVATE KEY"`},
		"bad der":     {[]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), "does not parse"},
		"leaf":        {leaf, "not a CA certificate"},
		"too large":   {bytes.Repeat([]byte(" "), openshell.MaxTrustedCABytes+1), "larger than"},
		// A valid CA followed (or surrounded) by a block that does not
		// decode refuses the whole file, not just the damaged block.
		"valid then truncated cert":     {cat(good, truncated), damaged},
		"valid then bad base64 cert":    {cat(good, badBase64), damaged},
		"valid then broken private key": {cat(good, brokenKey), damaged},
		"damaged between two valid":     {cat(good, badBase64, second), damaged},
		"truncated only":                {truncated, damaged},
		"stray END line":                {cat(good, []byte("-----END CERTIFICATE-----\n")), damaged},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := openshell.ParseTrustedCAs(tc.in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadTrustedCAs(t *testing.T) {
	home := t.TempDir()
	// os.UserHomeDir reads USERPROFILE on Windows and HOME elsewhere.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	ca := openshelltest.NewCA(t, "Corp Root CA")
	file := filepath.Join(home, "corp-root.pem")
	if err := os.WriteFile(file, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if cas, err := openshell.LoadTrustedCAs("", false); err != nil || !cas.Empty() {
		t.Fatalf("empty path: %v %v", cas, err)
	}
	for _, p := range []string{file, "~/corp-root.pem"} {
		cas, err := openshell.LoadTrustedCAs(p, false)
		if err != nil || len(cas.Certs) != 1 {
			t.Fatalf("%s: %v %v", p, cas.Subjects(), err)
		}
	}
	var te *openshell.TrustedCAError
	if _, err := openshell.LoadTrustedCAs("corp-root.pem", false); !errors.As(err, &te) || !strings.Contains(err.Error(), openshell.TrustedCAKey) {
		t.Fatalf("relative path: %v", err)
	}
	if _, err := openshell.LoadTrustedCAs(filepath.Join(home, "missing.pem"), false); !errors.As(err, &te) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := openshell.LoadTrustedCAs(home, false); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory: %v", err)
	}
	// A valid CA then a damaged one: the file is refused, not half loaded.
	partial := filepath.Join(home, "partial.pem")
	next := openshelltest.NewCA(t, "Corp Issuing CA").PEM
	if err := os.WriteFile(partial, append(append([]byte(nil), ca.PEM...), next[:len(next)/2]...), 0o644); err != nil {
		t.Fatal(err)
	}
	if cas, err := openshell.LoadTrustedCAs(partial, false); !errors.As(err, &te) || !strings.Contains(err.Error(), "truncated or damaged") || !cas.Empty() {
		t.Fatalf("valid then truncated: %v %v", cas.Subjects(), err)
	}
	// An administrator's file: absolute, and through the managed trust check.
	if _, err := openshell.LoadTrustedCAs("~/corp-root.pem", true); err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("admin ~ path: %v", err)
	}
	saved := openshell.TrustedCAFileCheck
	t.Cleanup(func() { openshell.TrustedCAFileCheck = saved })
	var checked string
	openshell.TrustedCAFileCheck = func(path, label string) error {
		checked = path
		return errors.New("writable by group staff")
	}
	if _, err := openshell.LoadTrustedCAs(file, true); err == nil || !strings.Contains(err.Error(), "writable by group staff") || checked != file {
		t.Fatalf("admin untrusted file: %v (checked %q)", err, checked)
	}
	openshell.TrustedCAFileCheck = func(string, string) error { return nil }
	if cas, err := openshell.LoadTrustedCAs(file, true); err != nil || len(cas.Certs) != 1 {
		t.Fatalf("admin trusted file: %v", err)
	}
}
