// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// anchorsDoc is a bundle-anchors.json with keys given as "id:status"; k1
// is the host's signing key, any other id a fresh key.
func anchorsDoc(t *testing.T, b *bundleHost, keys ...string) string {
	t.Helper()
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		id, status, _ := strings.Cut(k, ":")
		public := b.key.Public()
		if id != "k1" {
			other, _, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			public = other
		}
		spki, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, fmt.Sprintf(`{"key_id":%q,"alg":"ed25519","public_key":%q,"not_before":"2020-01-01T00:00:00Z","not_after":"2099-01-01T00:00:00Z","status":%q}`,
			id, base64.StdEncoding.EncodeToString(spki), status))
	}
	return fmt.Sprintf(`{"schema_version":1,"tenant_id":"acme","device_groups":[],"min_version":0,"keys":[%s]}`, strings.Join(parts, ","))
}

// agentAnchors writes content where a management agent keeps the anchor
// file it downloaded, a folder of its own, and returns the file and the
// test folder above it.
func agentAnchors(t *testing.T, content string) (path, base string) {
	t.Helper()
	base = t.TempDir()
	dir := filepath.Join(base, "agent", "trust")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, enterprisebundle.AnchorsName)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, base
}

// modeTrust stands in for the managed trust check without its root-owner
// part (the tests do not run as root): the path and every folder above it,
// up to one of roots, must not be a link or writable by group or other.
func modeTrust(roots ...string) func(string, TrustKind) error {
	return func(path string, _ TrustKind) error {
		for p := path; ; p = filepath.Dir(p) {
			info, err := os.Lstat(p)
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%s: symlinks are not allowed in managed file path", p)
			}
			if info.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("%s: group/other writable permissions %04o are not trusted", p, info.Mode().Perm())
			}
			if slices.Contains(roots, p) || filepath.Dir(p) == p {
				return nil
			}
		}
	}
}

func newAnchorsHost(t *testing.T) (*bundleHost, string) {
	t.Helper()
	b := newBundleHost(t)
	b.env.LockTimeout, b.env.PollInterval = 100*time.Millisecond, 10*time.Millisecond
	return b, b.env.bundleAnchorsPath()
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// A management agent replaces the trust anchors: the installed file is the
// validated bytes, root-owned 0644, and the result names its digest, the
// digest it replaced, its keys and the signer of the confirmed bundle (for
// the key_unknown / key_revoked warning). The same bytes again write
// nothing.
func TestInstallBundleAnchorsReplacesTheFileAndReportsIt(t *testing.T) {
	b, dest := newAnchorsHost(t)
	v1, _, _ := bundleConfigs(b.testHost)
	b.mapPromotedBundleOwners(1)
	requireOK(t, b.apply(b.dir(1, v1)))
	before := readFile(t, dest)
	doc := anchorsDoc(t, b, "k1:active", "k2:active")
	src, base := agentAnchors(t, doc)
	b.env.Trust = modeTrust(base, b.env.Root)

	out, err := b.env.InstallBundleAnchors(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	info, statErr := os.Stat(dest)
	if out.Result != AnchorsReplaced || readFile(t, dest) != doc || out.SHA256 != sha256Bytes([]byte(doc)) ||
		out.PreviousSHA256 != sha256Bytes([]byte(before)) || out.SignerKeyID != "k1" ||
		out.Path != filepath.Join(b.env.Layout.ConfigDir, "trust", enterprisebundle.AnchorsName) ||
		out.Anchors == nil || len(out.Anchors.Keys) != 2 || out.Anchors.Keys[1].KeyID != "k2" {
		t.Fatalf("install = %+v", out)
	}
	if statErr != nil || info.Mode().Perm() != 0o644 || b.owners[dest] != [2]int{0, 0} {
		t.Fatalf("installed file mode %v owner %v: %v", info.Mode(), b.owners[dest], statErr)
	}
	if dir, err := os.Stat(filepath.Dir(dest)); err != nil || dir.Mode().Perm() != 0o755 {
		t.Fatalf("trust folder: %v, %v", dir, err)
	}

	again, err := b.env.InstallBundleAnchors(context.Background(), src)
	if err != nil || again.Result != AnchorsUnchanged || again.PreviousSHA256 != "" || again.SHA256 != out.SHA256 {
		t.Fatalf("same bytes again = %+v, %v", again, err)
	}
}

// The first anchor file turns bundle mode on; there is nothing it replaced
// and no confirmed signer yet.
func TestInstallBundleAnchorsInstallsTheFirstFile(t *testing.T) {
	b, dest := newAnchorsHost(t)
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	doc := anchorsDoc(t, b, "k1:active")
	src, base := agentAnchors(t, doc)
	b.env.Trust = modeTrust(base, b.env.Root)
	out, err := b.env.InstallBundleAnchors(context.Background(), src)
	if err != nil || out.Result != AnchorsInstalled || out.PreviousSHA256 != "" || out.SignerKeyID != "" || readFile(t, dest) != doc || !b.env.bundleMode() {
		t.Fatalf("first install = %+v, %v", out, err)
	}
}

// A source that is not a valid anchor file, or that an account other than
// root could have written or swapped (the file or a folder above it is
// group or other writable, or a link), is refused and the installed file
// stays byte for byte.
func TestInstallBundleAnchorsRefusesUntrustedOrInvalidSources(t *testing.T) {
	b, dest := newAnchorsHost(t)
	doc := anchorsDoc(t, b, "k1:active", "k2:active")
	before := readFile(t, dest)
	cases := map[string]struct {
		setup func(t *testing.T) (src, base string)
		code  enterprisebundle.Code
	}{
		"invalid": {func(t *testing.T) (string, string) { return agentAnchors(t, "{") }, enterprisebundle.CodeAnchorInvalid},
		"unknown field": {func(t *testing.T) (string, string) {
			return agentAnchors(t, strings.Replace(doc, `"min_version"`, `"floor":1,"min_version"`, 1))
		}, enterprisebundle.CodeAnchorInvalid},
		"byte-order mark": {func(t *testing.T) (string, string) { return agentAnchors(t, "\xef\xbb\xbf"+doc) }, enterprisebundle.CodeAnchorInvalid},
		"missing": {func(t *testing.T) (string, string) {
			base := t.TempDir()
			return filepath.Join(base, "absent.json"), base
		}, enterprisebundle.CodeAnchorMissing},
		"group-writable file": {func(t *testing.T) (string, string) {
			src, base := agentAnchors(t, doc)
			if err := os.Chmod(src, 0o664); err != nil {
				t.Fatal(err)
			}
			return src, base
		}, enterprisebundle.CodeAnchorInsecure},
		"group-writable folder": {func(t *testing.T) (string, string) {
			src, base := agentAnchors(t, doc)
			if err := os.Chmod(filepath.Dir(src), 0o775); err != nil {
				t.Fatal(err)
			}
			return src, base
		}, enterprisebundle.CodeAnchorInsecure},
		"symlinked file": {func(t *testing.T) (string, string) {
			src, base := agentAnchors(t, doc)
			link := filepath.Join(filepath.Dir(src), "link.json")
			if err := os.Symlink(src, link); err != nil {
				t.Fatal(err)
			}
			return link, base
		}, enterprisebundle.CodeAnchorInsecure},
		"symlinked folder": {func(t *testing.T) (string, string) {
			src, base := agentAnchors(t, doc)
			link := filepath.Join(base, "linked")
			if err := os.Symlink(filepath.Dir(src), link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, enterprisebundle.AnchorsName), base
		}, enterprisebundle.CodeAnchorInsecure},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			src, base := tc.setup(t)
			b.env.Trust = modeTrust(base, b.env.Root)
			out, err := b.env.InstallBundleAnchors(context.Background(), src)
			if enterprisebundle.CodeOf(err) != tc.code {
				t.Fatalf("error = %v, want %s", err, tc.code)
			}
			if readFile(t, dest) != before || out == nil || out.SHA256 != sha256Bytes([]byte(before)) {
				t.Fatalf("installed file changed or not reported: %+v", out)
			}
		})
	}
}

// The source is read once: the bytes installed are the bytes validated,
// even when the source changes between the read and the write.
func TestInstallBundleAnchorsWritesTheBytesItValidated(t *testing.T) {
	b, dest := newAnchorsHost(t)
	doc := anchorsDoc(t, b, "k1:active", "k2:active")
	src, base := agentAnchors(t, doc)
	b.env.Trust = modeTrust(base, b.env.Root)
	lchown := b.env.Lchown
	b.env.Lchown = func(path string, uid, gid int) error {
		if path == filepath.Dir(dest) {
			if err := os.WriteFile(src, []byte(anchorsDoc(t, b, "k3:active")), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return lchown(path, uid, gid)
	}
	if _, err := b.env.InstallBundleAnchors(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	if readFile(t, dest) != doc {
		t.Fatal("the installed file is not the validated source")
	}
}

// A source replaced while it was opened (after the trust check) is refused.
func TestInstallBundleAnchorsRefusesASourceReplacedWhileRead(t *testing.T) {
	b, dest := newAnchorsHost(t)
	before := readFile(t, dest)
	src, base := agentAnchors(t, anchorsDoc(t, b, "k1:active"))
	check := modeTrust(base, b.env.Root)
	b.env.Trust = func(path string, kind TrustKind) error {
		if err := check(path, kind); err != nil || path != src {
			return err
		}
		other := src + ".other"
		if err := os.WriteFile(other, []byte(anchorsDoc(t, b, "k9:active")), 0o600); err != nil {
			t.Fatal(err)
		}
		return os.Rename(other, src)
	}
	if _, err := b.env.InstallBundleAnchors(context.Background(), src); enterprisebundle.CodeOf(err) != enterprisebundle.CodeAnchorInsecure {
		t.Fatalf("swapped source: %v", err)
	}
	if readFile(t, dest) != before {
		t.Fatal("the installed file changed")
	}
}

// When the installed file fails its check after the write, the previous
// file is put back, or removed when there was none.
func TestInstallBundleAnchorsPutsThePreviousFileBack(t *testing.T) {
	for _, hadFile := range []bool{true, false} {
		t.Run(fmt.Sprintf("previous file %v", hadFile), func(t *testing.T) {
			b, dest := newAnchorsHost(t)
			before := readFile(t, dest)
			if !hadFile {
				if err := os.Remove(dest); err != nil {
					t.Fatal(err)
				}
			}
			doc := anchorsDoc(t, b, "k1:active", "k2:active")
			src, base := agentAnchors(t, doc)
			check := modeTrust(base, b.env.Root)
			b.env.Trust = func(path string, kind TrustKind) error {
				if raw, err := os.ReadFile(path); err == nil && path == dest && string(raw) == doc {
					return fmt.Errorf("%s: owner uid 1000 is not trusted", path)
				}
				return check(path, kind)
			}
			out, err := b.env.InstallBundleAnchors(context.Background(), src)
			if enterprisebundle.CodeOf(err) != enterprisebundle.CodeAnchorInsecure {
				t.Fatalf("failed post-check: %v", err)
			}
			raw, readErr := os.ReadFile(dest)
			if hadFile && (readErr != nil || string(raw) != before) {
				t.Fatalf("previous file not put back: %q, %v", raw, readErr)
			}
			if !hadFile && !os.IsNotExist(readErr) {
				t.Fatalf("new file left in place: %v", readErr)
			}
			// The result names the file still installed: the previous one,
			// or none, never the refused file.
			want := ""
			if hadFile {
				want = sha256Bytes([]byte(before))
			}
			if out == nil || out.SHA256 != want || out.Anchors != nil || out.Result != "" {
				t.Fatalf("refused install result = %+v, want sha256 %q only", out, want)
			}
		})
	}
}

// The install takes the lifecycle lock: another run holding it is
// lifecycle_busy and nothing is written. An installed path that is not a
// regular file is refused, never followed.
func TestInstallBundleAnchorsRefusesWhileBusyOrOverALink(t *testing.T) {
	b, dest := newAnchorsHost(t)
	before := readFile(t, dest)
	src, base := agentAnchors(t, anchorsDoc(t, b, "k1:active", "k2:active"))
	b.env.Trust = modeTrust(base, b.env.Root)
	lock, err := b.env.acquireLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.env.InstallBundleAnchors(context.Background(), src)
	lock.release()
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeLifecycleBusy || readFile(t, dest) != before {
		t.Fatalf("busy: %v", err)
	}

	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := b.env.InstallBundleAnchors(context.Background(), src); enterprisebundle.CodeOf(err) != enterprisebundle.CodeAnchorInsecure {
		t.Fatalf("installed link: %v", err)
	}
	if info, err := os.Lstat(dest); err != nil || info.Mode()&os.ModeSymlink == 0 || readFile(t, target) != before {
		t.Fatal("the link or its target changed")
	}
}

// Only root installs anchors, and nothing is read before that check.
func TestInstallBundleAnchorsNeedsRoot(t *testing.T) {
	b, _ := newAnchorsHost(t)
	b.env.Geteuid = func() int { return 1000 }
	b.env.Trust = func(path string, _ TrustKind) error { t.Fatalf("checked %s before the root check", path); return nil }
	if _, err := b.env.InstallBundleAnchors(context.Background(), "/nonexistent"); enterprisebundle.CodeOf(err) != codeNotRoot {
		t.Fatalf("not root: %v", err)
	}
}
