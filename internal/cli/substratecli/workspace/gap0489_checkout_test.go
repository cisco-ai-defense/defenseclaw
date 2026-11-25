// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gap0489Filter is a stand-in for a git-lfs filter: the commit holds the
// pointer (upper case), a checkout writes the content (lower case).
var gap0489Filter = []string{"-c", "filter.fakelfs.clean=tr a-z A-Z", "-c", "filter.fakelfs.smudge=tr A-Z a-z"}

// gap0489Recheckout writes paths again from the index, as a checkout does.
func gap0489Recheckout(t *testing.T, o *hcEnv, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.Remove(filepath.Join(o.project, p)); err != nil {
			t.Fatal(err)
		}
	}
	o.git(o.project, append([]string{"checkout", "--"}, paths...)...)
}

// substrate-1 GAP-0489 (RV-T6B): the second computer's baseline is HEAD as a
// checkout there writes it, line endings (eol=crlf, core.autocrlf) and filter
// drivers (git-lfs smudge) included: the folder the person sent held
// work-tree bytes. Before, the raw blobs were the baseline, so every such
// file showed as modified (and --apply fell back to a patch file, --branch
// committed the churn).
func TestGAP0489BaselineIsTheCheckoutHere(t *testing.T) {
	old := hostCopy
	hostCopy = true
	t.Cleanup(func() { hostCopy = old })
	o := newHCEnv(t)
	o.git(o.project, "init", "-q", "-b", "main")
	o.git(o.project, "config", "core.autocrlf", "true")
	for i := 0; i < len(gap0489Filter); i += 2 {
		k, v, _ := strings.Cut(gap0489Filter[i+1], "=")
		o.git(o.project, "config", k, v)
	}
	hcWrite(t, o.project, ".gitattributes", "crlf.txt text eol=crlf\n*.fl filter=fakelfs\n")
	hcWrite(t, o.project, "crlf.txt", "one\ntwo\n")
	hcWrite(t, o.project, "auto.txt", "three\nfour\n")
	hcWrite(t, o.project, "model.fl", "real content\n")
	hcWrite(t, o.project, "README.md", "line one\n")
	gap0489Commit(o)
	// The first computer's folder, as a checkout writes it.
	gap0489Recheckout(t, o, ".gitattributes", "crlf.txt", "auto.txt", "model.fl", "README.md")
	if b, _ := os.ReadFile(filepath.Join(o.project, "crlf.txt")); string(b) != "one\r\ntwo\r\n" {
		t.Fatalf("the fixture's checkout of crlf.txt is %q", b)
	}
	if b := o.git(o.project, "cat-file", "-p", "HEAD:model.fl"); b != "REAL CONTENT\n" {
		t.Fatalf("the fixture's commit of model.fl is %q", b)
	}

	workdir, c := hcActor(t)
	ctx := context.Background()
	if _, err := Start(ctx, StartOptions{Transport: c, Project: o.project, Name: "w1", DataDir: o.data, Home: o.home}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	hcWrite(t, filepath.Join(workdir, "myapp"), "README.md", "line one\r\nline two by the agent\r\n")
	hostCopy = old
	second := filepath.Join(t.TempDir(), "laptop2")
	clone := filepath.Join(second, "myapp")
	o.git(filepath.Dir(o.project), append(append([]string{"clone", "-q", "-c", "core.autocrlf=true"}, gap0489Filter...), o.project, clone)...)
	rv, err := Pull(ctx, PullOptions{Exec: c, DataDir: filepath.Join(second, "data"), Name: "w1", Project: clone, ExcludesStated: true})
	if err != nil {
		t.Fatalf("pull on the second computer: %v", err)
	}
	if len(rv.Changed) != 1 || rv.Changed[0].Path != "README.md" || rv.Changed[0].Status != "modified" {
		t.Fatalf("changed %+v, want only README.md modified (review %q)", rv.Changed, rv.Text)
	}
}

// substrate-1 GAP-0489 (RV-T6B P4): the same --exclude set in another order
// keeps the record adopted before. Before, the order counted, so a pull
// with the masks reordered adopted HEAD again and lost what an apply had
// brought back.
func TestGAP0489ExcludeOrderKeepsTheRecord(t *testing.T) {
	old := hostCopy
	hostCopy = true
	t.Cleanup(func() { hostCopy = old })
	o := newHCEnv(t)
	o.git(o.project, "init", "-q", "-b", "main")
	hcWrite(t, o.project, "README.md", "line one\n")
	hcWrite(t, o.project, "a/x.txt", "a\n")
	hcWrite(t, o.project, "b/y.txt", "b\n")
	gap0489Commit(o)
	_, c := hcActor(t)
	ctx := context.Background()
	if _, err := Start(ctx, StartOptions{Transport: c, Project: o.project, Name: "w1", DataDir: o.data, Home: o.home, Masks: []string{"a/x.txt", "b/y.txt"}}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	hostCopy = old
	clone, data2 := gap0489Second(t, o)
	pull := func(masks ...string) *hostRecord {
		t.Helper()
		if _, err := Pull(ctx, PullOptions{Exec: c, DataDir: data2, Name: "w1", Project: clone, Exclude: masks, ExcludesStated: true}); err != nil {
			t.Fatalf("pull --exclude %v: %v", masks, err)
		}
		rec, err := loadHostRecord(data2, "w1")
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	first := pull("b/y.txt", "a/x.txt", "b/y.txt")
	time.Sleep(10 * time.Millisecond)
	second := pull("a/x.txt", "b/y.txt")
	if !second.UploadedAt.Equal(first.UploadedAt) || second.Baseline != first.Baseline {
		t.Fatalf("the same --exclude set in another order adopted HEAD again (record %v, then %v)", first.UploadedAt, second.UploadedAt)
	}
	if len(second.Masks) != 2 || second.Masks[0] != "a/x.txt" || second.Masks[1] != "b/y.txt" {
		t.Fatalf("stored masks %v, want them sorted and without repeats", second.Masks)
	}
}
