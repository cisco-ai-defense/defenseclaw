// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package namespaceinit

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestProofAndSingleNonrootMaps(t *testing.T) {
	p := proof{1000, 1001, [3]identity{{1, 2}, {1, 3}, {1, 4}}}
	got, err := decode(p.encode())
	if err != nil || got != p {
		t.Fatalf("proof roundtrip: %v", err)
	}
	for _, mutation := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:63] },
		func(b []byte) []byte { b[0] = 'X'; return b },
		func(b []byte) []byte { clear(b[8:12]); return b },
		func(b []byte) []byte { clear(b[24:32]); return b },
	} {
		if _, err := decode(mutation(p.encode())); err == nil {
			t.Fatal("malformed proof accepted")
		}
	}
	if !validMap([]byte(" 1000 1000 1\n"), 1000) {
		t.Fatal("exact nonroot map refused")
	}
	for _, mapping := range []string{"0 0 1", "1000 0 1", "1000 1000 2", "1000 1000 1\n1001 1001 1", "1000 1000 1 extra"} {
		if validMap([]byte(mapping), 1000) {
			t.Fatalf("map accepted: %s", mapping)
		}
	}
}

type fakeBootstrap struct {
	seen []string
	fail string
}

func (f *fakeBootstrap) step(s string) error {
	f.seen = append(f.seen, s)
	if f.fail == s {
		return errors.New("fixed refusal")
	}
	return nil
}
func (f *fakeBootstrap) validate() error      { return f.step("identity-and-owner") }
func (f *fakeBootstrap) privateMounts() error { return f.step("private-propagation") }
func (f *fakeBootstrap) mountProc() error     { return f.step("owned-proc") }
func (f *fakeBootstrap) dropCaps() error      { return f.step("all-thread-cap-drop") }
func (f *fakeBootstrap) verify() error        { return f.step("zero-caps-and-pid-view") }

func TestBootstrapStopsBeforeMutationOrReadinessOnEveryFailure(t *testing.T) {
	want := []string{"identity-and-owner", "private-propagation", "owned-proc", "all-thread-cap-drop", "zero-caps-and-pid-view"}
	for i, fail := range want {
		f := &fakeBootstrap{fail: fail}
		if bootstrap(f) == nil || !reflect.DeepEqual(f.seen, want[:i+1]) {
			t.Fatalf("order after %s: %v", fail, f.seen)
		}
	}
	f := &fakeBootstrap{}
	if bootstrap(f) != nil || !reflect.DeepEqual(f.seen, want) {
		t.Fatal("bootstrap ordering differs")
	}
}

func TestNamespaceOwnershipRefusesReusedOrForeignNamespaces(t *testing.T) {
	parent := [3]identity{{1, 2}, {1, 3}, {1, 4}}
	child := [3]identity{{1, 5}, {1, 6}, {1, 7}}
	owners := [2]identity{child[0], child[0]}
	if !validNamespaces(parent, child, owners) {
		t.Fatal("owned fresh namespaces refused")
	}
	for i := range child {
		bad := child
		bad[i] = parent[i]
		if validNamespaces(parent, bad, owners) {
			t.Fatal("parent namespace admitted")
		}
	}
	for i := range owners {
		bad := owners
		bad[i] = parent[0]
		if validNamespaces(parent, child, bad) {
			t.Fatal("foreign namespace owner admitted")
		}
	}
}

func TestEveryThreadStatusRequiresAllFourZeroSetsAndNNP(t *testing.T) {
	status := "Name:\tfixed\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"
	if !zeroThreadStatus([]byte(status)) {
		t.Fatal("zero capability status refused")
	}
	for _, field := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapAmb:"} {
		bad := strings.Replace(status, field+"\t0000000000000000", field+"\t0000000000200000", 1)
		if zeroThreadStatus([]byte(bad)) {
			t.Fatal("thread startup capability survived")
		}
	}
	for _, bad := range []string{strings.Replace(status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), status + "CapEff:\t0\n", strings.Replace(status, "CapAmb:\t0000000000000000\n", "", 1)} {
		if zeroThreadStatus([]byte(bad)) {
			t.Fatal("incomplete or ambiguous cap status accepted")
		}
	}
}
