// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSecretToolLookupStoreClear(t *testing.T) {
	var gotArgs []string
	var gotStdin []byte
	exit, stderr, out := 0, "", []byte("  s3cr3t-material \n")
	st := SecretTool{Bin: "/bin/secret-tool", Run: func(_ context.Context, stdin []byte, name string, args ...string) ([]byte, string, int, error) {
		gotArgs, gotStdin = append([]string{name}, args...), stdin
		return out, stderr, exit, nil
	}}
	v, found, err := st.Lookup(context.Background(), "service", "s", "account", "a")
	if err != nil || !found || string(v) != "s3cr3t-material" {
		t.Fatalf("lookup = %q %v %v", v, found, err)
	}
	if strings.Join(gotArgs, " ") != "/bin/secret-tool lookup service s account a" {
		t.Fatalf("argv = %v", gotArgs)
	}
	exit, out = 1, nil
	if _, found, err := st.Lookup(context.Background(), "service", "s"); found || err != nil {
		t.Fatalf("missing = %v %v", found, err)
	}
	exit = 0
	if err := st.Store(context.Background(), "label", []byte("material"), "service", "s"); err != nil {
		t.Fatal(err)
	}
	if string(gotStdin) != "material" || strings.Contains(strings.Join(gotArgs, " "), "material") {
		t.Fatalf("store argv = %v", gotArgs)
	}
	exit, stderr = 1, "Cannot autolaunch D-Bus\nsecond line"
	if err := st.Store(context.Background(), "label", []byte("material"), "service", "s"); err == nil ||
		!strings.Contains(err.Error(), "D-Bus") || strings.Contains(err.Error(), "second line") {
		t.Fatalf("store error = %v", err)
	}
	if err := st.Clear(context.Background(), "service", "s"); err == nil {
		t.Fatal("clear with stderr did not fail")
	}
	exit, stderr = 1, ""
	if err := st.Clear(context.Background(), "service", "s"); err != nil {
		t.Fatalf("clear of a missing item = %v", err)
	}
	broken := SecretTool{Bin: "x", Run: func(context.Context, []byte, string, ...string) ([]byte, string, int, error) {
		return nil, "", -1, errors.New("run x: not found")
	}}
	if _, _, err := broken.Lookup(context.Background()); err == nil {
		t.Fatal("a helper that cannot run did not fail")
	}
}

func TestMacStatusReasonAndFirstLine(t *testing.T) {
	if !strings.Contains(MacStatusReason(StatusInteractionNotAllowed), "locked") ||
		!strings.Contains(MacStatusReason(StatusUserCanceled), "declined") ||
		!strings.Contains(MacStatusReason(-1), "-1") {
		t.Fatal("status reasons")
	}
	if got := FirstLine(" a\x1bb \nc", 160); got != "a b" {
		t.Fatalf("first line = %q", got)
	}
	if got := FirstLine(strings.Repeat("x", 300), 10); len(got) != 10 {
		t.Fatalf("first line = %d", len(got))
	}
}
