// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// A reading is a copy that opens no source only when the source operand is
// the empty string and every word before it is an option that takes no value
// (rel-1-0-6:GAP-0880, GAP-0885).
func TestCopyOpensNoSourceNeedsAnEmptySourceAndValuelessOptions(t *testing.T) {
	t.Setenv("BASH_ENV", "")
	t.Setenv("ENV", "")
	for _, row := range []struct {
		reading string
		want    bool
	}{
		{`cp '' keylink`, true},
		{`cp "" keylink`, true},
		{`gcp '' keylink`, true},
		{`cp -f '' keylink`, true},
		{`cp -- '' keylink`, true},
		{`cp -aR '' keylink`, true},
		{`cp a.txt keylink`, false},
		{`cp '-' keylink`, false},
		{`cp -t keylink ''`, false},
		{`cp -S '' x keylink`, false},
		{`cp --target-directory=d '' keylink`, false},
		{`mv '' keylink`, false},
		{`cp '' keylink; echo`, false},
		{`cp '' keylink > out`, false},
		{`cp '' keylink &`, false},
		{`cp '' b keylink`, false},
		{`X=1 cp '' keylink`, false},
	} {
		if got := copyOpensNoSource(row.reading, "/h"); got != row.want {
			t.Errorf("copyOpensNoSource(%q) = %v, want %v", row.reading, got, row.want)
		}
	}
	t.Setenv("BASH_ENV", "/h/startup.sh")
	if copyOpensNoSource(`cp '' keylink`, "/h") {
		t.Error("a startup file can redefine cp: the copy is not proved to open no source")
	}
}
