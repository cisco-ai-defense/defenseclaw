// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// restoredElementsIf is what a stubbed worker answers when it stands for a
// repair that put the hook entry back.
func restoredElementsIf(restored bool) []string {
	if restored {
		return entryElement
	}
	return nil
}

var (
	entryElement   = []string{enterprisehooks.HookElementEntry}
	runtimeElement = []string{enterprisehooks.HookElementRuntime}
)

// GAP-0754: the parent reads the progress lines of a worker while the worker
// still writes them, so the output may end in the middle of a line.
func TestParseEnterpriseHookWorkerOutputReadsProgressThenAnswer(t *testing.T) {
	var out bytes.Buffer
	writer := &enterpriseHookWorkerProgressWriter{out: &out}
	writer.begin(enterpriseHookWorkerTarget{Index: 4}, entryElement)
	writer.end(enterpriseHookWorkerTargetResult{Index: 4, OK: true, Repaired: true, RestoredElements: entryElement})
	writer.begin(enterpriseHookWorkerTarget{Index: 5}, runtimeElement)
	got := parseEnterpriseHookWorkerOutput(out.Bytes())
	if got.answered || got.repairing != 1 || len(got.repaired) != 1 || got.repaired[0].Index != 4 ||
		!slices.Equal(got.repaired[0].RestoredElements, entryElement) || !slices.Equal(got.unfinished[5], runtimeElement) {
		t.Fatalf("output = %+v, want one repair under way and target 4 kept", got)
	}
	writer.end(enterpriseHookWorkerTargetResult{Index: 5, OK: true}) // nothing rewritten: nothing to keep
	fmt.Fprintf(&out, `{"version":%d,"targets":[{"index":4,"ok":true,"repaired":true}]}`+"\n", enterpriseHookWorkerProtocolVersion)
	got = parseEnterpriseHookWorkerOutput(out.Bytes())
	if !got.answered || got.repairing != 0 || len(got.response.Targets) != 1 {
		t.Fatalf("output = %+v, want the answer after two ended repairs", got)
	}
}

func TestParseEnterpriseHookWorkerOutputIgnoresACutLine(t *testing.T) {
	var out bytes.Buffer
	writer := &enterpriseHookWorkerProgressWriter{out: &out}
	writer.begin(enterpriseHookWorkerTarget{Index: 2}, entryElement)
	writer.end(enterpriseHookWorkerTargetResult{Index: 2, OK: true, Repaired: true, RestoredElements: entryElement})
	cut := out.Len()
	writer.begin(enterpriseHookWorkerTarget{Index: 3}, entryElement)
	got := parseEnterpriseHookWorkerOutput(out.Bytes()[:out.Len()-3])
	if got.repairing != 0 || len(got.repaired) != 1 || got.repaired[0].Index != 2 || len(got.unfinished) != 0 || got.err == nil {
		t.Fatalf("output cut at %d = %+v, want the complete lines only", cut, got)
	}
}

// A repair that began and has no end line is a target under repair, never a
// healthy one: the parse keeps only what the worker ended, and names the
// repairs that began with a protected element broken (a configuration-only
// repair, or one that found every element in order, has no restore to look
// for).
func TestParseEnterpriseHookWorkerOutputNamesUnfinishedRestoresWithoutKeepingThem(t *testing.T) {
	var out bytes.Buffer
	writer := &enterpriseHookWorkerProgressWriter{out: &out}
	writer.begin(enterpriseHookWorkerTarget{Index: 1}, nil) // configuration only
	writer.begin(enterpriseHookWorkerTarget{Index: 2}, entryElement)
	writer.end(enterpriseHookWorkerTargetResult{Index: 2, Error: "failed"}) // ended without a restore
	writer.begin(enterpriseHookWorkerTarget{Index: 3}, []string{enterprisehooks.HookElementEntry, enterprisehooks.HookElementRuntime})
	got := parseEnterpriseHookWorkerOutput(out.Bytes())
	if got.repairing != 2 || len(got.repaired) != 0 || len(got.unfinished) != 1 || len(got.unfinished[3]) != 2 {
		t.Fatalf("output = %+v, want two repairs under way, none kept, the elements named for 3 only", got)
	}
}

// The evidence of a restore is the element: one that did not match and matches
// now. An element that matched all along, one that is still broken and a name
// the guardian does not know are not restores.
func TestRestoredHookElementsAreTheOnesThatWentFromBrokenToMatching(t *testing.T) {
	both := []string{enterprisehooks.HookElementEntry, enterprisehooks.HookElementRuntime}
	script := "hook runtime file hermes-hook.sh"
	record := "hook runtime file .hookcfg.hermes"
	for _, tc := range []struct {
		name   string
		broken []string
		after  enterprisehooks.HookElements
		want   []string
	}{
		{"both back", both, enterprisehooks.HookElements{Entry: true}, both},
		{"only the runtime back", both, enterprisehooks.HookElements{}, runtimeElement},
		{"only the entry back", both, enterprisehooks.HookElements{Entry: true, BrokenRuntime: runtimeElement}, entryElement},
		{"still broken", both, enterprisehooks.HookElements{BrokenRuntime: runtimeElement}, nil},
		{"was not broken", runtimeElement, enterprisehooks.HookElements{Entry: true, BrokenRuntime: runtimeElement}, nil},
		{"unknown name", []string{"shared agent config"}, enterprisehooks.HookElements{Entry: true}, nil},
		{"a name that is no file", []string{"hook runtime file ../escape", "hook runtime file "}, enterprisehooks.HookElements{Entry: true}, nil},
		// The script is its own element: putting it back counts while another
		// runtime file is still broken (GAP-0754).
		{"script back, record still broken", []string{script, record}, enterprisehooks.HookElements{Entry: true, BrokenRuntime: []string{record}}, []string{script}},
		// The lock stays missing (the aggregate stays broken) while the script
		// is put back: the script alone is the restore.
		{"script back, lock still missing", []string{enterprisehooks.HookElementRuntime, script}, enterprisehooks.HookElements{Entry: true, BrokenRuntime: runtimeElement}, []string{script}},
		{"record back, script still broken", []string{script, record}, enterprisehooks.HookElements{Entry: true, BrokenRuntime: []string{script}}, []string{record}},
	} {
		if got := restoredHookElements(tc.broken, tc.after); !slices.Equal(got, tc.want) {
			t.Errorf("%s: restored = %v, want %v", tc.name, got, tc.want)
		}
	}
	if got, _ := knownEnterpriseHookElements([]string{"made up", enterprisehooks.HookElementEntry, enterprisehooks.HookElementEntry}, nil); !slices.Equal(got, entryElement) {
		t.Errorf("known elements = %v, want the entry once", got)
	}
}

// A writer the parent did not ask for drops everything.
func TestEnterpriseHookWorkerProgressWriterIsNilSafe(t *testing.T) {
	var writer *enterpriseHookWorkerProgressWriter
	writer.begin(enterpriseHookWorkerTarget{Index: 1}, entryElement)
	writer.end(enterpriseHookWorkerTargetResult{Index: 1, OK: true, Repaired: true})
}
