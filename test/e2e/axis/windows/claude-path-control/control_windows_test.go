// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// These are pure or synthetic filesystem tests. No test calls execute, runCase,
// CreateProcess, the native child, Claude, any SDK or any PSEC API.
func TestClosedSelectorAndSourcePinnedReceipt(t *testing.T) {
	for _, args := range [][]string{nil, {"--run-fixed", "extra"}, {"--run-fixed=true"}, {"--image", "anything"}, {"--run-fixed", "--version"}} {
		if fixedSelector(args) {
			t.Fatalf("accepted nonliteral selector %q", args)
		}
	}
	if !fixedSelector([]string{"--run-fixed"}) {
		t.Fatal("fixed selector refused")
	}
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`{"verified":true,"image":"C:\\arbitrary.exe"}`), []byte(`{"verified":true,"verified":false}`)} {
		if _, err := decodeReceipt(raw); err == nil {
			t.Fatal("unpinned receipt accepted")
		}
	}
	no := false
	value := localReceipt{Schema: "fixed-reviewed-anthropic-claude-version-v1", Verified: true,
		ExecutionPerformed: &no, ProductionQualification: &no, SHA256: imageSHA, Size: imageSize,
		ProductVersion: "2.1.292.0", SignatureStatus: "Valid", SignerOrganization: "Anthropic, PBC",
		SignerThumbprint: "0D7581D2C51C59DF686C3000C70BF543F9F6C6CB"}
	if err := validateMetadata(value); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*localReceipt){
		func(v *localReceipt) { v.SHA256 = strings.Repeat("0", 64) },
		func(v *localReceipt) { v.Size-- }, func(v *localReceipt) { v.ProductVersion = "other" },
		func(v *localReceipt) { v.SignatureStatus = "UnknownError" },
		func(v *localReceipt) { v.ExecutionPerformed = nil },
		func(v *localReceipt) { yes := true; v.ProductionQualification = &yes },
	} {
		copy := value
		mutate(&copy)
		if validateMetadata(copy) == nil {
			t.Fatal("changed fixed image metadata accepted")
		}
	}
}

func TestHeldApplicationSpellingsAndUnchangedLiteralInputs(t *testing.T) {
	guid := `\\?\Volume{12345678-1234-1234-1234-123456789abc}\fixed\claude-reviewed.exe`
	native := `\Device\HarddiskVolume3\fixed\claude-reviewed.exe`
	dos := `\\?\C:\fixed\claude-reviewed.exe`
	got, err := applicationNames(guid, native, dos)
	if err != nil {
		t.Fatal(err)
	}
	want := []application{{"volume_guid", guid}, {"globalroot_native", `\\?\GLOBALROOT` + native}, {"ordinary_dos", `C:\fixed\claude-reviewed.exe`}}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("fixed held spelling derivation differs")
	}
	for _, bad := range [][3]string{{dos, native, dos}, {guid, `\\server\share\child.exe`, dos}, {guid, native, `C:\fixed\claude-reviewed.exe`}, {guid + "\x00", native, dos}} {
		if _, err := applicationNames(bad[0], bad[1], bad[2]); err == nil {
			t.Fatal("unsupported image spelling accepted")
		}
	}
	command, err := fixedCommand(dos)
	if err != nil {
		t.Fatal(err)
	}
	if string(utf16.Decode(command[:len(command)-1])) != `"\\?\C:\fixed\claude-reviewed.exe" "--version"` {
		t.Fatal("fixed SDK literal command encoding differs")
	}
	for _, bad := range []string{"claude.exe", dos + " --other", dos + "\x00"} {
		if _, err := fixedCommand(bad); err == nil {
			t.Fatal("arbitrary literal command accepted")
		}
	}
	block, err := environmentBlock(`\\?\C:\Windows`, `\\?\C:\fixed`)
	if err != nil {
		t.Fatal(err)
	}
	text := string(utf16.Decode(block))
	entries := strings.Split(strings.TrimSuffix(text, "\x00\x00"), "\x00")
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i], _, _ = strings.Cut(entry, "=")
	}
	if !reflect.DeepEqual(names, []string{"APPDATA", "HOME", "LOCALAPPDATA", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "WINDIR"}) || !strings.HasSuffix(text, "\x00\x00") {
		t.Fatal("exact clean sorted eight-entry environment differs")
	}
	if _, err := environmentBlock(`C:\Windows`, `\\?\C:\fixed`); err == nil {
		t.Fatal("noncanonical SystemRoot accepted")
	}
	if _, err := environmentBlock(`\\?\C:\Windows`, "\\\\?\\C:\\fixed\x00PATH=bad"); err == nil {
		t.Fatal("environment injection accepted")
	}
}

func TestCreatedImageMustBindBeforeResume(t *testing.T) {
	for fail := range 4 {
		var events []int
		step := func(index int) func() error {
			return func() error {
				events = append(events, index)
				if index == fail {
					return errors.New("fixed synthetic refusal")
				}
				return nil
			}
		}
		err := admitBeforeResume(step(1), step(2), step(3))
		want := []int{1, 2, 3}
		if fail != 0 {
			want = want[:fail]
		}
		if (err != nil) != (fail != 0) || !reflect.DeepEqual(events, want) {
			t.Fatalf("admission sequence %v, fail %d, err %v", events, fail, err)
		}
	}
}

func TestAggregateBudgetAcrossBothStreamsAndCases(t *testing.T) {
	b := &budget{}
	if !b.admit(outputBound-1) || !b.admit(1) || b.admit(1) || !b.exceeded() {
		t.Fatal("aggregate output limit not exact")
	}
	if (&budget{}).admit(-1) {
		t.Fatal("negative byte count accepted")
	}
}

func TestNativeSyntheticBlockedPipeCloseJoinsReader(t *testing.T) {
	pipe, err := newPipes()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.closeChildren()
	defer pipe.readers[1].Close()
	done := make(chan streamResult, 1)
	go drain(pipe.readers[0], &budget{}, done)
	// Its owned writer remains open and writes nothing, so no EOF/read result
	// can complete before cancellation. No child or native launch is involved.
	_, joined, closed, err := finishStream(pipe.readers[0], done, 5*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "completion deadline") || !joined || !closed {
		t.Fatalf("timeout must fail but cancel/join its exact reader: joined=%v closed=%v err=%v", joined, closed, err)
	}
}

func TestNativeSyntheticDirectoryAndImageCustody(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "owned")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	file, err := openPinned(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(directory, directory+"-moved"); err == nil {
		_ = file.Close()
		t.Fatal("held list-directory pin allowed rename")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(directory, directory+"-moved"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "public-synthetic-image.bin")
	if err := os.WriteFile(path, []byte("fixed-public"), 0600); err != nil {
		t.Fatal(err)
	}
	held, err := openPinned(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	duplicate, err := openPinned(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer duplicate.Close()
	if err := sameIdentity(held, duplicate); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err == nil {
		t.Fatal("read-only pin allowed writes")
	}
	other := filepath.Join(base, "other.bin")
	if err := os.WriteFile(other, []byte("fixed-public"), 0600); err != nil {
		t.Fatal(err)
	}
	different, err := openPinned(other, false)
	if err != nil {
		t.Fatal(err)
	}
	defer different.Close()
	if sameIdentity(held, different) == nil {
		t.Fatal("identical bytes in different object admitted")
	}
	if err := readFixed(held, 12, digest([]byte("fixed-public"))); err != nil {
		t.Fatal(err)
	}
	if readFixed(held, 13, digest([]byte("fixed-public"))) == nil {
		t.Fatal("wrong input length admitted")
	}
}
