// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

func syntheticReceipt(t *testing.T) (string, reviewedPins) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pins := reviewed246
	pins.Images = slices.Clone(pins.Images)
	for i := range pins.Images {
		data := []byte("fixed synthetic non-executable image " + pins.Images[i].Path)
		pins.Images[i].SHA, pins.Images[i].Size = digest(data), int64(len(data))
		name := filepath.Join(root, filepath.FromSlash(pins.Images[i].Path))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	source := []byte("fixed synthetic source; never compiled")
	pins.Source = digest(source)
	name := filepath.Join(root, filepath.FromSlash(sourceName))
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, source, 0600); err != nil {
		t.Fatal(err)
	}
	no := false
	value := verificationReceipt{Verified: true, Executed: &no, Certified: &no,
		Scope: "fixed_windows_native_psec_boundary_literal_argv", Variant: "standalone_std_boundary_literal_argv",
		Axis: "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c", MXC: "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2",
		Commit: pins.Commit, Run: pins.Run, ArtifactID: pins.ArtifactID, Archive: pins.Archive, Provenance: pins.Provenance,
		Lock: "3b29ecb06dd2a81266c84712f8d6e088605290f386e87498bb7a7472a005af69", Artifact: root,
		Binary: parentName, BinarySHA: pins.Images[0].SHA, BinarySize: pins.Images[0].Size, Binaries: pins.Images}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "receipt.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	pins.Receipt = digest(data)
	return path, pins
}

func TestDefaultAndUnknownSelectorsNeverReachFilesystemOrProcess(t *testing.T) {
	for _, args := range [][]string{nil, {"--run-fixed"}, {"--run-fixed", "--receipt", "missing", "--evidence", "missing", "arbitrary"}, {"--run-fixed", "--command", "anything"}} {
		record, err := execute(args)
		if err == nil || record["execution_performed"] != false || record["passed"] != false {
			t.Fatal("non-explicit control was admitted")
		}
	}
}

func TestReceiptPinsEveryImageAndSourceWithoutExecuting(t *testing.T) {
	path, pins := syntheticReceipt(t)
	value, held, err := checkReceipt(path, pins)
	if err != nil {
		t.Fatal(err)
	}
	defer held.close()
	for _, name := range []string{parentName, loaderName, childName, sourceName} {
		file, err := os.OpenFile(filepath.Join(value.Artifact, filepath.FromSlash(name)), os.O_WRONLY, 0)
		if err == nil {
			file.Close()
			t.Fatal("reviewed image/source writable while pinned")
		}
	}
}

func TestReceiptAndComponentTamperingRefuseBeforeExecution(t *testing.T) {
	for _, kind := range []string{"receipt", "image", "source", "inventory", "unknown", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			path, pins := syntheticReceipt(t)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var value verificationReceipt
			if err := json.Unmarshal(data, &value); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "receipt":
				data = append(data, ' ')
			case "image", "source":
				name := childName
				if kind == "source" {
					name = sourceName
				}
				if err := os.WriteFile(filepath.Join(value.Artifact, filepath.FromSlash(name)), []byte("tampered fixed synthetic bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			case "inventory":
				value.Binaries = value.Binaries[:2]
				data, err = json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				pins.Receipt = digest(data)
			case "unknown":
				data = append([]byte(`{"unexpected":true,`), data[1:]...)
				pins.Receipt = digest(data)
			case "trailing":
				data = append(data, []byte("\n{}")...)
				pins.Receipt = digest(data)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, held, err := checkReceipt(path, pins); err == nil {
				held.close()
				t.Fatal("tampered verification admitted")
			}
		})
	}
}

func TestFixedEnvironmentHasExactlyEightDerivedEntries(t *testing.T) {
	t.Setenv("PATH", "fixed caller PATH must not be forwarded")
	t.Setenv("OPENAI_API_KEY", "fixed public synthetic marker")
	root, system := `\\?\C:\fixed-fixture`, `\\?\C:\Windows`
	got := fixedEnvironment(root, system)
	want := []string{
		`APPDATA=\\?\C:\fixed-fixture\home\AppData\Roaming`, `HOME=\\?\C:\fixed-fixture\home`,
		`LOCALAPPDATA=\\?\C:\fixed-fixture\home\AppData\Local`, `SYSTEMROOT=\\?\C:\Windows`,
		`TEMP=\\?\C:\fixed-fixture\tmp`, `TMP=\\?\C:\fixed-fixture\tmp`,
		`USERPROFILE=\\?\C:\fixed-fixture\home`, `WINDIR=\\?\C:\Windows`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("fixed explicit environment differs")
	}
}

func TestBoundedCaptureAndExactLateFailure(t *testing.T) {
	var b boundedOutput
	large := bytes.Repeat([]byte{'x'}, outputLimit+100)
	if n, err := b.Write(large); err != nil || n != len(large) || !b.overflow || len(b.data) != outputLimit {
		t.Fatal("capture was not bounded and drained")
	}
	good := "FIXED_CANONICALIZE result=ok\nfixed child failed: outside read was not denied\n"
	if !expectedTranscript(nil, []byte(good)) || !expectedTranscript(nil, []byte(strings.ReplaceAll(good, "\n", "\r\n"))) {
		t.Fatal("exact late control failure refused")
	}
	for _, stderr := range []string{good + "unexpected\n", strings.ReplaceAll(good, "outside read was not denied", "private environment differs"), "", "FIXED_BOUNDARIES_PASS\n"} {
		if expectedTranscript(nil, []byte(stderr)) {
			t.Fatal("different or incomplete child progression accepted")
		}
	}
	if expectedTranscript([]byte("unexpected"), []byte(good)) {
		t.Fatal("unexpected stdout accepted")
	}
	if cleanExitOne(errors.Join(&exec.ExitError{}, errors.New("owned Job cleanup failed"))) || cleanExitOne(nil) {
		t.Fatal("joined cleanup failure accepted as clean expected exit")
	}
}

func TestFreshFixturePreservesSentinelsAndRefusesReuse(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(parent, "private-parent")
	if _, err := safefile.CreatePrivateDirectory(private); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "environment-control-inert")
	f, err := newFixture(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	for _, name := range []string{"outside-parent/outside.txt", "readonly.txt", "workspace/fixture-seal"} {
		data, err := f.root.ReadFile(name)
		if err != nil || string(data) != sentinel {
			t.Fatal("fixed sentinel differs")
		}
	}
	if _, err := newFixture(path); err == nil {
		t.Fatal("existing fixture/evidence directory reused")
	}
	for name, data := range map[string]string{"workspace/allowed-write": "fixed write", "outside-parent/allowed-sibling": "fixed parent-grant write"} {
		if err := f.root.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := inspectFixture(f.root); err != nil {
		t.Fatal(err)
	}
	if err := f.root.WriteFile("readonly.txt", []byte("wrong synthetic bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := inspectFixture(f.root); err == nil {
		t.Fatal("modified original sentinel accepted")
	}
}

// No child or PSEC operation: only a fresh synthetic directory and public bytes.
func TestPinParentsBlocksRenameUntilCloseAndAllowsContentWrites(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "fixed-parent")
	moved := parent + "-renamed"
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, parent); err != nil {
		t.Fatal(err)
	}
	held, err := pinParents(filepath.Join(parent, "fixed-not-executed.exe"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.close()
	if err := os.Rename(parent, moved); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("held parent rename: %v", err)
	}
	content := filepath.Join(parent, "fixed-public.txt")
	if err := os.WriteFile(content, []byte("fixed public content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(content); err != nil {
		t.Fatal(err)
	}
	if err := held.close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, parent); err != nil {
		t.Fatal(err)
	}
}
