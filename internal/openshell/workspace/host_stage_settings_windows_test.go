// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package workspace

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestHostStageWindowsSettingsPrecedenceUsesCapturedLocalFacts(t *testing.T) {
	opts := hostStageFixture(t)
	setupCapturedGitFixture(t, opts)
	writeHostStageFixture(t, opts.Home, ".gitconfig", "[core]\nautocrlf = true\nsafecrlf = warn\n")
	writeHostStageFixture(t, opts.Home, ".config/git/config", "[core]\nautocrlf = false\nsafecrlf = true\neol = lf\n")
	facts, err := freezeWindowsHostStageSettings(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	// Home overrides conflicting XDG facts; XDG only supplies missing keys.
	// Assert before local overrides, so the local repository cannot mask a
	// regression in the independently frozen operator fallback authority.
	wantFallback := map[string]string{"core.autocrlf": "true", "core.safecrlf": "warn", "core.eol": "lf"}
	if !facts.frozen || !reflect.DeepEqual(facts.lineEndings, wantFallback) {
		t.Fatalf("conflicting operator fallback precedence changed: %+v", facts.lineEndings)
	}
	fixedGit(t, opts.Project, "config", "core.safecrlf", "off")
	writeHostStageFixture(t, opts.Project, "main.txt", "fixed raw CRLF\r\n")
	fixedGit(t, opts.Project, "add", "--all")
	fixedGit(t, opts.Project, "commit", "--quiet", "-m", "fixed settings fixture")
	changed := false
	opts.Detector = hostStageDetectorFunc(func(rel string, _ []byte) (string, bool) {
		if rel == "main.txt" && !changed {
			changed = true
			writeHostStageFixture(t, opts.Project, ".git/config", "[core]\nautocrlf = true\n")
			writeHostStageFixture(t, opts.Home, ".gitconfig", "[core]\nautocrlf = true\neol = crlf\n")
		}
		return "", false
	})
	stage, err := PrepareHostStage(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stage.Close(); err != nil {
			t.Error(err)
		}
	}()
	want := map[string]string{"core.autocrlf": "false", "core.eol": "lf", "core.safecrlf": "false"}
	if !changed || !reflect.DeepEqual(stage.Summary().LineEndings, want) {
		t.Fatalf("local snapshot/operator precedence changed: %+v", stage.Summary().LineEndings)
	}
	path, err := stage.TreePath()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(path, "main.txt"))
	if err != nil || !bytes.Equal(data, []byte("fixed raw CRLF\r\n")) {
		t.Fatalf("raw working bytes changed: %q %v", data, err)
	}
	artifact := filepath.Dir(filepath.Dir(path))
	for _, name := range []string{"capture", "scratch", "git-home"} {
		if _, err := os.Stat(filepath.Join(artifact, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("raw temporary data retained: %s %v", name, err)
		}
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoHostStageResidue(t, opts)
}

func TestHostStageWindowsSettingsPlainPreservesRawBaselineWithoutGit(t *testing.T) {
	opts := hostStageFixture(t)
	writeHostStageFixture(t, opts.Home, ".gitconfig", "[include]\npath = fixed-unused-config\n[core]\nautocrlf = true\n")
	writeHostStageFixture(t, opts.Project, "main.txt", "fixed plain bytes\r\n")
	t.Setenv("PATH", "")
	stage, err := PrepareHostStage(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stage.Close(); err != nil {
			t.Error(err)
		}
	}()
	if len(stage.Summary().LineEndings) != 0 || stage.Summary().Kind != CopyPlain {
		t.Fatal("plain snapshot applied irrelevant operator Git config")
	}
	path, err := stage.TreePath()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(path, "main.txt"))
	if err != nil || string(data) != "fixed plain bytes\r\n" {
		t.Fatalf("plain CRLF bytes were normalized: %q %v", data, err)
	}
}

func TestHostStageWindowsSettingsRefuseUnknownOrUnstableOperatorFacts(t *testing.T) {
	for _, kind := range []string{"include", "invalid", "oversize", "writer", "hardlink", "junction", "stream", "effective transform"} {
		t.Run(kind, func(t *testing.T) {
			opts := hostStageFixture(t)
			setupCapturedGitFixture(t, opts)
			writeHostStageFixture(t, opts.Project, "main.txt", "fixed public fixture")
			fixedGit(t, opts.Project, "add", "--all")
			fixedGit(t, opts.Project, "commit", "--quiet", "-m", "fixed commit")
			global := filepath.Join(opts.Home, ".gitconfig")
			writeHostStageFixture(t, opts.Home, ".gitconfig", "[core]\nautocrlf = false\n")
			want := ""
			switch kind {
			case "include":
				writeHostStageFixture(t, opts.Home, ".gitconfig", "[include]\npath = fixed-unused-config\n")
				want = "operator_config_includes_not_supported"
			case "invalid":
				writeHostStageFixture(t, opts.Home, ".gitconfig", "[\n")
				want = "operator_config_invalid_or_unbounded"
			case "oversize":
				writeHostStageFixture(t, opts.Home, ".gitconfig", strings.Repeat("a", (1<<20)+1))
				want = "operator_config_size_limit"
			case "writer":
				file, err := os.OpenFile(global, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				want = "operator_config_not_readable_or_stable"
			case "hardlink":
				if err := os.Link(global, filepath.Join(opts.Home, "fixed-second-link")); err != nil {
					t.Fatal(err)
				}
				want = "operator_config_type_or_link_not_supported"
			case "junction":
				if err := os.Remove(global); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(opts.Home, "fixed-global-directory")
				if err := os.Mkdir(outside, 0o700); err != nil {
					t.Fatal(err)
				}
				if output, err := exec.Command("cmd.exe", "/D", "/C", "mklink", "/J", global, outside).CombinedOutput(); err != nil {
					t.Fatalf("create owned junction: %v %s", err, output)
				}
				t.Cleanup(func() { _ = os.Remove(global) })
				want = "operator_config_type_or_link_not_supported"
			case "stream":
				if err := os.WriteFile(global+":fixed-private-stream", []byte("fixed stream canary"), 0o600); err != nil {
					t.Fatal(err)
				}
				want = "operator_config_stream_not_supported"
			case "effective transform":
				fixedGit(t, opts.Project, "config", "--unset", "core.autocrlf")
				writeHostStageFixture(t, opts.Home, ".gitconfig", "[core]\nautocrlf = true\n")
				want = "line_ending_transform_not_supported"
			}
			stage, err := PrepareHostStage(context.Background(), opts)
			if err == nil {
				_ = stage.Close()
				t.Fatal("uncertain operator configuration was accepted")
			}
			assertCapturedReason(t, err, want)
			assertNoHostStageResidue(t, opts)
		})
	}
}

func TestHostStageWindowsSettingsKnownAbsentParentsReleasePins(t *testing.T) {
	opts := hostStageFixture(t)
	name := filepath.Join(opts.Home, "not-created", "nested", "config")
	data, present, err := readWindowsHostStageOptionalConfig(context.Background(), name)
	if err != nil || present || data != nil {
		t.Fatalf("known absence was not exact: %t %v", present, err)
	}
	// A leaked no-delete-sharing ancestor handle would prevent this rename.
	moved := opts.Home + "-renamed"
	if err := os.Rename(opts.Home, moved); err != nil {
		t.Fatalf("optional missing path leaked a held ancestor: %v", err)
	}
	if err := os.Rename(moved, opts.Home); err != nil {
		t.Fatal(err)
	}
}

func TestHostStageWindowsOverlapUsesHeldIdentitiesBothDirections(t *testing.T) {
	opts := hostStageFixture(t)
	child := filepath.Join(opts.Project, "child")
	sibling := filepath.Join(opts.Home, "sibling")
	for _, name := range []string{child, sibling} {
		if err := os.Mkdir(name, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	open := func(name string) *windowsHostStagePin {
		pin, err := openWindowsHostStagePin(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pin.close)
		return pin
	}
	a, b, c := open(opts.Project), open(child), open(sibling)
	a.path = "fixed-metadata-only-display-a"
	b.path = "fixed-metadata-only-display-b"
	for _, pair := range [][2]*windowsHostStagePin{{a, b}, {b, a}, {a, a}} {
		yes, err := windowsHostStagePinsOverlap(pair[0], pair[1])
		if err != nil || !yes {
			t.Fatalf("held ancestor overlap lost: %t %v", yes, err)
		}
	}
	if yes, err := windowsHostStagePinsOverlap(a, c); err != nil || yes {
		t.Fatalf("disjoint held siblings overlap: %t %v", yes, err)
	}
}
