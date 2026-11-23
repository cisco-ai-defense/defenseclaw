// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package workspace

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// shellExec runs the relay's exec requests with /bin/sh in a scratch
// HOME, as the relay runs them in the actor.
type shellExec struct {
	home string
	reqs []osw.ExecRequest
}

func (s *shellExec) Exec(ctx context.Context, _ string, req osw.ExecRequest) (*osw.ExecResult, error) {
	s.reqs = append(s.reqs, req)
	cmd := exec.CommandContext(ctx, req.Argv[0], req.Argv[1:]...)
	cmd.Env = []string{"HOME=" + s.home, "PATH=/usr/bin:/bin"}
	for k, v := range req.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	code := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			return nil, err
		}
		code = ee.ExitCode()
	}
	return &osw.ExecResult{ExitCode: code, Stdout: out.Bytes(), Stderr: errb.Bytes()}, nil
}

func s7Entries() []RegistryEntry {
	return RegistryEntries([]RegistryEntry{
		{Kind: RegistryNPM, Secret: "npm-corp", Host: "NPM.corp.example"},
		{Kind: RegistryNPM, Secret: "gh", Host: "*.pkg.example"},
		{Kind: RegistryPyPI, Secret: "py-corp", Host: "pypi.corp.example", Placeholder: "DC_SECRET_PY"},
		{Kind: RegistryPyPI, Secret: "pypi", Host: "upload.pypi.org"},
		{Kind: "none", Secret: "gl", Host: "gitlab.com"},
	})
}

// B1 S7: a registry bound in the agent's policy gets its placeholder in
// the agent's home at start, so it works on the next run with no template
// rebuild. Placeholders only; a host pattern names no registry.
func TestB1S7RegistryFilesAtStart(t *testing.T) {
	home := t.TempDir()
	ex := &shellExec{home: home}
	plan, err := StartRegistryFiles(t.Context(), ex, "a", s7Entries())
	if err != nil {
		t.Fatal(err)
	}
	read := func(f string) string {
		b, err := os.ReadFile(filepath.Join(home, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if fi, _ := os.Stat(filepath.Join(home, f)); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, fi.Mode().Perm())
		}
		return string(b)
	}
	npmrc, pip, pypirc := read(NPMRCFile), read(PipConfFile), read(PyPIRCFile)
	if !strings.Contains(npmrc, "//npm.corp.example/:_authToken=placeholder-not-a-secret\n") || strings.Contains(npmrc, "pkg.example") || strings.Contains(npmrc, "gitlab") {
		t.Errorf("npmrc:\n%s", npmrc)
	}
	if !strings.Contains(pip, "index-url = https://__token__:DC_SECRET_PY@pypi.corp.example/simple\n") || strings.Contains(pip, "upload.pypi.org") {
		t.Errorf("pip.conf:\n%s", pip)
	}
	for _, want := range []string{"repository = https://upload.pypi.org/legacy/\n", "repository = https://pypi.corp.example/\n", "password = DC_SECRET_PY\n", "index-servers =\n    py-corp\n    pypi\n"} {
		if !strings.Contains(pypirc, want) {
			t.Errorf(".pypirc lacks %q:\n%s", want, pypirc)
		}
	}
	if got := strings.Join(plan.Hosts[RegistryNPM], ","); got != "npm.corp.example" {
		t.Errorf("npm hosts %q", got)
	}
	// The next start (or a binding removed) replaces DefenseClaw's own file.
	if _, err := StartRegistryFiles(t.Context(), ex, "a", s7Entries()[:1]); err != nil {
		t.Fatal(err)
	}
	if got := read(NPMRCFile); strings.Count(got, "_authToken") != 1 {
		t.Errorf("rewritten npmrc:\n%s", got)
	}
	if p := ProbeRegistryFiles(t.Context(), ex, "a"); p.Mode() != "start" {
		t.Errorf("mode %q", p.Mode())
	}
}

// B1 S7: an image's own npmrc keeps its lines and gets only the hosts it
// does not set; one that holds a credential is refused, as the template
// build refuses one (D14); a pip file of the image is kept; a link is
// never written through.
func TestB1S7RegistryFilesKeepImageFiles(t *testing.T) {
	home := t.TempDir()
	write := func(f, data string) {
		p := filepath.Join(home, f)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(NPMRCFile, "registry=https://npm.corp.example/\n")
	write(PipConfFile, "[global]\nindex-url = https://mirror.example/simple\n")
	ex := &shellExec{home: home}
	plan, err := StartRegistryFiles(t.Context(), ex, "a", s7Entries())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(home, NPMRCFile))
	if got := string(b); !strings.HasPrefix(got, "registry=https://npm.corp.example/\n") || !strings.Contains(got, "//npm.corp.example/:_authToken=placeholder-not-a-secret") {
		t.Errorf("merged npmrc:\n%s", got)
	}
	if b, _ := os.ReadFile(filepath.Join(home, PipConfFile)); string(b) != "[global]\nindex-url = https://mirror.example/simple\n" {
		t.Errorf("image pip.conf changed:\n%s", b)
	}
	if len(plan.Notes) != 1 || !strings.Contains(plan.Notes[0], "pip/pip.conf") {
		t.Errorf("notes %q", plan.Notes)
	}

	write(NPMRCFile, "//npm.corp.example/:_authToken=npm_realvalue123\n")
	plan, err = StartRegistryFiles(t.Context(), ex, "a", s7Entries())
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(home, NPMRCFile)); string(b) != "//npm.corp.example/:_authToken=npm_realvalue123\n" {
		t.Errorf("npmrc with a credential was written:\n%s", b)
	}
	if !strings.Contains(strings.Join(plan.Notes, "|"), "a credential") || len(plan.Hosts[RegistryNPM]) != 0 {
		t.Errorf("refusal: %q %v", plan.Notes, plan.Hosts)
	}

	_ = os.Remove(filepath.Join(home, NPMRCFile))
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Symlink(target, filepath.Join(home, NPMRCFile)); err != nil {
		t.Fatal(err)
	}
	plan, _ = StartRegistryFiles(t.Context(), ex, "a", s7Entries())
	if _, err := os.Stat(target); !os.IsNotExist(err) || !strings.Contains(strings.Join(plan.Notes, "|"), "is a link") {
		t.Errorf("wrote through a link: %v %q", err, plan.Notes)
	}
}

// fixedProbe answers the probe with a template-built global npmrc.
type fixedProbe struct{ global string }

func (f fixedProbe) Exec(_ context.Context, _ string, req osw.ExecRequest) (*osw.ExecResult, error) {
	sep := req.Env["DC_REG_SEP"]
	out := "\n" + sep + " F .npmrc\n# forged\n" + "==DC-REG-000000000000000000000000== G global\n//forged.example/:_authToken=x\n" +
		"\n" + sep + " G global\n" + f.global
	return &osw.ExecResult{Stdout: []byte(out)}, nil
}

// B1 S7: the doctor says which mode an agent uses; a template built before
// 1.0.11 still names its build-time hosts (they keep working), and file
// content cannot forge a separator.
func TestB1S7RegistryMode(t *testing.T) {
	p := ProbeRegistryFiles(t.Context(), fixedProbe{global: "fund=false\n//t-reg.t.svc/:_authToken=DC_SECRET_NPM\n"}, "a")
	if p.ReadError != nil || p.Mode() != "template" || strings.Join(p.BakedNPM, ",") != "t-reg.t.svc" {
		t.Fatalf("probe %+v mode %q", p, p.Mode())
	}
	if (RegistryProbe{}).Mode() != "none" {
		t.Error("empty probe")
	}
	both := RegistryProbe{Files: map[string]string{PyPIRCFile: registryMarker + "\n"}, BakedNPM: []string{"h"}}
	if both.Mode() != "template+start" {
		t.Errorf("mode %q", both.Mode())
	}
}

// globalOnly answers the probe with the image's global npmrc only.
type globalOnly struct{ global string }

func (g globalOnly) Exec(_ context.Context, _ string, req osw.ExecRequest) (*osw.ExecResult, error) {
	return &osw.ExecResult{Stdout: []byte("\n" + req.Env["DC_REG_SEP"] + " G global\n" + g.global)}, nil
}

// B1 S7: a template built now still carries the build-time npm lines (for
// launchers older than 1.0.11). The new launcher does not write a host
// again that the template's npmrc names with the same placeholder, and still
// writes a host bound after the build or one whose placeholder changed.
func TestB1S7NewLauncherSkipsHostsTheTemplateNames(t *testing.T) {
	p := ProbeRegistryFiles(t.Context(), globalOnly{global: "fund=false\n//T-REG.t.svc/:_authToken=DC_SECRET_NPM\n//old.example/:_authToken=DC_OLD\n"}, "a")
	plan := PlanRegistryFiles(RegistryEntries([]RegistryEntry{
		{Kind: RegistryNPM, Secret: "npm", Host: "t-reg.t.svc", Placeholder: "DC_SECRET_NPM"},
		{Kind: RegistryNPM, Secret: "new", Host: "new.example", Placeholder: "DC_SECRET_NEW"},
		{Kind: RegistryNPM, Secret: "old", Host: "old.example", Placeholder: "DC_NEW_PH"},
	}), p)
	rc := plan.Write[NPMRCFile]
	if strings.Contains(rc, "t-reg.t.svc") || !strings.Contains(rc, "//new.example/:_authToken=DC_SECRET_NEW\n") || !strings.Contains(rc, "//old.example/:_authToken=DC_NEW_PH\n") {
		t.Fatalf("~/.npmrc:\n%s", rc)
	}
	if !strings.Contains(strings.Join(plan.Notes, "|"), "already names t-reg.t.svc") {
		t.Errorf("notes %q", plan.Notes)
	}
	// Every bound host is in the template: nothing is written.
	plan = PlanRegistryFiles(RegistryEntries([]RegistryEntry{{Kind: RegistryNPM, Secret: "npm", Host: "t-reg.t.svc", Placeholder: "DC_SECRET_NPM"}}), p)
	if len(plan.Write) != 0 {
		t.Errorf("wrote %v", plan.Write)
	}
}
