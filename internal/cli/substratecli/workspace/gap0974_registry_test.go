// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

func gapRegWrite(t *testing.T, home, f, data string) {
	t.Helper()
	p := filepath.Join(home, f)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gapRegRead(t *testing.T, home, f string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, f))
	if err != nil {
		t.Fatalf("%s: %v", f, err)
	}
	return string(b)
}

// GAP-0974: a folder link on the way to a registry file (~/.config,
// ~/.config/pip, ~/.pip) is never written through, and the other files
// are still written.
func TestGAP0974RegistryWriteRefusesFolderLinks(t *testing.T) {
	for _, dir := range []string{".config", ".config/pip", ".pip"} {
		t.Run(dir, func(t *testing.T) {
			home, outside := t.TempDir(), t.TempDir()
			if err := os.MkdirAll(filepath.Dir(filepath.Join(home, dir)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(home, dir)); err != nil {
				t.Fatal(err)
			}
			plan, err := StartRegistryFiles(t.Context(), &shellExec{home: home}, "a", s7Entries())
			if err != nil {
				t.Fatal(err)
			}
			_ = filepath.Walk(outside, func(p string, fi os.FileInfo, _ error) error {
				if fi != nil && !fi.IsDir() {
					t.Errorf("wrote through the %s link: %s", dir, p)
				}
				return nil
			})
			if !strings.Contains(strings.Join(plan.Notes, "|"), "is a link") {
				t.Errorf("no link note: %q", plan.Notes)
			}
			if !strings.Contains(gapRegRead(t, home, NPMRCFile), "_authToken=") || !strings.Contains(gapRegRead(t, home, PyPIRCFile), "[distutils]") {
				t.Error("the files outside the link were not written")
			}
		})
	}
}

// GAP-0974: a parent that is a file, not a folder, refuses that file only.
func TestGAP0974RegistryWriteRefusesNonFolderParent(t *testing.T) {
	home := t.TempDir()
	gapRegWrite(t, home, ".config", "not a folder\n")
	plan, err := StartRegistryFiles(t.Context(), &shellExec{home: home}, "a", s7Entries())
	if err != nil {
		t.Fatal(err)
	}
	if gapRegRead(t, home, ".config") != "not a folder\n" || !strings.Contains(strings.Join(plan.Notes, "|"), "not a folder") {
		t.Errorf(".config changed or no note: %q", plan.Notes)
	}
	if _, ok := plan.Write[PipConfFile]; ok {
		t.Error("pip.conf planned through a non-folder")
	}
	if !strings.Contains(gapRegRead(t, home, NPMRCFile), "_authToken=") {
		t.Error("~/.npmrc not written")
	}
}

// plantTmpExec runs the write script in a shell whose $$ is known
// beforehand (exec keeps the pid), after a link is put at the temporary
// name the old script used ($1.dc-tmp.$$).
type plantTmpExec struct {
	shellExec
	target string
}

func (p *plantTmpExec) Exec(ctx context.Context, sb string, req osw.ExecRequest) (*osw.ExecResult, error) {
	if req.Env["DC_REG_NPMRC"] == "" {
		return p.shellExec.Exec(ctx, sb, req)
	}
	env := map[string]string{"DC_S": req.Argv[2], "DC_T": p.target}
	for k, v := range req.Env {
		env[k] = v
	}
	return p.shellExec.Exec(ctx, sb, osw.ExecRequest{Argv: []string{"/bin/sh", "-c", `ln -s "$DC_T" "$HOME/.npmrc.dc-tmp.$$"; exec /bin/sh -c "$DC_S"`}, Env: env})
}

// GAP-0974: a link planted at a temporary name is not followed: the
// temporary file is made fresh (mktemp), and ~/.npmrc ends a regular file.
func TestGAP0974RegistryWritePlantedTempLink(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	ex := &plantTmpExec{shellExec: shellExec{home: home}, target: target}
	if _, err := StartRegistryFiles(t.Context(), ex, "a", s7Entries()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Errorf("wrote through the planted temporary link: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(home, NPMRCFile))
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("~/.npmrc: %v %v", fi, err)
	}
	if !strings.Contains(gapRegRead(t, home, NPMRCFile), "_authToken=placeholder-not-a-secret") {
		t.Error("~/.npmrc lacks its line")
	}
	ents, _ := os.ReadDir(home)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".dc-reg.") {
			t.Errorf("temporary file left: %s", e.Name())
		}
	}
}

// GAP-0974: a file that is a folder (or a link to one) is refused, not
// written into.
func TestGAP0974RegistryWriteRefusesFolderTarget(t *testing.T) {
	home, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, PyPIRCFile)); err != nil {
		t.Fatal(err)
	}
	// The probe names the link; the write script refuses it too when the
	// plan is made without the probe (a link put there after it).
	plan := PlanRegistryFiles(s7Entries(), RegistryProbe{Files: map[string]string{}})
	err := WriteRegistryFiles(t.Context(), &shellExec{home: home}, "a", plan)
	if err == nil || !strings.Contains(err.Error(), ".pypirc is a folder") {
		t.Errorf("err %v", err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("wrote into the linked folder: %v", ents)
	}
	if !strings.Contains(gapRegRead(t, home, NPMRCFile), "_authToken=") {
		t.Error("~/.npmrc not written")
	}
}

// GAP-0975: an image's own ~/.npmrc that got lines at start reads as
// mode start.
func TestGAP0975ModeStartForMergedNPMRC(t *testing.T) {
	home := t.TempDir()
	gapRegWrite(t, home, NPMRCFile, "registry=https://npm.corp.example/\n")
	ex := &shellExec{home: home}
	if _, err := StartRegistryFiles(t.Context(), ex, "a", s7Entries()[:1]); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gapRegRead(t, home, NPMRCFile), registryAppendMarker) {
		t.Fatal("no lines added")
	}
	if p := ProbeRegistryFiles(t.Context(), ex, "a"); p.Mode() != "start" {
		t.Errorf("mode %q", p.Mode())
	}
}

// GAP-0976: a comment that names a bound host sets nothing, so the host
// still gets its line; a live image line with another placeholder is kept
// and said in a Note; the same placeholder is kept silently.
func TestGAP0976CommentDoesNotStopTheAdd(t *testing.T) {
	for _, c := range []string{"# example: //npm.corp.example/:_authToken=YOUR-TOKEN\n", "  ; //npm.corp.example/:_authToken=x\n"} {
		plan := PlanRegistryFiles(s7Entries(), RegistryProbe{Files: map[string]string{NPMRCFile: c + "registry=https://npm.corp.example/\n"}})
		if !strings.Contains(plan.Write[NPMRCFile], registryAppendMarker+"\n//npm.corp.example/:_authToken=placeholder-not-a-secret\n") {
			t.Errorf("%q: no line added:\n%s", c, plan.Write[NPMRCFile])
		}
		if strings.Join(plan.Hosts[RegistryNPM], ",") != "npm.corp.example" {
			t.Errorf("%q: hosts %v", c, plan.Hosts)
		}
	}
	plan := PlanRegistryFiles(s7Entries(), RegistryProbe{Files: map[string]string{NPMRCFile: "//NPM.corp.example/:_authToken = DC_SECRET_PY\n"}})
	if _, ok := plan.Write[NPMRCFile]; ok || !strings.Contains(strings.Join(plan.Notes, "|"), "already sets //npm.corp.example/:_authToken") {
		t.Errorf("other placeholder: write %v notes %q", plan.Write[NPMRCFile] != "", plan.Notes)
	}
	plan = PlanRegistryFiles(s7Entries(), RegistryProbe{Files: map[string]string{NPMRCFile: "//npm.corp.example/:_authToken=\"placeholder-not-a-secret\"\n"}})
	if _, ok := plan.Write[NPMRCFile]; ok || strings.Contains(strings.Join(plan.Notes, "|"), "already sets") {
		t.Errorf("same placeholder: write %v notes %q", plan.Write[NPMRCFile] != "", plan.Notes)
	}
}

// GAP-0977: pip's user file under XDG_CONFIG_HOME is missed when a
// connector points XDG_CONFIG_HOME elsewhere (Devin), so the index is also
// in ~/.pip/pip.conf, which pip reads whatever XDG_CONFIG_HOME is.
func TestGAP0977PipLegacyConf(t *testing.T) {
	home := t.TempDir()
	plan, err := StartRegistryFiles(t.Context(), &shellExec{home: home}, "a", s7Entries())
	if err != nil {
		t.Fatal(err)
	}
	xdg, legacy := gapRegRead(t, home, PipConfFile), gapRegRead(t, home, PipLegacyConfFile)
	if legacy != xdg || !strings.Contains(legacy, "index-url = https://__token__:DC_SECRET_PY@pypi.corp.example/simple\n") {
		t.Errorf("~/.pip/pip.conf:\n%s", legacy)
	}
	if fi, _ := os.Stat(filepath.Join(home, PipLegacyConfFile)); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if len(plan.Notes) != 0 {
		t.Errorf("notes %q", plan.Notes)
	}
	if pip, err := exec.LookPath("pip3"); err == nil {
		cmd := exec.Command(pip, "config", "list")
		cmd.Env = []string{"HOME=" + home, "XDG_CONFIG_HOME=" + t.TempDir(), "PATH=/usr/bin:/bin", "PIP_CONFIG_FILE="}
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "pypi.corp.example") {
			t.Errorf("pip with XDG_CONFIG_HOME elsewhere reads no index: %s", out)
		}
	}

	// An image's ~/.config/pip/pip.conf keeps pip as it was: nothing is
	// added in ~/.pip either.
	home = t.TempDir()
	gapRegWrite(t, home, PipConfFile, "[global]\nindex-url = https://mirror.example/simple\n")
	if _, err := StartRegistryFiles(t.Context(), &shellExec{home: home}, "a", s7Entries()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, PipLegacyConfFile)); !os.IsNotExist(err) {
		t.Errorf("~/.pip/pip.conf written under an image pip.conf: %v", err)
	}

	// An image's ~/.pip/pip.conf is kept; ~/.config/pip/pip.conf is still
	// written, as before.
	home = t.TempDir()
	gapRegWrite(t, home, PipLegacyConfFile, "[global]\ntimeout = 60\n")
	plan, err = StartRegistryFiles(t.Context(), &shellExec{home: home}, "a", s7Entries())
	if err != nil {
		t.Fatal(err)
	}
	if gapRegRead(t, home, PipLegacyConfFile) != "[global]\ntimeout = 60\n" || !strings.Contains(gapRegRead(t, home, PipConfFile), "index-url") {
		t.Error("image ~/.pip/pip.conf changed or ~/.config/pip/pip.conf not written")
	}
	if !strings.Contains(strings.Join(plan.Notes, "|"), "~/.pip/pip.conf in the agent is the image's") {
		t.Errorf("notes %q", plan.Notes)
	}
}
