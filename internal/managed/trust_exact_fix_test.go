// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A refusal of a changed managed object names the exact commands: the real
// path and the real accounts, never <path> or <SID> (GAP-0602).
func TestStandaloneExactFixNamesThePathAndTheAccounts(t *testing.T) {
	path := `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`
	for _, test := range []struct {
		name    string
		writers []string
		drift   []string
		want    []string
	}{
		{"writer", []string{"S-1-5-32-545"}, nil, []string{`icacls "` + path + `" /remove:g *S-1-5-32-545`}},
		{"two writers", []string{"S-1-5-32-545", "S-1-5-11"}, nil, []string{`/remove:g *S-1-5-32-545`, `/remove:g *S-1-5-11`}},
		// A null access list names Everyone, and an object entry the assessment
		// cannot read names "object-ace-N": neither is an SID /remove:g can use.
		{"null DACL", []string{"S-1-1-0"}, []string{"DACL is null"}, []string{`/inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)"`, `/setowner *S-1-5-32-544`}},
		{"object entry", []string{"object-ace-3"}, nil, []string{`/inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)"`, `/setowner *S-1-5-32-544`}},
		{"owner", nil, []string{"owner S-1-5-21-1-2-3-1001 is not trusted"}, []string{`icacls "` + path + `" /remove:g *S-1-5-21-1-2-3-1001`, `icacls "` + path + `" /setowner *S-1-5-32-544`}},
		{"both", []string{"S-1-5-32-545"}, []string{"owner S-1-5-21-1-2-3-1001 is not trusted"}, []string{`/remove:g *S-1-5-32-545`, `/remove:g *S-1-5-21-1-2-3-1001`, `/setowner *S-1-5-32-544`}},
		{"a writer that also owns", []string{"S-1-5-32-545"}, []string{"owner S-1-5-32-545 is not trusted"}, []string{`/remove:g *S-1-5-32-545`, `/setowner *S-1-5-32-544`}},
		{"unknown", nil, nil, []string{`/inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)"`, `/setowner *S-1-5-32-544`}},
	} {
		got := standaloneExactFix(path, false, test.writers, test.drift)
		for _, want := range test.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s: %q does not contain %q", test.name, got, want)
			}
		}
		// Every command is exact and runnable: no template, no pseudo SID,
		// and no /remove:g of Everyone for a null access list.
		if strings.ContainsAny(got, "<>") || strings.Contains(got, "object-ace") || (test.name == "null DACL" && strings.Contains(got, "/remove:g")) {
			t.Errorf("%s: %q is not an exact command", test.name, got)
		}
	}
	if folder := standaloneExactFix(path, true, nil, []string{"DACL is null"}); !strings.Contains(folder, `"*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)"`) {
		t.Errorf("a folder reset does not inherit: %q", folder)
	}
	file := standaloneInPlaceRecovery(path, false, []string{"S-1-5-32-545"}, nil)
	folder := standaloneInPlaceRecovery(`C:\ProgramData\Cisco\DefenseClaw\etc`, true, nil, nil)
	for _, text := range []string{file, folder} {
		if strings.Contains(text, "<path>") || strings.Contains(text, "<SID>") || !strings.Contains(text, "/ensure") {
			t.Errorf("recovery %q holds a template or names no Setup step", text)
		}
	}
	if !strings.Contains(standaloneStructuralRecovery(path), `Remove-Item -LiteralPath "`+path+`" -Force`) {
		t.Error("the structural recovery does not name the exact removal")
	}
}

type principalForTest struct {
	sid   string
	owner bool
}

func (p principalForTest) Error() string                { return "untrusted " + p.sid }
func (p principalForTest) untrustedSID() (string, bool) { return p.sid, p.owner }

// A machine-policy refusal reads the account out of the verdict it wraps.
func TestStandaloneMachinePolicyRecoveryNamesTheExactCommand(t *testing.T) {
	missing := `C:\does-not-exist-g602\90-defenseclaw.json`
	text := standaloneMachinePolicyDriftRecovery(missing, errors.New("untrusted"))
	if !strings.Contains(text, `Remove-Item -LiteralPath "`+missing+`" -Force`) || strings.Contains(text, "<path>") {
		t.Errorf("file recovery = %q", text)
	}
	dir := t.TempDir()
	folder := standaloneMachinePolicyDriftRecovery(dir, principalForTest{sid: "S-1-5-32-545"})
	if !strings.Contains(folder, `icacls "`+dir+`" /remove:g *S-1-5-32-545`) || strings.Contains(folder, "<SID>") {
		t.Errorf("folder recovery = %q", folder)
	}
	owner := standaloneMachinePolicyDriftRecovery(dir, principalForTest{sid: "S-1-5-21-1-2-3-1001", owner: true})
	if !strings.Contains(owner, `icacls "`+dir+`" /setowner *S-1-5-32-544`) || !strings.Contains(owner, `/remove:g *S-1-5-21-1-2-3-1001`) {
		t.Errorf("owner recovery = %q", owner)
	}
	// A verdict wrapped as text still yields exact /remove:g commands.
	plain := standaloneMachinePolicyDriftRecovery(dir, errors.New("an untrusted principal can write C:\\x: untrusted principal S-1-5-32-545 has write access; owner S-1-5-21-1-2-3-1001 is not trusted"))
	for _, want := range []string{`icacls "` + dir + `" /remove:g *S-1-5-32-545`, `/remove:g *S-1-5-21-1-2-3-1001`} {
		if !strings.Contains(plain, want) {
			t.Errorf("text-only recovery lacks %q: %q", want, plain)
		}
	}
	above := standaloneMachinePolicyDriftRecovery(filepath.Join(dir, ".defenseclaw-managed-hooks.state"), errors.New("managed policy file x has an untrusted writer above it"))
	if !strings.Contains(above, `icacls "`+dir+`" /remove:g *S-1-5-32-545`) {
		t.Errorf("a writer above the object is not taken off the folder above: %q", above)
	}
	file := filepath.Join(dir, "requirements.toml")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileText := standaloneMachinePolicyDriftRecovery(file, principalForTest{sid: "S-1-5-32-545"})
	for _, want := range []string{`Remove-Item -LiteralPath "` + file + `" -Force`, `icacls "` + file + `" /remove:g *S-1-5-32-545`, `/setowner *S-1-5-32-544`, "/ensure"} {
		if !strings.Contains(fileText, want) {
			t.Errorf("file recovery lacks %q: %q", want, fileText)
		}
	}
}
