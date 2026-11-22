// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// urlOperandShapes are URL spellings an operand takes; {H} is the host, a
// fresh one for every row so that no share answer is reused between rows.
var urlOperandShapes = []struct{ name, url string }{
	{"https", "https://{H}/team/pkg"},
	{"git+https", "git+https://{H}/team/pkg.git"},
	{"git+ssh", "git+ssh://git@{H}/team/pkg.git"},
	{"ssh", "ssh://git@{H}/team/repo.git"},
	{"svn+ssh", "svn+ssh://{H}/repo/trunk"},
	{"ftp", "ftp://{H}/pub/file.txt"},
	{"port", "http://{H}:8080/pkg/archive.tgz"},
	{"userinfo", "https://user@{H}/pkg/archive.tgz"},
	{"drive-letter-scheme-tail", "x+b://{H}/share/file.txt"},
	{"backslash", `https:\\{H}\share\file.txt`},
}

// urlOperandReaders are the commands each reader decides, by dialect, with
// the URL in {U}: programs of known role, programs of unknown role (whose
// words the opaque scan reads), option values, quoted requirement specs,
// and the nested shells each reader opens.
var urlOperandReaders = []struct {
	dialect   actionfacts.Dialect
	templates []string
}{
	{actionfacts.DialectPOSIX, []string{
		`curl -fsSL {U} -o out.bin`,
		`wget {U}`,
		`git clone {U}`,
		`pip install {U}`,
		`pip install "pkg @ {U}"`,
		`npm install {U}`,
		`mytool --source={U}`,
		`mytool {U}`,
		`echo {U}`,
		`bash -c "pip install {U}"`,
		`sh -c 'mytool {U}'`,
		`env PIP_INDEX_URL={U} pip install pkg`,
	}},
	{actionfacts.DialectPowerShell, []string{
		`Invoke-WebRequest -Uri {U} -OutFile out.bin`,
		`iwr {U} -OutFile out.bin`,
		`pip install {U}`,
		`pip install "pkg @ {U}"`,
		`& mytool {U}`,
		`Start-Process mytool -ArgumentList {U}`,
		`git clone {U}`,
		`Write-Output {U}`,
		`powershell -NoProfile -Command "pip install {U}"`,
		`cmd /c pip install {U}`,
	}},
	{actionfacts.DialectCMD, []string{
		`curl.exe -L -o out.bin {U}`,
		`pip install {U}`,
		`mytool {U}`,
		`git clone {U}`,
		`echo {U}`,
		`cmd /c "pip install {U}"`,
		`powershell -Command pip install {U}`,
	}},
	{actionfacts.DialectNone, []string{
		`pip install {U}`,
		`mytool {U}`,
	}},
}

// No reader asks a network share for a URL operand, on any route, in any
// URL shape: the //host/... of a URL is judged by its text, never read as
// the UNC path \\host\... (asking it opens an SMB session to the host the
// URL names, with the user's credentials). rel-1-0-10:GAP-0920, GAP-1072
// (s7/gap0980 2050629d2b: the opaque scan of an unknown program's words
// asked \\host\x for pip install git+https://host/x).
func TestURLOperandAsksNoNetworkShareOnAnyRoute(t *testing.T) {
	asked := countShareAsks(t)
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	row, failed := 0, 0
	for _, reader := range urlOperandReaders {
		for _, template := range reader.templates {
			for _, shape := range urlOperandShapes {
				if shape.name == "backslash" && reader.dialect == actionfacts.DialectPOSIX {
					continue // a POSIX shell reads the backslashes as escapes
				}
				row++
				host := fmt.Sprintf("h%03d.example.test", row)
				command := strings.ReplaceAll(template, "{U}", strings.ReplaceAll(shape.url, "{H}", host))
				before := len(asked())
				end := HookCall()
				decision := ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, reader.dialect, nil)
				end()
				if roots := asked()[before:]; len(roots) != 0 {
					failed++
					t.Errorf("%s/%s/%s: decision %q asked network shares %v", reader.dialect, template, shape.name, decision, roots)
				}
			}
		}
	}
	t.Logf("URL operand rows checked: %d, asking a share: %d", row, failed)
	// A real UNC operand is still a share path: it is asked as before.
	before := len(asked())
	end := HookCall()
	_ = ActionCommandDecisionWithDialectAndGlobFacts(`cp payload //fileserver.example.test/share/notes.txt`, cwd, home, actionfacts.DialectPOSIX, nil)
	end()
	if len(asked()) == before {
		t.Fatalf("a UNC operand was not asked")
	}
}
