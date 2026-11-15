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

package gateway

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// GAP-0671: a random base64 password that holds a slash is not a relative
// path. relativePathValue weighs the value by its characters with the helper
// the SEC-SECRET-ASSIGN path rule uses (weighPath), so a piece that mixes
// upper case, lower case and digits is an id and the ids of the value stay
// over a quarter of it. Every password here is drawn at run time.

const (
	b64PwAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b64PwDraws    = 4000
)

// b64SlashPassword draws an n-character base64 password (openssl rand
// -base64 shape, no padding) that starts with a letter, holds a letter, a
// digit and a slash, and has no + or // and no slash at its ends.
func b64SlashPassword(r *rand.Rand, n int) string {
	for {
		b := make([]byte, n)
		for i := range b {
			b[i] = (b64PwAlphabet + "+/")[r.IntN(len(b64PwAlphabet)+2)]
		}
		s := string(b)
		if strings.ContainsAny(s, "+") || strings.Contains(s, "//") || s[0] == '/' || s[n-1] == '/' ||
			!strings.Contains(s, "/") || countLetters(s) == len(s)-strings.Count(s, "/") ||
			!secretAssignmentLetter(s[0]) {
			continue
		}
		return s
	}
}

func TestPasswordBase64WithSlashIsNotARelativePath(t *testing.T) {
	r := rand.New(rand.NewPCG(671, 16))
	for _, n := range []int{12, 16, 20, 24, 32} {
		path := 0
		for i := 0; i < b64PwDraws; i++ {
			if v := b64SlashPassword(r, n); relativePathValue(v) {
				path++
			}
		}
		// A random draw whose pieces all look like short names (Dev/ab12) is
		// a path by shape; that is under 1 in 300 at 12 characters and under
		// 1 in 1000 from 16 (round 1: 63 of 916 slashed values were missed).
		t.Logf("base64 %d characters with a slash: %d of %d read as a path", n, path, b64PwDraws)
		if path*200 > b64PwDraws {
			t.Errorf("base64 of %d characters: %d of %d draws read as a relative path", n, path, b64PwDraws)
		}
	}
}

// TestPasswordBase64RowsReported is the reviewer's rows R06, R21 and R24
// (s7-respfrev2) and their shapes: every draw is reported by the pack rule.
func TestPasswordBase64RowsReported(t *testing.T) {
	r := rand.New(rand.NewPCG(671, 24))
	shapes := []struct {
		id string
		n  int
		in func(v string) string
	}{
		{"R06", 16, func(v string) string { return `DB_PASSWORD="` + v + `"` }},
		{"R21", 16, func(v string) string { return `PGPASSWORD=` + v + ` psql -h db` }},
		{"R24", 24, func(v string) string { return `"db_password": "` + v + `"` }},
		{"R26", 16, func(v string) string { return `mysql -u root --password=` + v }},
	}
	for _, shape := range shapes {
		missed := 0
		for i := 0; i < 1000; i++ {
			v := b64SlashPassword(r, shape.n)
			if !hasRule(ScanAllRules(shape.in(v), "write_file"), passwordAssignRuleID) {
				missed++
			}
		}
		if missed != 0 {
			t.Errorf("%s: %d of 1000 base64 passwords with a slash were not reported", shape.id, missed)
		}
	}
}

// TestPasswordRelativePathsStayPaths: names, camel-case names, versions and
// counters joined by / are paths, whatever the casing, and a piece that
// mixes the three classes or is long and random is not a name.
func TestPasswordRelativePathsStayPaths(t *testing.T) {
	paths := []string{
		"packages/core", "packages/web-app", "src/components/forms",
		"src/components/LoginForm", "src/hooks/useAuthToken", "src/config/dbConfig.ts",
		"src/api/HTTPServer", "config/Production.yaml", "docs/guides/getting-started",
		"releases/v2.1/notes", "app/models/user_account", "logs/2026-11-14_backup",
		"build/output/web3", "internal/gateway/password_assignment.go",
	}
	for _, p := range paths {
		if !relativePathValue(p) {
			t.Errorf("not a path: %q", p)
		}
	}
	notPaths := []string{
		"Xk3/mQ9z", "aB3dE9xQ/mK2pLw1", "src/a1B2c3D4e5/out", "Summer2026/Winter2026",
		"x7Kq/bTz9/Lm4p", "kQzXpLmN/rTvBsDfG", "packages/aB3dE9xQmK2pLw1z",
	}
	for _, p := range notPaths {
		if relativePathValue(p) {
			t.Errorf("a path: %q", p)
		}
	}
}

// TestWeighPathSharedRule pins the helper both path rules call: the same
// value is weighed the same way by SEC-SECRET-ASSIGN and SEC-PASSWORD-ASSIGN.
func TestWeighPathSharedRule(t *testing.T) {
	w := weighPath("a/b/c/d/e/f/aB3dE9xQmK2pLw1z", false)
	if w.ok && w.namesOnly() {
		t.Errorf("padded id read as names: %+v", w)
	}
	w = weighPath("src/main/java/com/example/project/service", false)
	if !w.namesOnly() || w.words < 6 || w.components != 7 {
		t.Errorf("a source path: %+v", w)
	}
	if weighPath("src//x", true).ok || weighPath("src/"+strings.Repeat("a1", 9), true).ok {
		t.Errorf("an empty component and a long id must rule the value out")
	}
	if weighPath("src/LoginForm", false).namesOnly() == weighPath("src/LoginForm", true).namesOnly() {
		t.Errorf("camel names are weighed only when the caller asks (the secret rule keeps its shape)")
	}
}

// TestPasswordWrappedInBracketsIsReported is the reviewer's row R03: a random
// alphanumeric password in [ ] is not a template slot, whose name is an
// identifier, while the benign slots (B04, B05, B13, B29, B52) stay silent
// (TestPasswordBenignRowsKeepTheRelFloor).
func TestPasswordWrappedInBracketsIsReported(t *testing.T) {
	r := rand.New(rand.NewPCG(671, 3))
	for i := 0; i < 1000; i++ {
		b := make([]byte, 12)
		for j := range b {
			b[j] = b64PwAlphabet[r.IntN(len(b64PwAlphabet))]
		}
		v := string(b)
		if !generatedPiece(v) {
			// Not all three classes: skip, the draw is a name by shape.
			i--
			continue
		}
		in := `"password": "[` + v + `]"`
		if !hasRule(ScanAllRules(in, "write_file"), passwordAssignRuleID) {
			t.Fatalf("bracketed random password of draw %d not reported", i)
		}
	}
}
