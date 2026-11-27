// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"bufio"
	"encoding/json"
	"os"
	"path"
	"strings"
	"testing"
)

type det111R2CorpusCase struct {
	ID      string `json:"id"`
	Payload struct {
		Command    string `json:"command"`
		CWD        string `json:"cwd"`
		ActiveHome string `json:"active_home"`
		Dialect    string `json:"dialect"`
	} `json:"payload"`
	Truth struct {
		SourceTruth string   `json:"source_truth"`
		Categories  []string `json:"categories"`
	} `json:"truth"`
}

// TestDET111R2Corpus runs every R2 seed, variant, and benign twin through the
// data-driven effects reader. A malicious row that names a protected target
// must retain that target as known or explicitly unknown; benign twins must
// not acquire a protected mutation. This keeps R2 cases tied to the program
// table instead of duplicating command strings in Go tests.
func TestDET111R2Corpus(t *testing.T) {
	f, err := os.Open("testdata/det111_r2.cases.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	count := 0
	for scanner.Scan() {
		var c det111R2CorpusCase
		if err := json.Unmarshal(append([]byte(nil), scanner.Bytes()...), &c); err != nil {
			t.Fatalf("case row %d: %v", count+1, err)
		}
		if !det111R2HasCategory(c.Truth.Categories, "class:R2") {
			continue
		}
		count++
		if c.Payload.Command == "" {
			t.Errorf("%s: missing command", c.ID)
			continue
		}
		opt := det111R2Options(c.Payload)
		r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: c.Payload.Command, Workdir: c.Payload.CWD}, opt)
		role := det111R2Category(c.Truth.Categories, "role:")
		if c.Truth.SourceTruth == "benign" || role == "role:benign" {
			for _, e := range r.Effects {
				if det111R2Mutation(e.Kind) && det111R2ProtectedEffect(e, c.Payload.ActiveHome) {
					t.Errorf("%s: benign twin has protected %s effect at %s\n%s", c.ID, e.Kind, det111R2EffectName(e), fmtRes(r))
				}
			}
			continue
		}
		if det111R2ProtectedText(c.Payload.Command) && !det111R2HasReach(r, c.Payload.Command, c.Payload.ActiveHome) {
			t.Errorf("%s: protected target was dropped instead of known or reach-unknown\n%s", c.ID, fmtRes(r))
		}
		if len(r.Effects) == 0 && len(r.Unknowns) == 0 {
			t.Errorf("%s: command produced neither effects nor an unknown", c.ID)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 356 {
		t.Fatalf("loaded %d R2 corpus cases; want 356", count)
	}
}

func det111R2Options(p struct {
	Command    string `json:"command"`
	CWD        string `json:"cwd"`
	ActiveHome string `json:"active_home"`
	Dialect    string `json:"dialect"`
}) Options {
	o := Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: p.ActiveHome, CWD: p.CWD, Env: map[string]string{"HOME": p.ActiveHome}}
	if strings.Contains(strings.ToLower(p.ActiveHome), `:\`) || strings.EqualFold(p.Dialect, "cmd") || strings.EqualFold(p.Dialect, "powershell") {
		o.Flavor = FlavorWindows
		o.CaseInsensitive = true
		o.Env["USERPROFILE"] = p.ActiveHome
		if len(p.ActiveHome) >= 2 && p.ActiveHome[1] == ':' {
			o.Drive = p.ActiveHome[:1]
			o.Env["HOMEDRIVE"] = p.ActiveHome[:2]
			o.Env["HOMEPATH"] = strings.TrimPrefix(p.ActiveHome[2:], "\\")
		}
	}
	switch strings.ToLower(p.Dialect) {
	case "cmd":
		o.Dialect = DialectCMD
	case "powershell":
		o.Dialect = DialectPowerShell
	case "posix", "bash", "sh", "shell":
		o.Dialect = DialectPOSIX
	default:
		o.Dialect = DialectNone
	}
	return o
}

func det111R2HasCategory(categories []string, want string) bool {
	for _, c := range categories {
		if c == want {
			return true
		}
	}
	return false
}

func det111R2Category(categories []string, prefix string) string {
	for _, c := range categories {
		if strings.HasPrefix(c, prefix) {
			return c
		}
	}
	return ""
}

func det111R2ProtectedText(s string) bool {
	s = strings.ToLower(s)
	for _, marker := range []string{".defenseclaw", ".claude", ".codex", ".ssh", ".aws", ".kube", ".netrc", "git-credentials", "authorized_keys", "id_rsa"} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func det111R2ProtectedEffect(e Effect, home string) bool {
	h := strings.ToLower(path.Clean(strings.ReplaceAll(home, "\\", "/")))
	for _, candidate := range []string{e.Target.Path, e.Target.Glob, e.Target.Spelling} {
		p := strings.ToLower(path.Clean(strings.ReplaceAll(candidate, "\\", "/")))
		if e.Target.Subtree && e.Kind != KindRead && h != "." && (h == p || strings.HasPrefix(h, strings.TrimSuffix(p, "/")+"/")) {
			return true // a proven recursive mutation covers protected descendants
		}
		if !det111R2ProtectedText(candidate) {
			continue
		}
		if e.TargetState == TargetStateUnknown && strings.Contains(strings.ToLower(candidate), "$env:userprofile") && home != "" {
			return true
		}
		if h != "." && (p == h || strings.HasPrefix(p, strings.TrimSuffix(h, "/")+"/")) {
			return true
		}
	}
	return false
}

func det111R2HasReach(r Result, command, home string) bool {
	for _, e := range r.Effects {
		if det111R2ProtectedEffect(e, home) {
			return true // known target or target-scoped unknown
		}
		if e.TargetState != TargetStateKnown || e.RoleState != RoleStateKnown {
			if len(e.Reasons) > 0 && det111R2ProtectedText(command) {
				return true // an explicit unknown effect whose command text reaches the protected name
			}
		}
	}
	return len(r.Unknowns) > 0 && det111R2ProtectedText(command)
}

func det111R2Mutation(k Kind) bool {
	switch k {
	case KindWrite, KindAppend, KindDelete, KindLink, KindPermissionChange:
		return true
	default:
		return false
	}
}

func det111R2EffectName(e Effect) string {
	if e.Target.Path != "" {
		return e.Target.Path
	}
	if e.Target.Glob != "" {
		return e.Target.Glob
	}
	return e.Target.Spelling
}
