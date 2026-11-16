// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// patchDeleteVerdict is the verdict of a typed Codex apply_patch that deletes
// (directive "Delete File") or adds (directive "Add File") file, called from
// cwd, with the client evidence given (nil: the gateway resolves links itself).
func patchDeleteVerdict(t *testing.T, connector, directive, home, cwd, file string, evidence map[string]string) (string, map[string]bool) {
	t.Helper()
	body := ""
	if directive == "Add File" {
		body = "+# note\n"
	}
	raw, err := json.Marshal(map[string]string{"command": "*** Begin Patch\n*** " + directive + ": " + file + "\n" + body + "*** End Patch"})
	if err != nil {
		t.Fatal(err)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:      actionfacts.Input{Tool: "apply_patch", Args: raw, CWD: cwd, ActiveHome: home},
		LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
		SkipLocalFilesystemResolution: evidence != nil, ResolvedWriteTargets: evidence,
	})
	rules := make(map[string]bool)
	for _, finding := range findings {
		rules[finding.RuleID] = true
	}
	return buildVerdict(findings, "tool_call").Action, rules
}

// A typed apply_patch Delete File of a credential file of the user's home is
// judged by the same protected-path decision as Add File and Update File of
// it: the same finding in every profile, whether the name is absolute, in the
// form of the home, or relative to a working directory, and for a home folder
// below the working directory (the home of the user under another parent).
func TestTypedPatchDeleteOfCredentialFileIsJudgedLikeAnAdd(t *testing.T) {
	home := hostFixturePath("/Users/alice")
	// The copies are compared too: a profile that protects a copy of a credential file for a write protects it for a delete.
	files := []string{".netrc", ".git-credentials", ".aws/credentials", ".kube/config", ".netrc.bak", ".aws/credentials.bak", ".aws/credentials.example"}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "typed-patch-delete-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, cwd := range []string{filepath.Join(home, "project"), hostFixturePath("/tmp/work"), home} {
			for _, slashed := range files {
				file := filepath.FromSlash(slashed)
				for _, name := range []string{
					filepath.Join(home, file), filepath.FromSlash("~/") + file,
					filepath.Join(cwd, "Users", "alice", file), filepath.Join("Users", "alice", file),
					filepath.Join(cwd, "a", "home", "alice", file), filepath.Join("a", "home", "alice", file),
					filepath.Join(cwd, "a", "USERS", "ALICE", file),
				} {
					added, addRules := patchDeleteVerdict(t, connector, "Add File", home, cwd, name, nil)
					deleted, deleteRules := patchDeleteVerdict(t, connector, "Delete File", home, cwd, name, nil)
					if added != "block" {
						continue // the Add itself is no protected name in this spelling: nothing to compare
					}
					if deleted != "block" || !sameRules(ownerKeys(addRules), ownerKeys(deleteRules)) {
						t.Errorf("%s cwd=%s Delete File %q: %s %v, want the block of Add File: %v", profile, cwd, name, deleted, deleteRules, addRules)
					}
				}
			}
		}
		// The files of the review, named from the working directory.
		for _, name := range []string{"Users/alice/.netrc", "Users/alice/.git-credentials", "Users/alice/.aws/credentials"} {
			if action, rules := patchDeleteVerdict(t, connector, "Delete File", home, filepath.Join(home, "project"), filepath.FromSlash(name), nil); action != "block" {
				t.Errorf("%s Delete File %q from the project: %s %v, want block", profile, name, action, rules)
			}
		}
	}
}

// Ordinary names stay deletable: a copy or example of a credential file, a
// credential file of a project fixture home of another account, and files
// that are no credential file.
func TestTypedPatchDeleteOfOrdinaryFileStaysAllowed(t *testing.T) {
	home := hostFixturePath("/Users/alice")
	cwd := filepath.Join(home, "project")
	for _, profile := range []string{"default", "permissive"} {
		connector := "typed-patch-delete-ordinary-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, name := range []string{
			filepath.Join(home, ".netrc.bak"), filepath.Join(home, ".aws", "credentials.example"), filepath.Join(home, ".git-credentials.old"), filepath.Join(home, "notes.txt"),
			filepath.Join(cwd, "Users", "bob", ".netrc"), filepath.Join(cwd, "Users", "alice", ".netrc.bak"), filepath.Join(cwd, "Users", "alice", ".aws", "credentials.sample"),
			filepath.Join(cwd, "main.go"), filepath.Join("src", "main.go"), ".netrc", filepath.Join("sub", ".aws", "credentials"),
		} {
			if action, rules := patchDeleteVerdict(t, connector, "Delete File", home, cwd, name, nil); action != "allow" {
				t.Errorf("%s Delete File %q: %s %v, want allow", profile, name, action, rules)
			}
		}
	}
}

// Every spelling Windows opens as the credential file of the home is judged
// as the plain name is, for a delete as for an add, in every profile.
func TestWindowsTypedPatchDeleteOfCredentialFileIsJudgedInEverySpellingWindowsOpens(t *testing.T) {
	useShortNames(t, map[string]string{"NETRC~1": ".netrc", "R109YW~1": "r109yws.d-2"})
	const home = `C:\Users\r109yws.d-2`
	spellings := func(file string) []string {
		return []string{
			home + `\` + file, `C:/Users/r109yws.d-2/` + file, `\\?\` + home + `\` + file, `\\.\` + home + `\` + file,
			`\\localhost\C$\Users\r109yws.d-2\` + file, `\\127.0.0.1\c$\Users\r109yws.d-2\` + file,
			`\\?\UNC\localhost\c$\Users\r109yws.d-2\` + file, home + `\` + file + `.`, home + `\` + file + `::$DATA`,
			`C:\USERS\R109YWS.D-2\` + file, `c:\users\r109yws.d-2\` + file, `\\?\C:\Users\R109YW~1\` + file,
		}
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-typed-patch-delete-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, file := range []string{`.netrc`, `.git-credentials`, `.aws\credentials`, `.kube\config`} {
			for _, cwd := range []string{home, home + `\project`, `D:\work`} {
				for _, name := range spellings(file) {
					if action, rules := windowsPatchVerdictIn(t, connector, "Delete File", home, cwd, name); action != "block" {
						t.Errorf("%s cwd=%q Delete File %q: %s %v, want block", profile, cwd, name, action, rules)
					}
				}
			}
		}
	}
}
