// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestAccountHomeByPosition pins what counts as an account home
// (rel-1-0-10:GAP-0810, GAP-0836): a home root and one account folder, found by
// position (/root, /home/<a>, /Users/<a>, <drive>:/Users/<a>). A folder that
// only has such a name deeper in a path is a project folder, never a home.
func TestAccountHomeByPosition(t *testing.T) {
	for dir, want := range map[string]bool{
		"/home/bob": true, "/users/bob": true, "/root": true, "d:/users/bob": true, "c:/users/bob": true,
		"/mnt/home/alice": false, "/srv/homes/carol": false, "/Volumes/data/Users/bob": false,
		"//server/share/users/bob": false, "/work/repo/home/bob": false, "/repo/users/bob": false,
		"/work/f5proj": false, "/repo/app": false, "/srv/data/proj": false, "/home": false, "/": false, "": false,
		"/home/bob/proj": false, "c:/work/proj": false, "c:/users": false, "c:/work/users/bob": false,
	} {
		if got := isRecognizedHomeRoot(canonicalSemanticPath(dir)); got != want {
			t.Errorf("isRecognizedHomeRoot(%q) = %t, want %t", dir, got, want)
		}
	}
}

// TestOtherHomeCredentialFileShapes: the home-only credentials shapes are read
// in the account homes outside the active home (by position), never in a project
// folder, never a name projects ship (.npmrc, .env), a template or a relative path.
func TestOtherHomeCredentialFileShapes(t *testing.T) {
	facts := actionfacts.Facts{ActiveHome: "/home/alice", CWD: "/home/alice/proj"}
	for _, tc := range []struct {
		value string
		class actionfacts.CredentialFileClass
		want  bool
	}{
		{"/home/carol/.aws/credentials", actionfacts.CredentialFileAWS, true},
		{"/Users/carol/.kube/config", actionfacts.CredentialFileKubeconfig, true},
		{"/root/.git-credentials", actionfacts.CredentialFileDeveloperToken, true},
		{"/home/carol/.netrc", actionfacts.CredentialFileDeveloperToken, true},
		{"/home/carol/.docker/config.json", actionfacts.CredentialFilePackageRegistry, true},
		{"/home/carol/.config/gh/hosts.yml", actionfacts.CredentialFileCloudCLI, true},
		{"D:\\Users\\bob\\.aws\\credentials", actionfacts.CredentialFileAWS, true},
		{"C:/Users/bob/.netrc", actionfacts.CredentialFileDeveloperToken, true},
		{"/home/carol/.npmrc", actionfacts.CredentialFilePackageRegistry, false},
		{"/home/carol/proj/.env", actionfacts.CredentialFileEnvironment, false},
		{"/home/carol/.aws/credentials.example", actionfacts.CredentialFileAWS, false},
		{"/work/f5proj/.aws/credentials", actionfacts.CredentialFileAWS, false},
		{"/home/alice/proj/.aws/credentials", actionfacts.CredentialFileAWS, false},
		{"/home/carol/proj/.aws/credentials", actionfacts.CredentialFileAWS, false},
		{"/mnt/home/carol/.aws/credentials", actionfacts.CredentialFileAWS, false},
		{"/srv/homes/carol/.netrc", actionfacts.CredentialFileDeveloperToken, false},
		{".aws/credentials", actionfacts.CredentialFileAWS, false},
		{"/home/carol/.aws/credentials", actionfacts.CredentialFileKubeconfig, false},
	} {
		got := otherHomeCredentialFile(facts, actionfacts.PathFact{Value: tc.value, Resolved: tc.value}, tc.class, "")
		if got != tc.want {
			t.Errorf("otherHomeCredentialFile(%q, %s) = %t, want %t", tc.value, tc.class, got, tc.want)
		}
	}
}

// TestOtherHomeCredentialFileProjectAndWorkingFolder (rel-1-0-10:GAP-0836,
// GAP-0837): a folder called Users, home or homes below the working folder is a
// folder of the project (a fixture tree), whatever the working folder is, and
// the working folder inside another account's home makes a relative operand that
// account's file. No path rule reads a folder name; the home is where it sits.
func TestOtherHomeCredentialFileProjectAndWorkingFolder(t *testing.T) {
	aws := actionfacts.CredentialFileAWS
	for _, tc := range []struct {
		name, cwd, value string
		want             bool
	}{
		{"fixture tree named Users in the repo", "/repo", "/repo/Users/bob/.aws/credentials", false},
		{"fixture tree named home below the cwd", "/work/repo", "/work/repo/home/bob/.aws/credentials", false},
		{"fixture tree in a CI home", "/home/ci/work", "/home/ci/work/home/bob/.aws/credentials", false},
		{"cwd is the fixture tree itself", "/repo/Users", "/repo/Users/bob/.aws/credentials", false},
		{"cwd is the other home", "/home/x", "/home/x/.aws/credentials", true},
		{"cwd inside the other home", "/home/x/proj", "/home/x/.aws/credentials", true},
		{"cwd beside the other home", "/work", "/home/x/.aws/credentials", true},
		{"no cwd, a home", "", "/home/x/.aws/credentials", true},
		{"no cwd, /root", "", "/root/.aws/credentials", true},
		{"no cwd, a Windows Users folder", "", "C:/Users/x/.aws/credentials", true},
		{"no cwd, a project folder named homes", "", "/srv/app/homes/x/.aws/credentials", false},
		{"no cwd, a project folder named users", "", "/work/repo/users/bob/.aws/credentials", false},
	} {
		facts := actionfacts.Facts{ActiveHome: "/home/alice", CWD: tc.cwd}
		got := otherHomeCredentialFile(facts, actionfacts.PathFact{Value: tc.value, Resolved: tc.value}, aws, "")
		if got != tc.want {
			t.Errorf("%s: otherHomeCredentialFile(cwd %q, %q) = %t, want %t", tc.name, tc.cwd, tc.value, got, tc.want)
		}
	}
	// The SSH key of a fixture tree below the cwd is not a key; the key of an account home is.
	for _, tc := range []struct {
		cwd, value string
		want       bool
	}{
		{"/repo", "/repo/Users/bob/.ssh/id_rsa", false},
		{"/repo", "/repo/homes/bob/.ssh/id_ed25519", false},
		{"/home/x", "/home/x/.ssh/id_rsa", true},
		{"/work", "/Users/x/.ssh/id_rsa", true},
		{"/work", "C:/Users/x/.ssh/id_rsa", true},
	} {
		facts := actionfacts.Facts{ActiveHome: "/home/alice", CWD: tc.cwd}
		got := matchesContextualSSHPrivateKey(facts, actionfacts.PathFact{Value: tc.value, Resolved: tc.value})
		if got != tc.want {
			t.Errorf("ssh key (cwd %q, %q) = %t, want %t", tc.cwd, tc.value, got, tc.want)
		}
	}
}
