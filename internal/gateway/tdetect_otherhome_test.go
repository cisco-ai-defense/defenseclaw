// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestHomeLikeDirectory pins what counts as an account's home by where it sits
// (rel-1-0-10:GAP-0810), with the Windows spellings as parity rows.
func TestHomeLikeDirectory(t *testing.T) {
	for dir, want := range map[string]bool{
		"/home/bob": true, "/mnt/home/alice": true, "/srv/homes/carol": true, "/Volumes/data/Users/bob": true,
		"/users/bob": true, "/root": true, "d:/users/bob": true, "c:/users/bob": true, "//server/share/users/bob": true,
		"/work/f5proj": false, "/repo/app": false, "/srv/data/proj": false, "/home": false, "/": false, "": false,
		"/home/bob/proj": false, "c:/work/proj": false, "c:/users": false,
	} {
		if got := homeLikeDirectory(canonicalSemanticPath(dir)); got != want {
			t.Errorf("homeLikeDirectory(%q) = %t, want %t", dir, got, want)
		}
	}
}

// TestOtherHomeCredentialFileShapes: the home-only credentials shapes are read
// in any home-like folder outside the active home, never in a project folder,
// never a name projects ship (.npmrc, .env), a template or a relative path.
func TestOtherHomeCredentialFileShapes(t *testing.T) {
	facts := actionfacts.Facts{ActiveHome: "/home/alice", CWD: "/home/alice/proj"}
	for _, tc := range []struct {
		value string
		class actionfacts.CredentialFileClass
		want  bool
	}{
		{"/mnt/home/alice/.aws/credentials", actionfacts.CredentialFileAWS, true},
		{"/srv/homes/carol/.kube/config", actionfacts.CredentialFileKubeconfig, true},
		{"/srv/homes/carol/.git-credentials", actionfacts.CredentialFileDeveloperToken, true},
		{"/srv/homes/carol/.netrc", actionfacts.CredentialFileDeveloperToken, true},
		{"/srv/homes/carol/.docker/config.json", actionfacts.CredentialFilePackageRegistry, true},
		{"/srv/homes/carol/.config/gh/hosts.yml", actionfacts.CredentialFileCloudCLI, true},
		{"D:\\Users\\bob\\.aws\\credentials", actionfacts.CredentialFileAWS, true},
		{"/srv/homes/carol/.npmrc", actionfacts.CredentialFilePackageRegistry, false},
		{"/srv/homes/carol/proj/.env", actionfacts.CredentialFileEnvironment, false},
		{"/srv/homes/carol/.aws/credentials.example", actionfacts.CredentialFileAWS, false},
		{"/work/f5proj/.aws/credentials", actionfacts.CredentialFileAWS, false},
		{"/home/alice/proj/.aws/credentials", actionfacts.CredentialFileAWS, false},
		{"/srv/homes/carol/proj/.aws/credentials", actionfacts.CredentialFileAWS, false},
		{".aws/credentials", actionfacts.CredentialFileAWS, false},
		{"/srv/homes/carol/.aws/credentials", actionfacts.CredentialFileKubeconfig, false},
	} {
		got := otherHomeCredentialFile(facts, actionfacts.PathFact{Value: tc.value, Resolved: tc.value}, tc.class, "")
		if got != tc.want {
			t.Errorf("otherHomeCredentialFile(%q, %s) = %t, want %t", tc.value, tc.class, got, tc.want)
		}
	}
}
