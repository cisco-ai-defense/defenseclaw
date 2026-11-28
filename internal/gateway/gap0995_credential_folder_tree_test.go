// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// substrate-1:GAP-0995 part 2: an archive or a recursive copy of the
// credentials folder of an account reads the credentials files in it, so it
// gets the finding the read of the file gets, from the same rule. The home,
// the shared roots in it (.config), a folder below the one that holds the
// file and a project folder are no credentials folder, and a copy or an
// archive that does not take the folder tree (cp, rsync -d, zip without -r)
// reads no file in it. The call takes the verdict of the read of the file,
// not only its finding.
func TestGAP0995CredentialFolderTreeReadIsTheFileRead(t *testing.T) {
	const connector = "gap0995-folder-tree-test"
	installDefaultProfileConnector(t, connector)
	check := func(command string) []RuleFinding {
		return dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: actionfacts.Input{Tool: "shell", Command: command, CWD: "/home/alice",
				ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX},
			LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
	}
	ruleIDs := []string{"PATH-AWS-CREDS", "PATH-KUBE", "PATH-DOCKER", "secrets.cloud_credential_read"}
	fileRead := "alert"
	for _, command := range []string{"cat ~/.aws/credentials", "cat ~/.kube/config", "cat ~/.docker/config.json", "cat ~/.config/gcloud/application_default_credentials.json"} {
		if got := buildVerdict(check(command), "tool_call").Action; got != fileRead {
			t.Fatalf("%q: action %s, want %s", command, got, fileRead)
		}
	}
	for _, tt := range []struct{ command, ruleID string }{
		{"tar cz ~/.aws", "PATH-AWS-CREDS"},
		{"tar czf /tmp/a.tgz /home/alice/.aws", "PATH-AWS-CREDS"},
		{"tar cz .aws", "PATH-AWS-CREDS"},
		{"cd ~ && tar cz .aws", "PATH-AWS-CREDS"},
		{"cd ~/.aws && tar cz .", "PATH-AWS-CREDS"},
		{"cd .aws && tar cz .", "PATH-AWS-CREDS"},
		{"zip -r /tmp/a.zip ~/.aws", "PATH-AWS-CREDS"},
		{"cp -r ~/.aws /tmp/a", "PATH-AWS-CREDS"},
		{"cp -a ~/.aws /tmp/a", "PATH-AWS-CREDS"},
		{"rsync -a ~/.aws /tmp/a", "PATH-AWS-CREDS"},
		{"rsync -rv ~/.aws/ /tmp/a/", "PATH-AWS-CREDS"},
		{"tar czf /tmp/b.tgz /home/bob/.aws", "PATH-AWS-CREDS"},
		{"tar cz ~/.kube", "PATH-KUBE"},
		{"cd ~/.kube && tar cz .", "PATH-KUBE"},
		{"tar cz ~/.docker", "PATH-DOCKER"},
		{"tar cz ~/.config/gcloud", "secrets.cloud_credential_read"},
		{"tar cz ~/.config/gcloud/legacy_credentials", "secrets.cloud_credential_read"},
		{"cd ~/.config && tar cz gh", "secrets.cloud_credential_read"},
		{"cd .config/gh && tar cz .", "secrets.cloud_credential_read"},
		{"cp -R ~/.config/gh /tmp/g", "secrets.cloud_credential_read"},
	} {
		t.Run(tt.command, func(t *testing.T) {
			findings := check(tt.command)
			if findingWithID(findings, tt.ruleID) == nil {
				t.Fatalf("%q: no %s finding, all=%v", tt.command, tt.ruleID, FindingStrings(findings))
			}
			// The verdict of the read of the file: a local credentials read
			// alerts in the default pack. The finding alone was not enough:
			// graded as a reference (LOW audit record), the call allowed.
			if got := buildVerdict(findings, "tool_call").Action; got != fileRead {
				t.Errorf("%q: action %s, want %s (the read of the file), all=%v", tt.command, got, fileRead, FindingStrings(findings))
			}
		})
	}
	for _, command := range []string{
		"tar cz ~",
		"tar czf /tmp/h.tgz -C ~ .",
		"tar czf /tmp/c.tgz ~/.config",
		"cp -r ~/.config /tmp/c",
		"tar cz ~/.config/gcloud/configurations",
		"tar cz proj/.aws",
		"zip /tmp/a.zip ~/.aws",
		"rsync -d ~/.aws /tmp/a",
		"cp ~/.aws/config /tmp/c",
		"ls ~/.aws",
		"tar czf /tmp/p.tgz src",
		"cd ~ && tar cz src",
		"cp -r src /tmp/s",
	} {
		t.Run("benign/"+command, func(t *testing.T) {
			findings := check(command)
			for _, ruleID := range ruleIDs {
				if got := findingWithID(findings, ruleID); got != nil {
					t.Errorf("%q: %s finding %+v, all=%v", command, ruleID, got, FindingStrings(findings))
				}
			}
		})
	}
}
