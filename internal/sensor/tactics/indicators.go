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

import "runtime"

// IndicatorSet is what counts as suspicious on one operating system.
//
// This is the layer people forget when porting a detector. /Library/LaunchAgents
// is how a Mac gains persistence; a systemd unit or a crontab is how Linux
// does it, and a Run key is how Windows does. A detector that ports its
// acquisition but not its indicators reports a clean host because it is
// looking in the wrong place, which is worse than refusing to run.
type IndicatorSet struct {
	// CredentialPaths are fixed substrings identifying a secret at rest.
	// Fixed strings rather than patterns so the match is cheap enough for the
	// event hot path.
	CredentialPaths []string
	// HighConfidenceCredentials are the subset whose read is unambiguous. A
	// generic ~/.config read is weak; ~/.aws/credentials is not.
	HighConfidenceCredentials []string
	// PersistencePaths are locations that arrange for something to run again.
	PersistencePaths []string
	// AgentConfigPaths are the agent's own standing configuration. An agent
	// that rewrites these is arranging to influence every future session on
	// the machine, which no launch item and no login item would show.
	AgentConfigPaths []string
}

// portableCredentialPaths are the secrets at rest that exist on every
// platform this sensor supports.
var portableCredentialPaths = []string{
	"/.aws/credentials", "/.aws/config",
	"/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/id_ecdsa", "/.ssh/id_dsa",
	"/.config/gcloud/credentials.db",
	"/.config/gcloud/application_default_credentials.json",
	"/.kube/config", "/.docker/config.json",
	"/.netrc", "/.npmrc", "/.pypirc", "/.git-credentials",
	"/.gnupg/secring.gpg", "/.gnupg/private-keys-v1.d/",
	"/credentials.json", "/service-account.json",
	"/.env", "/.env.local", "/.env.production",
}

// portableHighConfidence are the ones whose read is unambiguous on any host.
var portableHighConfidence = []string{
	"/.aws/credentials",
	"/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/id_ecdsa", "/.ssh/id_dsa",
	"/.config/gcloud/credentials.db",
	"/.config/gcloud/application_default_credentials.json",
	"/.kube/config", "/.docker/config.json",
	"/.git-credentials", "/.gnupg/secring.gpg",
}

// portableAgentConfigPaths are the standing configurations an agent can use to
// influence its own future sessions. These are the same on every platform
// because the connectors put them in the same relative place.
var portableAgentConfigPaths = []string{
	"/.claude/settings.json", "/.claude/settings.local.json",
	"/.claude/hooks/", "/.claude/skills/", "/CLAUDE.md",
	"/.codex/config.toml", "/.codex/skills/",
	"/.cursor/mcp.json", "/.cursor/rules/",
	"/.openclaw/", "/.zeptoclaw/",
	"/.config/github-copilot/", "/AGENTS.md",
	"/.mcp.json", "/mcp.json",
}

var darwinIndicators = IndicatorSet{
	CredentialPaths: append(append([]string{}, portableCredentialPaths...),
		"/Library/Keychains/", "/.aws/sso/cache/",
		"/Library/Application Support/com.apple.TCC/",
	),
	HighConfidenceCredentials: append(append([]string{}, portableHighConfidence...),
		"/Library/Keychains/login.keychain-db",
	),
	PersistencePaths: []string{
		"/Library/LaunchAgents/", "/Library/LaunchDaemons/",
		"/Library/StartupItems/", "/Library/Application Support/com.apple.backgroundtaskmanagement/",
		"/etc/periodic/", "/etc/rc.common", "/.bashrc", "/.bash_profile",
		"/.zshrc", "/.zprofile", "/.profile", "/etc/sudoers.d/",
	},
	AgentConfigPaths: portableAgentConfigPaths,
}

var linuxIndicators = IndicatorSet{
	CredentialPaths: append(append([]string{}, portableCredentialPaths...),
		"/etc/shadow", "/etc/gshadow",
		"/var/lib/kubelet/", "/run/secrets/",
	),
	HighConfidenceCredentials: append(append([]string{}, portableHighConfidence...),
		"/etc/shadow",
	),
	PersistencePaths: []string{
		"/etc/systemd/system/", "/usr/lib/systemd/system/", "/lib/systemd/system/",
		"/.config/systemd/user/",
		"/etc/crontab", "/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/",
		"/var/spool/cron/",
		"/etc/init.d/", "/etc/rc.local", "/etc/profile.d/",
		"/.bashrc", "/.bash_profile", "/.profile", "/.zshrc",
		"/.config/autostart/", "/etc/xdg/autostart/", "/etc/sudoers.d/",
	},
	AgentConfigPaths: portableAgentConfigPaths,
}

var windowsIndicators = IndicatorSet{
	CredentialPaths: append(append([]string{}, portableCredentialPaths...),
		`\AppData\Roaming\gcloud\`, `\AppData\Local\Microsoft\Credentials\`,
		`\AppData\Roaming\Microsoft\Credentials\`,
		`\Microsoft\Protect\`, `\.aws\credentials`, `\.ssh\id_rsa`,
	),
	HighConfidenceCredentials: append(append([]string{}, portableHighConfidence...),
		`\.aws\credentials`, `\AppData\Local\Microsoft\Credentials\`,
	),
	PersistencePaths: []string{
		`\CurrentVersion\Run`, `\CurrentVersion\RunOnce`,
		`\Start Menu\Programs\Startup\`,
		`\System32\Tasks\`, `\Windows\Tasks\`,
		`\WindowsPowerShell\profile.ps1`, `\PowerShell\profile.ps1`,
		`\Microsoft\Windows\PowerShell\`,
	},
	AgentConfigPaths: portableAgentConfigPaths,
}

// Indicators returns the set for the host this process runs on.
//
// Selected by GOOS rather than by a passed-in name because the classifier runs
// in the same process as the acquisition. A cross-host classifier would need a
// parameter here, and a test that wants one uses IndicatorsFor.
func Indicators() IndicatorSet { return IndicatorsFor(runtime.GOOS) }

// IndicatorsFor returns the set for a named platform, so Linux behaviour is
// verifiable from a Mac.
func IndicatorsFor(goos string) IndicatorSet {
	switch goos {
	case "darwin":
		return darwinIndicators
	case "windows":
		return windowsIndicators
	default:
		return linuxIndicators
	}
}
