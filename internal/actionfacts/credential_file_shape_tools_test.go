// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// One row per developer CLI or agent login file (credential_file_shape.go):
// the documented path is a credentials file and a similarly named
// non-credential file is not.
func TestMatchCredentialFileShapeDeveloperToolLogins(t *testing.T) {
	for _, row := range []struct {
		name     string
		path     string
		class    CredentialFileClass
		relative string
		// notCredential names look-alikes the table must not match.
		notCredential []string
	}{
		{"Claude Code", "/home/alice/.claude/.credentials.json", CredentialFileCloudCLI, ".credentials.json",
			[]string{"/home/alice/.claude/credentials.json.md", "/home/alice/.claude/settings.json", "/home/alice/.claude/.credentials.json.example"}},
		{"Claude Code on Windows", `C:\Users\alice\.claude\.credentials.json`, CredentialFileCloudCLI, ".credentials.json",
			[]string{`C:\Users\alice\.claude\credentials.txt`}},
		{"Claude Code CLAUDE_CONFIG_DIR", "/home/alice/.claude-work/.credentials.json", CredentialFileCloudCLI, ".credentials.json",
			[]string{"/home/alice/.claude-work/.claude.json"}},
		{"Codex CLI", "/home/alice/.codex/auth.json", CredentialFileCloudCLI, ".codex/auth.json",
			[]string{"/home/alice/.codex/config.toml", "/home/alice/project/auth.json", "/home/alice/.codex/auth.json.sample"}},
		{"Gemini CLI", "/home/alice/.gemini/oauth_creds.json", CredentialFileCloudCLI, ".gemini/oauth_creds.json",
			[]string{"/home/alice/.gemini/settings.json", "/home/alice/.gemini/google_accounts.json", "/home/alice/oauth_creds.json"}},
		{"Copilot CLI", "/home/alice/.copilot/config.json", CredentialFileCloudCLI, ".copilot/config.json",
			[]string{"/home/alice/.copilot/settings.json", "/home/alice/project/config.json"}},
		{"Copilot hosts", "/home/alice/.config/github-copilot/hosts.json", CredentialFileCloudCLI, ".config/github-copilot/hosts.json",
			[]string{"/home/alice/.config/github-copilot/versions.json", "/home/alice/.config/other/hosts.json"}},
		{"Copilot apps", "/home/alice/.config/github-copilot/apps.json", CredentialFileCloudCLI, ".config/github-copilot/apps.json",
			[]string{"/home/alice/.config/github-copilot/intellij/global.json"}},
		{"Copilot hosts on Windows", `C:\Users\alice\AppData\Local\github-copilot\hosts.json`, CredentialFileCloudCLI, "appdata/local/github-copilot/hosts.json",
			[]string{`C:\Users\alice\AppData\Local\github-copilot\versions.json`}},
		{"git XDG store", "/home/alice/.config/git/credentials", CredentialFileDeveloperToken, ".config/git/credentials",
			[]string{"/home/alice/.config/git/config", "/home/alice/.config/git/ignore", "/home/alice/.config/gitx/credentials"}},
		{"Vault token", "/home/alice/.vault-token", CredentialFileDeveloperToken, ".vault-token",
			[]string{"/home/alice/.vault-token.example", "/home/alice/vault-token", "/home/alice/.vault.hcl"}},
		{"Terraform", "/home/alice/.terraform.d/credentials.tfrc.json", CredentialFileDeveloperToken, ".terraform.d/credentials.tfrc.json",
			[]string{"/home/alice/.terraform.d/checkpoint_cache", "/work/p/credentials.tfrc.json", "/home/alice/.terraform.d/plugins/x.json"}},
		{"Terraform on Windows", `C:\Users\alice\AppData\Roaming\terraform.d\credentials.tfrc.json`, CredentialFileDeveloperToken, "appdata/roaming/terraform.d/credentials.tfrc.json",
			[]string{`C:\Users\alice\AppData\Roaming\terraform.d\terraform.rc`}},
		{"Cargo credentials.toml", "/home/alice/.cargo/credentials.toml", CredentialFileDeveloperToken, ".cargo/credentials.toml",
			[]string{"/home/alice/.cargo/config.toml", "/work/p/credentials.toml", "/home/alice/.cargo/credentials.toml.example"}},
		{"Cargo credentials", "/home/alice/.cargo/credentials", CredentialFileDeveloperToken, ".cargo/credentials",
			[]string{"/home/alice/.cargo/env", "/home/alice/.cargo/registry/credentials-notes"}},
		{"RubyGems", "/home/alice/.gem/credentials", CredentialFileDeveloperToken, ".gem/credentials",
			[]string{"/home/alice/.gem/specs", "/work/p/gem/credentials", "/home/alice/.gem/credentials.template"}},
		{"podman auth", "/home/alice/.config/containers/auth.json", CredentialFilePackageRegistry, "containers/auth.json",
			[]string{"/home/alice/.config/containers/policy.json", "/home/alice/.config/containers/registries.conf", "/work/p/auth.json"}},
		{"podman runtime auth", "/run/user/1000/containers/auth.json", CredentialFilePackageRegistry, "containers/auth.json",
			[]string{"/run/user/1000/containers/storage.conf"}},
		{"AWS SSO cache", "/home/alice/.aws/sso/cache/0a1b2c3d.json", CredentialFileCloudCLI, ".aws/sso/cache/0a1b2c3d.json",
			[]string{"/home/alice/.aws/sso/cache/README", "/home/alice/.aws/sso/cache/0a1b.json.sample", "/home/alice/.aws/sso/0a1b.json", "/work/p/sso/cache/0a1b.json"}},
		{"AWS CLI cache", "/home/alice/.aws/cli/cache/9f8e7d.json", CredentialFileCloudCLI, ".aws/cli/cache/9f8e7d.json",
			[]string{"/home/alice/.aws/cli/alias", "/home/alice/.aws/cli/cache/notes.txt", "/home/alice/.aws/config"}},
		{"AWS SSO cache on Windows", `C:\Users\alice\.aws\sso\cache\abc.json`, CredentialFileCloudCLI, ".aws/sso/cache/abc.json",
			[]string{`C:\Users\alice\.aws\sso\cache\abc.md`}},
		{"gcloud legacy credentials", "/home/alice/.config/gcloud/legacy_credentials/dev@example.com/adc.json", CredentialFileCloudCLI, ".config/gcloud/legacy_credentials/dev@example.com/adc.json",
			[]string{"/home/alice/.config/gcloud/configurations/config_default", "/home/alice/.config/gcloud/logs/2026.01.01/x.log", "/home/alice/.config/gcloud/legacy_credentials"}},
		{"gcloud legacy .boto", "/home/alice/.config/gcloud/legacy_credentials/dev@example.com/.boto", CredentialFileCloudCLI, ".config/gcloud/legacy_credentials/dev@example.com/.boto",
			nil},
		{"gcloud legacy on Windows", `C:\Users\alice\AppData\Roaming\gcloud\legacy_credentials\dev@example.com\adc.json`, CredentialFileCloudCLI, "appdata/roaming/gcloud/legacy_credentials/dev@example.com/adc.json",
			[]string{`C:\Users\alice\AppData\Roaming\gcloud\properties`}},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, ok := MatchCredentialFileShape(row.path)
			if !ok || got.Class != row.class || got.Relative != row.relative {
				t.Errorf("MatchCredentialFileShape(%q) = %+v, %t; want class %q relative %q",
					row.path, got, ok, row.class, row.relative)
			}
			for _, path := range row.notCredential {
				if got, ok := MatchCredentialFileShape(path); ok {
					t.Errorf("MatchCredentialFileShape(%q) = %+v, want no credentials-file shape", path, got)
				}
			}
		})
	}
}
