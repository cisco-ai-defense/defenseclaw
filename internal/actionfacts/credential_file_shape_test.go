// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestMatchCredentialFileShapeTable(t *testing.T) {
	tests := []struct {
		path     string
		class    CredentialFileClass
		relative string
		strong   bool
	}{
		// Environment files: .env and .env.<stage>, anywhere.
		{path: "/work/f5proj/.env", class: CredentialFileEnvironment, relative: ".env"},
		{path: ".env", class: CredentialFileEnvironment, relative: ".env"},
		{path: "~/.env", class: CredentialFileEnvironment, relative: ".env"},
		{path: "/srv/app/.env.production", class: CredentialFileEnvironment, relative: ".env.production"},
		{path: "app/.env.backup", class: CredentialFileEnvironment, relative: ".env.backup"},
		{path: `C:\work\proj\.env.local`, class: CredentialFileEnvironment, relative: ".env.local"},
		// SSH private keys: the key names anywhere, any id_* in an .ssh folder.
		{path: "/work/f5proj/id_rsa", class: CredentialFileSSHPrivateKey, relative: "id_rsa", strong: true},
		{path: "/work/f5proj/.ssh/id_rsa", class: CredentialFileSSHPrivateKey, relative: "id_rsa", strong: true},
		{path: "~/.ssh/id_ed25519_sk", class: CredentialFileSSHPrivateKey, relative: "id_ed25519_sk", strong: true},
		{path: "~/.ssh/id_github", class: CredentialFileSSHPrivateKey, relative: ".ssh/id_github", strong: true},
		{path: `C:\Users\alice\.ssh\id_ecdsa`, class: CredentialFileSSHPrivateKey, relative: "id_ecdsa", strong: true},
		// AWS: credentials (and a copy beside it) under any .aws folder.
		{path: "/work/f5proj/.aws/credentials", class: CredentialFileAWS, relative: ".aws/credentials", strong: true},
		{path: ".aws/credentials", class: CredentialFileAWS, relative: ".aws/credentials", strong: true},
		{path: "/home/alice/.aws/credentials", class: CredentialFileAWS, relative: ".aws/credentials", strong: true},
		{path: "/home/alice/.aws/credentials.bak", class: CredentialFileAWS, relative: ".aws/credentials.bak"},
		{path: "/home/alice/.aws/credentials.orig", class: CredentialFileAWS, relative: ".aws/credentials.orig"},
		{path: "~/.ssh/id_rsa.old", class: CredentialFileSSHPrivateKey, relative: ".ssh/id_rsa.old", strong: true},
		{path: `C:\Users\alice\.aws\credentials`, class: CredentialFileAWS, relative: ".aws/credentials", strong: true},
		// Kubernetes, registries, developer tokens, cloud CLI tokens.
		{path: "/work/p/.kube/config", class: CredentialFileKubeconfig, relative: ".kube/config", strong: true},
		{path: "/work/p/.docker/config.json", class: CredentialFilePackageRegistry, relative: ".docker/config.json"},
		{path: "/work/p/.npmrc", class: CredentialFilePackageRegistry, relative: ".npmrc", strong: true},
		{path: "/work/p/.pypirc", class: CredentialFilePackageRegistry, relative: ".pypirc", strong: true},
		{path: "/work/p/.git-credentials", class: CredentialFileDeveloperToken, relative: ".git-credentials", strong: true},
		{path: "~/.netrc", class: CredentialFileDeveloperToken, relative: ".netrc", strong: true},
		{path: `C:\Users\alice\_netrc`, class: CredentialFileDeveloperToken, relative: "_netrc"},
		{path: "/work/p/.pgpass", class: CredentialFileDeveloperToken, relative: ".pgpass"},
		{path: "~/.cache/huggingface/token", class: CredentialFileDeveloperToken, relative: ".cache/huggingface/token"},
		{path: "/work/p/.config/gh/hosts.yml", class: CredentialFileCloudCLI, relative: ".config/gh/hosts.yml"},
		{path: "~/.config/gcloud/application_default_credentials.json", class: CredentialFileCloudCLI, relative: ".config/gcloud/application_default_credentials.json"},
		{path: `C:\Users\alice\AppData\Roaming\GitHub CLI\hosts.yml`, class: CredentialFileCloudCLI, relative: "appdata/roaming/github cli/hosts.yml"},
		{path: "~/.azure/msal_token_cache.json", class: CredentialFileCloudCLI, relative: ".azure/msal_token_cache.json"},
		// Private key files known only by name.
		{path: "/work/p/certs/server.key", class: CredentialFilePrivateKey, relative: "server.key"},
		{path: "/work/p/tls/server-key.pem", class: CredentialFilePrivateKey, relative: "server-key.pem"},
		{path: "/etc/letsencrypt/live/x/privkey.pem", class: CredentialFilePrivateKey, relative: "privkey.pem"},
		{path: "/work/p/id_rsa.pem", class: CredentialFilePrivateKey, relative: "id_rsa.pem"},
		{path: "/work/p/client.p12", class: CredentialFilePrivateKey, relative: "client.p12"},
	}
	for _, test := range tests {
		got, ok := MatchCredentialFileShape(test.path)
		if !ok || got.Class != test.class || got.Relative != test.relative || got.StrongUpload != test.strong {
			t.Errorf("MatchCredentialFileShape(%q) = %+v, %t; want class %q relative %q strong %t",
				test.path, got, ok, test.class, test.relative, test.strong)
		}
	}
}

func TestMatchCredentialFileShapeExclusions(t *testing.T) {
	for _, path := range []string{
		// Public keys.
		"/work/p/.ssh/id_rsa.pub", "~/.ssh/id_ed25519.pub", "/work/p/id_rsa-cert.pub",
		// .env templates a repository ships.
		"/work/p/.env.example", "/work/p/.env.sample", "/work/p/.env.template",
		"/work/p/.env.dist", "/work/p/.env.local.example", "/work/p/.env.defaults",
		"/work/p/.env.tpl", "/work/p/.env.md",
		// Templates and samples of the other name variants.
		"/work/p/.aws/credentials.example", "/work/p/.aws/credentials.template",
		"/work/p/.ssh/id_rsa.sample", "~/.ssh/id_ed25519.tpl",
		`C:\work\p\.aws\credentials.sample`,
		// Certificates, chains and public keys in PEM.
		"/work/p/certs/ca.pem", "/work/p/fullchain.pem", "/work/p/cert.pem",
		"/work/p/pubkey.pem", "/work/p/public.key", "/work/p/server.crt",
		// Names that only look close.
		"/work/p/.envrc", "/work/p/environment.ts", "/work/p/.aws/config",
		"/work/p/aws/credentials", "/work/p/credentials", "/work/p/kube/config",
		"/work/p/id_card.go", "/work/p/.ssh/known_hosts", "/work/p/.ssh/config",
		"/work/p/hosts.yml", "/work/p/.key", "/work/p/.pem", "", "/",
	} {
		if got, ok := MatchCredentialFileShape(path); ok {
			t.Errorf("MatchCredentialFileShape(%q) = %+v, want no credentials-file shape", path, got)
		}
	}
}

func TestCredentialFileUploadClassReadsTheTable(t *testing.T) {
	for path, want := range map[string]string{
		"/work/f5proj/.aws/credentials":                       CredentialFileUploadStrong,
		"/work/f5proj/id_rsa":                                 CredentialFileUploadStrong,
		"/home/alice/.ssh/id_work":                            CredentialFileUploadStrong,
		"/work/p/.netrc":                                      CredentialFileUploadStrong,
		"/work/p/.kube/config":                                CredentialFileUploadStrong,
		"/var/run/secrets/kubernetes.io/serviceaccount/token": CredentialFileUploadStrong,
		"/etc/kubernetes/admin.conf":                          CredentialFileUploadKubeAdminConfig,
		"/home/alice/.ssh/id_rsa.pub":                         "",
		"/work/p/.env":                                        "",
		"/work/p/server.key":                                  "",
		"relative/.aws/credentials":                           "",
	} {
		if got := credentialFileUploadClass(path); got != want {
			t.Errorf("credentialFileUploadClass(%q) = %q, want %q", path, got, want)
		}
	}
}
