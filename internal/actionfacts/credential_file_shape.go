// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

// CredentialFileClass is the kind of secret a file of a known
// credentials-file shape holds.
type CredentialFileClass string

const (
	CredentialFileEnvironment     CredentialFileClass = "environment_file"
	CredentialFileSSHPrivateKey   CredentialFileClass = "ssh_private_key"
	CredentialFileAWS             CredentialFileClass = "aws_credentials"
	CredentialFileKubeconfig      CredentialFileClass = "kubeconfig"
	CredentialFilePackageRegistry CredentialFileClass = "package_registry_config"
	CredentialFileDeveloperToken  CredentialFileClass = "developer_token"
	CredentialFileCloudCLI        CredentialFileClass = "cloud_cli_token"
	CredentialFilePrivateKey      CredentialFileClass = "private_key_file"
)

// CredentialFileShape is the one entry of credentialFileShapes that a path
// matches.
type CredentialFileShape struct {
	Class CredentialFileClass
	// Relative is the part of the path the entry names: the file name, or
	// the trailing components (".aws/credentials", ".config/gh/hosts.yml").
	// A path whose Relative is all of its home-relative path is that
	// account's own file.
	Relative string
	// StrongUpload marks the shapes whose static upload is a credential
	// exfiltration on its own (CredentialFileUploadStrong).
	StrongUpload bool
}

// credentialFileShape is one row of the credentials-file table. A row
// names either a file (base, or basePrefix with an optional dir) or a
// trailing relative path matched at a path component boundary, so the same
// row names the file in a home, in a project or in a work directory.
type credentialFileShape struct {
	class CredentialFileClass
	// relative: trailing path components, matched at a component boundary.
	relative string
	// folder: a trailing folder (matched at a component boundary) with the
	// files anywhere beneath it, narrowed by suffixes when set
	// (".aws/sso/cache" with ".json": every token cache file in it). It
	// names the cache and per-account folders whose file names are not
	// fixed.
	folder string
	// base: an exact file name, anywhere.
	base string
	// basePrefix: a file name prefix; with dir, only directly inside a
	// folder of that name (".ssh").
	basePrefix string
	dir        string
	// suffixes: the file name ends in one of them (with basePrefix: also).
	suffixes []string
	// stemAny / stemNone: with suffixes alone, the name before the suffix
	// must contain one of stemAny and none of stemNone (key.pem, not
	// cert.pem).
	stemAny, stemNone []string
	// strongUpload: see CredentialFileShape.StrongUpload.
	strongUpload bool
}

// credentialFileShapes is the single credentials-file table. The semantic
// path owners (PATH-ENV-FILE, PATH-SSH-KEY, PATH-AWS-CREDS, PATH-KUBE,
// PATH-DOCKER/NPMRC/PYPIRC, PATH-GIT-CREDS/NETRC, secrets.cloud_credential_read),
// the trusted sensitive-path dispositions, the credential-file upload class
// and the secret-read-then-egress chain all read it. A path is matched in
// its lower-case, forward-slash spelling.
//
// The home-only rules keep their own scope: they ask whether the matched
// Relative is the whole home-relative path. The chain does not: a
// credentials file in a project or a work directory starts it too
// (substrate-1:GAP-0210).
var credentialFileShapes = [...]credentialFileShape{
	{class: CredentialFileEnvironment, base: ".env"},
	// .env.<stage> and other variants (a template is not one, see
	// credentialFileTemplateSuffixes).
	{class: CredentialFileEnvironment, basePrefix: ".env."},

	{class: CredentialFileSSHPrivateKey, base: "id_rsa", strongUpload: true},
	{class: CredentialFileSSHPrivateKey, base: "id_ed25519", strongUpload: true},
	{class: CredentialFileSSHPrivateKey, base: "id_ecdsa", strongUpload: true},
	{class: CredentialFileSSHPrivateKey, base: "id_dsa", strongUpload: true},
	{class: CredentialFileSSHPrivateKey, base: "id_ecdsa_sk", strongUpload: true},
	{class: CredentialFileSSHPrivateKey, base: "id_ed25519_sk", strongUpload: true},
	// Any other id_* key directly in an .ssh folder (id_rsa_work, id_github).
	{class: CredentialFileSSHPrivateKey, dir: ".ssh", basePrefix: "id_", strongUpload: true},

	{class: CredentialFileAWS, relative: ".aws/credentials", strongUpload: true},
	// A copy kept beside it (credentials.bak, credentials.old).
	{class: CredentialFileAWS, dir: ".aws", basePrefix: "credentials."},

	{class: CredentialFileKubeconfig, relative: ".kube/config", strongUpload: true},

	{class: CredentialFilePackageRegistry, relative: ".docker/config.json"},
	{class: CredentialFilePackageRegistry, base: ".npmrc", strongUpload: true},
	{class: CredentialFilePackageRegistry, base: ".pypirc", strongUpload: true},

	{class: CredentialFileDeveloperToken, base: ".git-credentials", strongUpload: true},
	{class: CredentialFileDeveloperToken, base: ".netrc", strongUpload: true},
	{class: CredentialFileDeveloperToken, base: "_netrc"},
	{class: CredentialFileDeveloperToken, base: ".pgpass"},
	{class: CredentialFileDeveloperToken, relative: ".cache/huggingface/token"},
	{class: CredentialFileDeveloperToken, relative: ".huggingface/token"},
	{class: CredentialFileDeveloperToken, relative: ".config/huggingface/token"},
	{class: CredentialFileDeveloperToken, relative: ".config/pypoetry/auth.toml"},
	{class: CredentialFileDeveloperToken, relative: ".kaggle/kaggle.json"},
	{class: CredentialFileDeveloperToken, relative: "library/application support/pypoetry/auth.toml"},
	{class: CredentialFileDeveloperToken, relative: "appdata/roaming/pypoetry/auth.toml"},

	{class: CredentialFileCloudCLI, relative: ".config/gcloud/application_default_credentials.json"},
	{class: CredentialFileCloudCLI, relative: ".config/gcloud/credentials.db"},
	{class: CredentialFileCloudCLI, relative: ".config/gcloud/access_tokens.db"},
	{class: CredentialFileCloudCLI, relative: ".config/gh/hosts.yml"},
	{class: CredentialFileCloudCLI, relative: ".config/anthropic/keys.json"},
	{class: CredentialFileCloudCLI, relative: "appdata/roaming/gcloud/application_default_credentials.json"},
	{class: CredentialFileCloudCLI, relative: "appdata/roaming/gcloud/credentials.db"},
	{class: CredentialFileCloudCLI, relative: "appdata/roaming/gcloud/access_tokens.db"},
	{class: CredentialFileCloudCLI, relative: "appdata/roaming/github cli/hosts.yml"},
	{class: CredentialFileCloudCLI, relative: ".azure/azureprofile.json"},
	{class: CredentialFileCloudCLI, relative: ".azure/tokencache.dat"},
	{class: CredentialFileCloudCLI, dir: ".azure", basePrefix: "msal_token_cache", suffixes: []string{".json", ".bin"}},

	// Login and token files of developer CLIs and agents (S7 secret-read
	// table). Each row names the path the tool's public documentation gives.
	//
	// Claude Code: ~/.claude/.credentials.json (Linux, Windows, the macOS
	// keychain fallback), or .credentials.json under CLAUDE_CONFIG_DIR:
	// https://code.claude.com/docs/en/authentication#credential-management
	{class: CredentialFileCloudCLI, base: ".credentials.json"},
	// OpenAI Codex CLI: "~/.codex/auth.json" caches the login:
	// https://developers.openai.com/codex/auth (moved to
	// https://learn.chatgpt.com/docs/auth)
	{class: CredentialFileCloudCLI, relative: ".codex/auth.json"},
	// Google Gemini CLI: the cached OAuth login is oauth_creds.json in the
	// ~/.gemini folder (OAUTH_FILE in
	// https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/config/storage.ts;
	// the public docs only say the login is cached locally,
	// https://geminicli.com/docs/get-started/authentication/).
	{class: CredentialFileCloudCLI, relative: ".gemini/oauth_creds.json"},
	// GitHub Copilot CLI: the plaintext token fallback is ~/.copilot/config.json:
	// https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli
	{class: CredentialFileCloudCLI, relative: ".copilot/config.json"},
	// GitHub Copilot editor plugins: hosts.json and apps.json hold the OAuth
	// token (the plugins' own behavior; docs.github.com does not name them).
	{class: CredentialFileCloudCLI, relative: ".config/github-copilot/hosts.json"},
	{class: CredentialFileCloudCLI, relative: ".config/github-copilot/apps.json"},
	{class: CredentialFileCloudCLI, relative: "appdata/local/github-copilot/hosts.json"},
	{class: CredentialFileCloudCLI, relative: "appdata/local/github-copilot/apps.json"},

	// git-credential-store's second file, $XDG_CONFIG_HOME/git/credentials
	// (default $HOME/.config/git/credentials):
	// https://git-scm.com/docs/git-credential-store#FILES
	{class: CredentialFileDeveloperToken, relative: ".config/git/credentials", strongUpload: true},
	// HashiCorp Vault's token helper file ~/.vault-token:
	// https://developer.hashicorp.com/vault/docs/commands/token-helper
	{class: CredentialFileDeveloperToken, base: ".vault-token"},
	// Terraform CLI credentials: ~/.terraform.d/credentials.tfrc.json, on
	// Windows %APPDATA%\terraform.d\credentials.tfrc.json:
	// https://developer.hashicorp.com/terraform/cli/config/config-file#credentials
	{class: CredentialFileDeveloperToken, relative: ".terraform.d/credentials.tfrc.json"},
	{class: CredentialFileDeveloperToken, relative: "appdata/roaming/terraform.d/credentials.tfrc.json"},
	// Cargo: $CARGO_HOME/credentials.toml, and the older credentials name
	// without the extension, both read and written:
	// https://doc.rust-lang.org/cargo/reference/config.html#credentials
	{class: CredentialFileDeveloperToken, relative: ".cargo/credentials.toml"},
	{class: CredentialFileDeveloperToken, relative: ".cargo/credentials"},
	// RubyGems: gem push and gem signin keep the API key in ~/.gem/credentials:
	// https://guides.rubygems.org/command-reference/#gem-push
	{class: CredentialFileDeveloperToken, relative: ".gem/credentials"},
	// podman login: ${XDG_RUNTIME_DIR}/containers/auth.json on Linux,
	// $HOME/.config/containers/auth.json on macOS and Windows:
	// https://docs.podman.io/en/latest/markdown/podman-login.1.html
	{class: CredentialFilePackageRegistry, relative: "containers/auth.json"},

	// AWS CLI: IAM Identity Center tokens are cached under ~/.aws/sso/cache
	// and assumed-role credentials under ~/.aws/cli/cache, one .json file
	// each:
	// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html#cli-configure-sso-login
	// https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-role.html#cli-configure-role-cache
	{class: CredentialFileCloudCLI, folder: ".aws/sso/cache", suffixes: []string{".json"}},
	{class: CredentialFileCloudCLI, folder: ".aws/cli/cache", suffixes: []string{".json"}},
	// gcloud: the per-account folder of legacy credentials (adc.json, .boto)
	// in the configuration directory, ~/.config/gcloud
	// (https://cloud.google.com/sdk/docs/configurations; the folder name
	// comes from the Cloud SDK, not from a public documentation page).
	{class: CredentialFileCloudCLI, folder: ".config/gcloud/legacy_credentials"},
	{class: CredentialFileCloudCLI, folder: "appdata/roaming/gcloud/legacy_credentials"},

	// Private key files known only by name: a .key file or a keystore, and
	// a .pem whose name says key (server-key.pem, privkey.pem), not a
	// certificate, a chain or a public key.
	{class: CredentialFilePrivateKey, suffixes: []string{".key", ".p12", ".pfx"}, stemNone: []string{"pub"}},
	{
		class: CredentialFilePrivateKey, suffixes: []string{".pem"},
		stemAny:  []string{"key", "priv", "id_"},
		stemNone: []string{"pub", "cert", "chain", "bundle", "trust"},
	},
}

// credentialFileTemplateSuffixes are the last dot-suffixes of a file name
// that mark a template or a sample a repository ships, not a credentials
// file: .env.example, .env.local.sample, .aws/credentials.template,
// .ssh/id_rsa.sample and the like. They apply to every row: a name the
// table matches exactly (.npmrc, .netrc) or by its key suffix (.key, .pem)
// never ends in one, so in practice they cut the name variants
// (.env.<x>, .aws/credentials.<x>, .ssh/id_<x>). A copy kept beside the
// real file (.bak, .old, .orig) stays a credentials file. The list comes
// from the owner traces (substrate-1:GAP-0210).
var credentialFileTemplateSuffixes = map[string]struct{}{
	"example": {}, "examples": {}, "sample": {}, "samples": {},
	"template": {}, "templates": {}, "tpl": {}, "tmpl": {}, "dist": {},
	"defaults": {}, "default": {}, "schema": {}, "skel": {}, "j2": {},
	"jinja": {}, "jinja2": {}, "md": {}, "txt": {},
}

// MatchCredentialFileShape returns the credentials-file table entry for a
// path (any spelling: absolute, relative, home-prefixed or a drive path; it
// is compared lower-case with forward slashes). A public key (*.pub) and a
// template or sample a repository ships (credentialFileTemplateSuffixes) are
// never credentials files. It says nothing
// about where the file is; see CredentialFileShape.Relative.
func MatchCredentialFileShape(value string) (CredentialFileShape, bool) {
	value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), `\`, "/"))
	if value == "" || strings.ContainsRune(value, '\x00') {
		return CredentialFileShape{}, false
	}
	value = path.Clean(value)
	base := path.Base(value)
	if base == "" || base == "." || base == "/" || strings.HasSuffix(base, ".pub") ||
		credentialFileTemplateName(base) {
		return CredentialFileShape{}, false
	}
	parent := ""
	if dir := path.Dir(value); dir != "." && dir != "/" {
		parent = path.Base(dir)
	}
	for _, row := range credentialFileShapes {
		var relative string
		switch {
		case row.folder != "":
			index := folderIndex(value, row.folder)
			if index < 0 || len(row.suffixes) != 0 && !hasAnySuffix(base, row.suffixes) {
				continue
			}
			relative = value[index:]
		case row.relative != "":
			if value != row.relative && !strings.HasSuffix(value, "/"+row.relative) {
				continue
			}
			relative = row.relative
		case row.base != "":
			if base != row.base {
				continue
			}
			relative = base
		case row.basePrefix != "":
			if !strings.HasPrefix(base, row.basePrefix) || len(base) == len(row.basePrefix) {
				continue
			}
			if row.dir != "" && parent != row.dir {
				continue
			}
			if len(row.suffixes) != 0 && !hasAnySuffix(base, row.suffixes) {
				continue
			}
			relative = base
			if row.dir != "" {
				relative = row.dir + "/" + base
			}
		case len(row.suffixes) != 0:
			suffix, ok := matchedSuffix(base, row.suffixes)
			if !ok || len(base) == len(suffix) {
				continue
			}
			stem := strings.TrimSuffix(base, suffix)
			if (len(row.stemAny) != 0 && !containsAny(stem, row.stemAny)) ||
				containsAny(stem, row.stemNone) {
				continue
			}
			relative = base
		default:
			continue
		}
		return CredentialFileShape{
			Class:        row.class,
			Relative:     relative,
			StrongUpload: row.strongUpload,
		}, true
	}
	return CredentialFileShape{}, false
}

// folderIndex is where folder starts in value as whole path components, with
// at least one more component after it, or -1.
func folderIndex(value, folder string) int {
	if strings.HasPrefix(value, folder+"/") {
		return 0
	}
	if index := strings.Index(value, "/"+folder+"/"); index >= 0 {
		return index + 1
	}
	return -1
}

func hasAnySuffix(value string, suffixes []string) bool {
	_, ok := matchedSuffix(value, suffixes)
	return ok
}

func matchedSuffix(value string, suffixes []string) (string, bool) {
	for _, suffix := range suffixes {
		if strings.HasSuffix(value, suffix) {
			return suffix, true
		}
	}
	return "", false
}

func containsAny(value string, words []string) bool {
	for _, word := range words {
		if strings.Contains(value, word) {
			return true
		}
	}
	return false
}

// credentialFileTemplateName reports a file name whose last dot-suffix
// marks a template or a sample (credentialFileTemplateSuffixes). A leading
// dot is part of the name, not a suffix (.env is not a template of "env").
func credentialFileTemplateName(base string) bool {
	name := strings.TrimPrefix(base, ".")
	index := strings.LastIndexByte(name, '.')
	if index < 0 {
		return false
	}
	_, template := credentialFileTemplateSuffixes[name[index+1:]]
	return template
}
