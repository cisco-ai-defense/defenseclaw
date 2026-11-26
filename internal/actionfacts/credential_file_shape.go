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
	// CredentialFileCredentialStore is a store of secrets the PATH-CRED-STORE
	// rules name that no other class holds: a Vault token, a MySQL client
	// option file, the Azure CLI credential files, a keytab, the system
	// shadow and service credential files (rel-1-0-10:GAP-0550).
	CredentialFileCredentialStore CredentialFileClass = "credential_store"
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
	// HomeFile marks the shapes that belong in a home only: a name inside a
	// tool folder (.aws/credentials, .kube/config, .config/gh/hosts.yml), and
	// the dotfiles that hold nothing but credentials (.git-credentials,
	// .netrc, .pgpass). Such a file in a project is the exception, so it is
	// read as an account's own credentials in any home, whatever the home
	// root is called (/mnt/home/alice, /srv/homes/carol). .npmrc, .pypirc
	// and .env are shipped in projects and are not HomeFile.
	HomeFile bool
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
	// under: a folder (path components, matched at a component boundary);
	// every file below it is the entry (var/lib/jenkins/secrets).
	under string
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
	// homeOnly: see CredentialFileShape.HomeFile (a row with a relative
	// path of several components is one already).
	homeOnly bool
	// notFolder: the parent folder of relative is not a credentials folder
	// by its name (credentialDirectoryNames). Claude Code's .claude holds
	// settings, skills, agents and worktrees, and a project has a .claude of
	// its own: a sender handed a folder under one is not handed credential
	// material for that (rel-1-0-10:GAP-1179, owner A/B datares-hd1).
	notFolder bool
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
	// A copy kept beside it (config.bak, config.old).
	{class: CredentialFileKubeconfig, dir: ".kube", basePrefix: "config."},

	{class: CredentialFilePackageRegistry, relative: ".docker/config.json"},
	{class: CredentialFilePackageRegistry, base: ".npmrc", strongUpload: true},
	{class: CredentialFilePackageRegistry, base: ".pypirc", strongUpload: true},

	{class: CredentialFileDeveloperToken, base: ".git-credentials", strongUpload: true, homeOnly: true},
	{class: CredentialFileDeveloperToken, base: ".netrc", strongUpload: true, homeOnly: true},
	{class: CredentialFileDeveloperToken, base: "_netrc", homeOnly: true},
	{class: CredentialFileDeveloperToken, base: ".pgpass", homeOnly: true},
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

	// The credential stores of the PATH-CRED-STORE and PATH-CRED-STORE-USER
	// rules that the rows above do not hold (gh hosts.yml, .pgpass and the
	// Azure token caches are rows above). A read of any of them starts the
	// secret-read chain like every other row (rel-1-0-10:GAP-0550).
	{class: CredentialFileCredentialStore, base: ".vault-token"},
	{class: CredentialFileCredentialStore, base: ".my.cnf"},
	{class: CredentialFileCredentialStore, relative: ".azure/accesstokens.json"},
	{class: CredentialFileCredentialStore, relative: ".azure/credentials"},
	{class: CredentialFileCredentialStore, relative: "etc/master.passwd"},
	{class: CredentialFileCredentialStore, relative: "etc/gshadow"},
	{class: CredentialFileCredentialStore, relative: "etc/security/opasswd"},
	{class: CredentialFileCredentialStore, relative: "etc/krb5.keytab"},
	{class: CredentialFileCredentialStore, relative: "etc/aws/credentials"},
	{class: CredentialFileCredentialStore, relative: "etc/azure/credentials"},
	{class: CredentialFileCredentialStore, relative: "etc/gcloud/credentials"},
	{class: CredentialFileCredentialStore, relative: "var/lib/jenkins/credentials.xml"},
	{class: CredentialFileCredentialStore, under: "var/lib/jenkins/secrets"},
	{class: CredentialFileCredentialStore, suffixes: []string{".keytab"}},

	// Login and token files of developer CLIs and agents (S7 secret-read
	// table). Each row names the path the tool's public documentation gives.
	//
	// Claude Code: ~/.claude/.credentials.json (Linux, Windows, the macOS
	// keychain fallback), or .credentials.json under CLAUDE_CONFIG_DIR:
	// https://code.claude.com/docs/en/authentication#credential-management
	// The home row comes first: its Relative is the whole home-relative path,
	// so the home-only owner (secrets.cloud_credential_read) reads it as the
	// account's own login (rel-1-0-10:GAP-1179). The base row keeps the
	// CLAUDE_CONFIG_DIR folders, whose name is not known, for the chain.
	{class: CredentialFileCloudCLI, relative: ".claude/.credentials.json", notFolder: true},
	{class: CredentialFileCloudCLI, base: ".credentials.json"},
	// OpenAI Codex CLI: "~/.codex/auth.json" caches the login:
	// https://developers.openai.com/codex/auth (moved to
	// https://learn.chatgpt.com/docs/auth)
	{class: CredentialFileCloudCLI, relative: ".codex/auth.json"},
	// Google's gemini command-line agent: the cached OAuth login is
	// oauth_creds.json in the ~/.gemini folder (OAUTH_FILE in
	// packages/core/src/config/storage.ts of Google's open-source agent
	// repository; its public authentication page only says the login is
	// cached locally). The vendor names are not spelled here: the retired
	// connector tripwire (cli/tests/test_retired_connector_names.py) scans
	// every tracked file.
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
	// Maven's master password for encrypted server passwords:
	// https://maven.apache.org/guides/mini/guide-encryption.html
	{class: CredentialFileDeveloperToken, relative: ".m2/settings-security.xml"},
	// RubyGems: gem push and gem signin keep the API key in ~/.gem/credentials:
	// https://guides.rubygems.org/command-reference/#gem-push
	{class: CredentialFileDeveloperToken, relative: ".gem/credentials"},
	// podman login: ${XDG_RUNTIME_DIR}/containers/auth.json on Linux,
	// $HOME/.config/containers/auth.json on macOS and Windows:
	// https://docs.podman.io/en/latest/markdown/podman-login.1.html
	// The home row comes first, as for Claude Code (rel-1-0-10:GAP-1179); the
	// runtime folder row (/run/user/<uid>/containers/auth.json) follows.
	{class: CredentialFilePackageRegistry, relative: ".config/containers/auth.json"},
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
			if value != row.relative && !hasPathSuffix(value, row.relative) {
				continue
			}
			relative = row.relative
		case row.under != "":
			under, ok := belowFolder(value, row.under)
			if !ok {
				continue
			}
			relative = under
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
			HomeFile:     row.homeOnly || strings.Contains(relative, "/"),
		}, true
	}
	return CredentialFileShape{}, false
}

// folderIndex is where folder starts in value as whole path components, with
// at least one more component after it, or -1.
// It builds no string: MatchCredentialFileShape runs it for each table row
// on every path of every placed reading, and the concatenations it made
// were most of the allocations of a long copy-mode call (substrate-1
// GAP-0956).
func folderIndex(value, folder string) int {
	for from := 0; from <= len(value); {
		index := strings.Index(value[from:], folder)
		if index < 0 {
			return -1
		}
		index += from
		end := index + len(folder)
		if (index == 0 || value[index-1] == '/') && end < len(value) && value[end] == '/' {
			return index
		}
		from = index + 1
	}
	return -1
}

// hasPathSuffix reports value ending in /suffix (strings.HasSuffix(value,
// "/"+suffix) without building it, folderIndex).
func hasPathSuffix(value, suffix string) bool {
	return len(value) > len(suffix) && value[len(value)-len(suffix)-1] == '/' && strings.HasSuffix(value, suffix)
}

// CredentialFileShapeProbePaths returns, for every row of the credentials-file
// table, one concrete path the row names, spelled relative to a root (a home,
// a project, "/"): a test that walks it covers every row, so a path added to
// the table is covered by the tests that read this list with no edit.
func CredentialFileShapeProbePaths() []string {
	probes := make([]string, 0, len(credentialFileShapes))
	for _, row := range credentialFileShapes {
		var probe string
		switch {
		case row.relative != "":
			probe = row.relative
		case row.under != "":
			probe = row.under + "/probe"
		case row.folder != "":
			probe = row.folder + "/probe"
			if len(row.suffixes) != 0 {
				probe += row.suffixes[0]
			}
		case row.base != "":
			probe = row.base
		case row.basePrefix != "":
			probe = row.basePrefix + "probe"
			if len(row.suffixes) != 0 {
				probe += row.suffixes[0]
			}
			if row.dir != "" {
				probe = row.dir + "/" + probe
			}
		case len(row.suffixes) != 0:
			stem := "probe"
			if len(row.stemAny) != 0 {
				stem += "-" + row.stemAny[0]
			}
			probe = stem + row.suffixes[0]
		default:
			continue
		}
		probes = append(probes, probe)
	}
	return probes
}

// belowFolder reports a path below folder (components, matched at a component
// boundary) and returns the folder-relative spelling of the file.
func belowFolder(value, folder string) (string, bool) {
	index := folderIndex(value, folder)
	if index < 0 {
		return "", false
	}
	rest := value[index+len(folder)+1:]
	if rest == "" {
		return "", false
	}
	return folder + "/" + rest, true
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
