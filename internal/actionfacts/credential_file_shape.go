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
	// .env.<stage> and other variants; credentialFileTemplateSuffixes
	// below are not environment files.
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

// credentialFileTemplateSuffixes are the last dot-suffixes of a .env.<x>
// name that mark a template a repository ships, not an environment file:
// .env.example, .env.sample, .env.template, .env.dist and the like.
var credentialFileTemplateSuffixes = map[string]struct{}{
	"example": {}, "examples": {}, "sample": {}, "samples": {},
	"template": {}, "templates": {}, "tpl": {}, "tmpl": {}, "dist": {},
	"defaults": {}, "default": {}, "schema": {}, "skel": {}, "j2": {},
	"jinja": {}, "jinja2": {}, "md": {}, "txt": {},
}

// MatchCredentialFileShape returns the credentials-file table entry for a
// path (any spelling: absolute, relative, home-prefixed or a drive path; it
// is compared lower-case with forward slashes). A public key (*.pub) and a
// repository's .env template are never credentials files. It says nothing
// about where the file is; see CredentialFileShape.Relative.
func MatchCredentialFileShape(value string) (CredentialFileShape, bool) {
	value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), `\`, "/"))
	if value == "" || strings.ContainsRune(value, '\x00') {
		return CredentialFileShape{}, false
	}
	value = path.Clean(value)
	base := path.Base(value)
	if base == "" || base == "." || base == "/" || strings.HasSuffix(base, ".pub") {
		return CredentialFileShape{}, false
	}
	parent := ""
	if dir := path.Dir(value); dir != "." && dir != "/" {
		parent = path.Base(dir)
	}
	for _, row := range credentialFileShapes {
		var relative string
		switch {
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
		if row.class == CredentialFileEnvironment && credentialEnvironmentTemplate(base) {
			return CredentialFileShape{}, false
		}
		return CredentialFileShape{
			Class:        row.class,
			Relative:     relative,
			StrongUpload: row.strongUpload,
		}, true
	}
	return CredentialFileShape{}, false
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

func credentialEnvironmentTemplate(base string) bool {
	suffix, ok := strings.CutPrefix(base, ".env.")
	if !ok {
		return false
	}
	if index := strings.LastIndexByte(suffix, '.'); index >= 0 {
		suffix = suffix[index+1:]
	}
	_, template := credentialFileTemplateSuffixes[suffix]
	return template
}
