// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/secretshape"
)

// envPlaceholderPattern is a ${NAME} environment placeholder. Nothing in the
// config loader expands it, so only the name form counts as a reference: a
// literal wrapped in ${...} is still a literal.
var envPlaceholderPattern = lazyregexp.New(`^\$\{[A-Za-z_][A-Za-z0-9_]{0,127}\}$`)

// configKey is key as the config loader reads it. The loader matches keys
// case-insensitively and reads a dotted key as a path (llm.api_key at the top
// level sets llm.api_key), so a check on the YAML spelling alone misses
// API_KEY or llm.api_key.
func configKey(key string) string {
	key = strings.ToLower(key)
	return key[strings.LastIndex(key, ".")+1:]
}

// secretHeaderName reports whether an observability header carries a
// credential by its name. A static (literal) value for such a header is a
// secret in the bundle; it must be a {credential: NAME} reference.
func secretHeaderName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "authorization", "proxy-authorization", "cookie":
		return true
	}
	for _, part := range []string{"key", "token", "secret", "password", "auth"} {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}

// secretReference reports whether text names a secret instead of holding
// one: secret://<credential name> or a ${NAME} placeholder.
func secretReference(text string) bool {
	if name, ok := strings.CutPrefix(text, SecretRefScheme); ok {
		return config.ValidEnterpriseCredentialName(name)
	}
	return envPlaceholderPattern.MatchString(text)
}

// configSecretKeys are config keys whose scalar value would be secret
// material (the keys the effective digest drops). A bundle config may only
// name credentials, never carry them.
var configSecretKeys = map[string]bool{
	"token": true, "api_key": true, "virustotal_api_key": true, "bearer_token": true,
	"password": true, "secret": true, "client_secret": true, "private_key": true,
}

// configCredentialKeys are config keys whose scalar value names an
// enterprise credential (enterprise.*.credential, observability
// {credential: NAME} headers, bearer_credential, token_credential).
var configCredentialKeys = map[string]bool{
	"credential": true, "bearer_credential": true, "token_credential": true,
}

// CheckInlineSecrets refuses (inline_secret) a bundle file that holds a
// secret value: a private key or a credential secretshape recognises in any
// file, or a value under a secret key (token, api_key, password, ...) of
// config.yaml. Bundles carry secret references only; the MDM delivers the
// values into the enterprise secret store.
func CheckInlineSecrets(b *Bundle) error {
	for _, name := range b.Paths() {
		if found, ok := secretshape.FindInlineSecret(string(b.Files[name])); ok {
			line := 1 + bytes.Count(b.Files[name][:found.Offset], []byte("\n"))
			return refuse(CodeInlineSecret, name, "line %d holds a %s; reference an enterprise credential with secret:// instead", line, found.Label)
		}
	}
	raw, ok := b.Files[ConfigName]
	if !ok {
		return nil
	}
	root, err := parseConfigNode(raw)
	if err != nil {
		return err
	}
	var bad *Error
	walkMappings(root, "", func(path, key string, value *yaml.Node) bool {
		value = resolveAlias(value)
		if configKey(key) == "headers" && value.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(value.Content); i += 2 {
				header := resolveAlias(value.Content[i+1])
				if header.Kind == yaml.ScalarNode && header.Tag == "!!str" && strings.TrimSpace(header.Value) != "" &&
					secretHeaderName(value.Content[i].Value) {
					bad = refuse(CodeInlineSecret, ConfigName, "%s.%s holds a literal value (line %d); use {credential: NAME} instead",
						safePath(path), safePath(value.Content[i].Value), header.Line)
					return false
				}
			}
		}
		if !configSecretKeys[configKey(key)] || value.Kind != yaml.ScalarNode || value.Tag == "!!null" {
			return true
		}
		text := strings.TrimSpace(value.Value)
		if text == "" || secretReference(text) {
			return true
		}
		bad = refuse(CodeInlineSecret, ConfigName, "%s holds a value (line %d); name an enterprise credential instead", safePath(path), value.Line)
		return false
	})
	if bad != nil {
		return bad
	}
	return nil
}

// ConfigCredentials returns the enterprise credential names config.yaml
// references, sorted and unique. Every one must be listed in secret_refs.
func ConfigCredentials(raw []byte) ([]string, error) {
	root, err := parseConfigNode(raw)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	walkMappings(root, "", func(_, key string, value *yaml.Node) bool {
		value = resolveAlias(value)
		if configCredentialKeys[configKey(key)] && value.Kind == yaml.ScalarNode {
			if name := strings.TrimSpace(value.Value); name != "" && value.Tag != "!!null" {
				seen[name] = true
			}
		}
		return true
	})
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// credentialBindingDomain keeps value_sha256 apart from every other digest
// of a credential (enterprise secret status prints a prefix of the plain
// SHA-256 of the stored file).
const credentialBindingDomain = "defenseclaw-bundle-credential-v1"

// CredentialValueSHA256 is the value_sha256 that binds value as credential
// name of a bundle for tenant: the lower-case hex SHA-256 of the domain, the
// tenant, the name and the value as the gateway reads it (surrounding
// whitespace trimmed), each followed by a NUL. The tenant and the name make
// the digest specific to one reference, so a table of digests of common
// values does not match it.
func CredentialValueSHA256(tenant, name string, value []byte) string {
	h := sha256.New()
	for _, part := range [][]byte{[]byte(credentialBindingDomain), []byte(tenant), []byte(name), bytes.TrimSpace(value)} {
		h.Write(part)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CheckCredentialChange refuses storing value as credential name unless the
// signed bundle that uses the credential binds that value. rotation is the
// verified bundle the caller names for a new value (enterprise secret set
// --bundle), nil for none; confirmed is the manifest of the confirmed
// bundle, nil when none is confirmed. With rotation, it must reference name
// and bind value. Without, a confirmed bundle that references name must bind
// value: an entry without a digest is secret_ref_unbound, another digest
// secret_ref_mismatch. A credential no bundle references is not checked; no
// signed record names it.
func CheckCredentialChange(confirmed, rotation *Manifest, name string, value []byte) error {
	m, source := confirmed, "the confirmed policy bundle"
	if rotation != nil {
		m, source = rotation, "the --bundle policy bundle"
	}
	if m == nil {
		return nil
	}
	for _, ref := range m.SecretRefs {
		if ref.Name() != name {
			continue
		}
		switch {
		case ref.ValueSHA256 == "":
			return refuse(CodeSecretRefUnbound, "secret_refs", "%s signs the name of credential %s but not its value; sign a bundle with --secret-file %s=<file> and pass it with --bundle", source, safePath(name), safePath(name))
		case !ref.Binds(m.TenantID, value):
			return refuse(CodeSecretRefMismatch, "secret_refs", "%s signs another value for credential %s; to rotate it, sign a bundle with --secret-file %s=<file> for the new value and pass it with --bundle", source, safePath(name), safePath(name))
		}
		return nil
	}
	if rotation != nil {
		return refuse(CodeSecretRefMismatch, "secret_refs", "%s does not reference credential %s", source, safePath(name))
	}
	return nil
}

// SecretRefState is what bundle verify reports for one secret_refs entry on
// a device: its credential name, whether the bundle requires it, whether the
// device stores a value for it and whether that value is the one the bundle
// signs. Every listed entry binds a value (CheckSecretRefs refuses one that
// does not), so there is no separate bound flag. It never carries a value
// or any digest.
type SecretRefState struct {
	Name       string `json:"name"`
	Required   bool   `json:"required"`
	Present    bool   `json:"present"`
	ValueMatch bool   `json:"value_match"`
}

// CheckSecretRefs refuses a bundle whose config.yaml names a credential that
// secret_refs does not list (manifest_invalid) and a secret_refs entry that
// binds no value (secret_ref_unbound). The device-side checks that every
// required credential is stored (secret_ref_missing) with its signed value
// (secret_ref_mismatch) are the verifier's.
func CheckSecretRefs(m *Manifest, b *Bundle) error {
	raw, ok := b.Files[ConfigName]
	if !ok {
		return refuse(CodeFileMissing, ConfigName, "the bundle has no config.yaml")
	}
	needed, err := ConfigCredentials(raw)
	if err != nil {
		return err
	}
	listed := map[string]bool{}
	for _, ref := range m.SecretRefs {
		listed[ref.Name()] = true
	}
	for _, name := range needed {
		if !listed[name] {
			return refuse(CodeManifestInvalid, "secret_refs", "config.yaml references the credential %s, which secret_refs does not list", safePath(name))
		}
	}
	for _, ref := range m.SecretRefs {
		if ref.ValueSHA256 == "" {
			return refuse(CodeSecretRefUnbound, "secret_refs", "the bundle signs the name of credential %s but not its value; sign it again with --secret-file %s=<file>", safePath(ref.Name()), safePath(ref.Name()))
		}
	}
	return nil
}

// parseConfigNode parses config.yaml into its document node, bounded by the
// config loader's source limit. Aliases are not expanded.
func parseConfigNode(raw []byte) (*yaml.Node, error) {
	if len(raw) > maxConfigBytes {
		return nil, refuse(CodeConfigInvalid, ConfigName, "larger than %d bytes", maxConfigBytes)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, refuse(CodeConfigInvalid, ConfigName, "not valid YAML")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, refuse(CodeConfigInvalid, ConfigName, "not a YAML mapping")
	}
	return &doc, nil
}

// walkMappings calls visit for every key/value pair of every mapping below
// node, with the dotted path of the value, until visit returns false. Alias
// nodes are not followed, so every node is visited once, where it is
// defined.
func walkMappings(node *yaml.Node, path string, visit func(path, key string, value *yaml.Node) bool) bool {
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for i, child := range node.Content {
			childPath := path
			if node.Kind == yaml.SequenceNode {
				childPath = path + "[" + strconv.Itoa(i) + "]"
			}
			if !walkMappings(child, childPath, visit) {
				return false
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i].Value, node.Content[i+1]
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			if !visit(childPath, key, value) || !walkMappings(value, childPath, visit) {
				return false
			}
		}
	}
	return true
}

// resolveAlias returns the node an alias names (one level: YAML aliases
// name anchored nodes, never other aliases), else node.
func resolveAlias(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		return node.Alias
	}
	return node
}
