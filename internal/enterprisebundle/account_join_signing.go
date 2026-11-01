// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/accountjoin"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ConfirmedAccountJoinSignedAt returns the created_at of the confirmed
// bundle when its config.yaml sets enterprise.account_join.next_generation
// to nextGeneration and next_not_after to the instant nextNotAfter. The
// account join key bounds the overlap of two generations by the time the
// administrator signed it, not by the device clock (rel-1-0-6:GAP-0277).
// ok is false when no bundle is confirmed, the confirmed version cannot be
// read and checked against its manifest, or its config sets other values
// (a config installed another way): the caller then uses its own clock.
func (s *Store) ConfirmedAccountJoinSignedAt(nextGeneration int, nextNotAfter time.Time) (time.Time, bool) {
	st, err := s.LoadState()
	if err != nil || st.Current == nil {
		return time.Time{}, false
	}
	b, err := s.ReadVersion(st.Current)
	if err != nil {
		return time.Time{}, false
	}
	m, err := DecodeManifest(b.Manifest)
	if err != nil {
		return time.Time{}, false
	}
	created, err := m.CreatedTime()
	if err != nil {
		return time.Time{}, false
	}
	generation, notAfter, ok := accountJoinNext(b.Files[ConfigName])
	if !ok || generation != nextGeneration || !notAfter.Equal(nextNotAfter) {
		return time.Time{}, false
	}
	return created, true
}

// AccountJoinCredentials are the tenant secrets a bundle config.yaml that
// turns enterprise.account_join on uses: account-join-key, and
// account-join-key-next while next_generation is set. The config names
// them only by the SHA-256 of their value, so they are not among
// ConfigCredentials; secret_refs binds each one to its value as an optional
// reference (rel-1-0-6:GAP-0276): a device that does not store it yet
// still applies the bundle and reports secret_missing, one that stores
// another value refuses the bundle (secret_ref_mismatch), and secret set
// refuses a value the confirmed bundle does not sign.
func AccountJoinCredentials(raw []byte) ([]string, error) {
	doc, err := parseConfigNode(raw)
	if err != nil {
		return nil, err
	}
	block := mappingChild(mappingChild(doc.Content[0], "enterprise"), "account_join")
	mode := mappingChild(block, "mode")
	if mode == nil || mode.Kind != yaml.ScalarNode || strings.TrimSpace(mode.Value) != config.AccountJoinOn {
		return nil, nil
	}
	names := []string{accountjoin.SecretName}
	if next := mappingChild(block, "next_generation"); next != nil && next.Kind == yaml.ScalarNode {
		if n, err := strconv.Atoi(strings.TrimSpace(next.Value)); err == nil && n != 0 {
			names = append(names, accountjoin.NextSecretName)
		}
	}
	return names, nil
}

// checkAccountJoinSecretValues refuses signing a bundle whose account join
// secrets are not the values its config names by digest, or not tenant
// secrets at all. No value or digest is echoed.
func checkAccountJoinSecretValues(join config.EnterpriseAccountJoinConfig, values map[string][]byte) error {
	for _, slot := range []struct{ name, digest, key string }{
		{accountjoin.SecretName, join.SecretSHA256, "secret_sha256"},
		{accountjoin.NextSecretName, join.NextSecretSHA256, "next_secret_sha256"},
	} {
		value, ok := values[slot.name]
		if !ok {
			continue
		}
		if _, err := accountjoin.ParseSecret(value); err != nil {
			return refuse(CodeConfigInvalid, "secret_refs", "the --secret-file value of %s is not a tenant secret (32 bytes, base64url)", slot.name)
		}
		if !accountjoin.ValueMatches(value, slot.digest) {
			return refuse(CodeConfigInvalid, ConfigName, "enterprise.account_join.%s is not the SHA-256 of the --secret-file value of %s", slot.key, slot.name)
		}
	}
	return nil
}

// accountJoinNext reads enterprise.account_join.next_generation and
// next_not_after from a bundle config.yaml.
func accountJoinNext(raw []byte) (int, time.Time, bool) {
	doc, err := parseConfigNode(raw)
	if err != nil {
		return 0, time.Time{}, false
	}
	block := mappingChild(mappingChild(doc.Content[0], "enterprise"), "account_join")
	generation, notAfter := mappingChild(block, "next_generation"), mappingChild(block, "next_not_after")
	if generation == nil || notAfter == nil || generation.Kind != yaml.ScalarNode || notAfter.Kind != yaml.ScalarNode {
		return 0, time.Time{}, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(generation.Value))
	if err != nil {
		return 0, time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339, strings.TrimSpace(notAfter.Value))
	if err != nil {
		return 0, time.Time{}, false
	}
	return n, at, true
}

// mappingChild is the value of key in the mapping node (aliases resolved),
// nil when node is not a mapping or has no such key.
func mappingChild(node *yaml.Node, key string) *yaml.Node {
	if node == nil {
		return nil
	}
	node = resolveAlias(node)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if k := resolveAlias(node.Content[i]); k != nil && k.Value == key {
			return resolveAlias(node.Content[i+1])
		}
	}
	return nil
}
