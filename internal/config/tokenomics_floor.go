// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import "gopkg.in/yaml.v3"

// TokenomicsMinProductVersion is the first release that reads
// observability.tokenomics and observability.pricing. DefenseClaw 1.0.9 and
// earlier validate config.yaml against a closed schema and refuse the whole
// file when either key is present, whatever its value.
const TokenomicsMinProductVersion = "1.0.10"

// TokenomicsMinVersionKeysInRaw lists the 1.0.10 tokenomics blocks a
// config.yaml writes, read from the YAML itself so an explicit zero value
// (tokenomics: {enabled: false}, pricing: {}) counts: an older device refuses
// the key whatever its value. A signed bundle that sets one needs
// min_product_version 1.0.10 or later (enterprisebundle.CheckKeyProductFloor).
func TokenomicsMinVersionKeysInRaw(raw []byte) []string {
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil || doc == nil {
		return nil
	}
	observability, ok := doc["observability"].(map[string]any)
	if !ok {
		return nil
	}
	var keys []string
	for _, k := range []string{"tokenomics", "pricing"} {
		if _, set := observability[k]; set {
			keys = append(keys, "observability."+k)
		}
	}
	return keys
}
