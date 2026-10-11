// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Destination secrets read from environment variables on a managed host.
//
// A managed lifecycle writes each service's environment itself, so the
// gateway never sees a variable set in the shell that ran ensure or Setup: a
// destination secret read with token_env, bearer_env or an {env: NAME} header
// cannot resolve there. With the variable set the config passed every check,
// was applied, and the gateway failed to start into a rollback; unset, the
// refusal gave per-user advice (GAP-0939 on Linux and macOS, GAP-0966 on
// Windows, where Setup stopped the services first).

// EnterpriseSettingsReferenceURL is the enterprise settings reference; the
// managed packages ship no per-user CLI to print the schema with.
const EnterpriseSettingsReferenceURL = "https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/configuration/#settings-reference"

// ManagedEnvSecretReferences lists the environment-backed destination
// secrets of an administrator config.
type ManagedEnvSecretReferences struct {
	// Fields names each reference, for example
	// "observability.destinations[1] (eoi-hec) token_env".
	Fields []string
	// Line is the line of the first reference.
	Line int
	// Conflict is a destination that sets both a credential field and its
	// environment twin; it is reported instead of Fields.
	Conflict *ManagedEnvSecretConflict
}

// ManagedEnvSecretConflict is a destination that sets a credential field and
// its environment twin.
type ManagedEnvSecretConflict struct {
	Destination     string
	CredentialField string
	EnvField        string
	Line            int
}

// ScanManagedEnvSecretReferences finds the environment-backed destination
// secrets in raw, whether or not the variables are set. A document that does
// not parse has none; the schema check reports it.
func ScanManagedEnvSecretReferences(raw []byte) ManagedEnvSecretReferences {
	var found ManagedEnvSecretReferences
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil || len(doc.Content) == 0 {
		return found
	}
	destinations := yamlMappingChild(yamlMappingChild(doc.Content[0], "observability"), "destinations")
	if destinations == nil || destinations.Kind != yaml.SequenceNode {
		return found
	}
	note := func(field string, node *yaml.Node) {
		found.Fields = append(found.Fields, field)
		if found.Line == 0 {
			found.Line = node.Line
		}
	}
	for index, destination := range destinations.Content {
		if destination.Kind != yaml.MappingNode {
			continue
		}
		label := fmt.Sprintf("observability.destinations[%d]", index)
		if name := yamlMappingChild(destination, "name"); name != nil && name.Kind == yaml.ScalarNode && name.Value != "" {
			label += fmt.Sprintf(" (%s)", name.Value)
		}
		for _, pair := range [][2]string{{"token_env", "token_credential"}, {"bearer_env", "bearer_credential"}} {
			node := yamlMappingChild(destination, pair[0])
			if node == nil || node.Kind != yaml.ScalarNode || strings.TrimSpace(node.Value) == "" {
				continue
			}
			if credential := yamlMappingChild(destination, pair[1]); credential != nil && strings.TrimSpace(credential.Value) != "" {
				// Both fields: the documented sentence, naming the
				// destination and both fields (GAP-0940).
				return ManagedEnvSecretReferences{Conflict: &ManagedEnvSecretConflict{
					Destination: label, CredentialField: pair[1], EnvField: pair[0], Line: node.Line,
				}}
			}
			note(label+" "+pair[0], node)
		}
		if headers := yamlMappingChild(destination, "headers"); headers != nil && headers.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(headers.Content); i += 2 {
				if value := headers.Content[i+1]; value.Kind == yaml.MappingNode && yamlMappingChild(value, "env") != nil {
					note(label+" header "+headers.Content[i].Value, value)
				}
			}
		}
	}
	return found
}

// Refusal is the sentence that refuses the references: where names the file,
// store is how this platform stores a protected credential (a command in
// backticks) and reference the settings reference URL. ok is false when the
// config has none.
func (r ManagedEnvSecretReferences) Refusal(where, store, reference string) (string, bool) {
	if c := r.Conflict; c != nil {
		return fmt.Sprintf("%s%s: %s sets both %s and %s; set either %s or %s, not both (on a managed host, %s). The settings reference: %s",
			where, managedEnvSecretLine(c.Line), c.Destination, c.CredentialField, c.EnvField, c.CredentialField, c.EnvField,
			c.CredentialField, reference), true
	}
	if len(r.Fields) == 0 {
		return "", false
	}
	return fmt.Sprintf("%s%s: %s reads a secret from an environment variable, and a managed host never passes one to its services, "+
		"so DefenseClaw refuses token_env, bearer_env and {env: NAME} headers. Store the secret %s "+
		"and reference it by name: token_credential (splunk_hec), bearer_credential (http_jsonl) or {credential: <name>} (a header). The settings reference: %s",
		where, managedEnvSecretLine(r.Line), strings.Join(r.Fields, ", "), store, reference), true
}

func managedEnvSecretLine(line int) string {
	if line <= 0 {
		return ""
	}
	return fmt.Sprintf(" line %d", line)
}

// yamlMappingChild is the value of key in a mapping node, or nil.
func yamlMappingChild(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
