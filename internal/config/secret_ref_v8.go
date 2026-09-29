// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type ObservabilityV8SecretResolver interface {
	ResolveObservabilitySecret(name string) (string, bool)
}

// ObservabilityV8CredentialResolver is the optional part of a resolver that
// reads {credential: NAME}, token_credential and bearer_credential
// references. A resolver without it resolves none of them.
type ObservabilityV8CredentialResolver interface {
	ResolveObservabilityCredential(name string) (string, bool)
}

type ObservabilityV8SecretResolverFunc func(string) (string, bool)

func (resolve ObservabilityV8SecretResolverFunc) ResolveObservabilitySecret(name string) (string, bool) {
	return resolve(name)
}

// ResolveObservabilityV8Credential resolves a protected credential reference
// through resolver, when it can read credentials.
func ResolveObservabilityV8Credential(resolver ObservabilityV8SecretResolver, name string) (string, bool) {
	credentials, ok := resolver.(ObservabilityV8CredentialResolver)
	if !ok {
		return "", false
	}
	return credentials.ResolveObservabilityCredential(name)
}

// observabilityV8RuntimeSecretResolver resolves env references from the key
// store, then the environment. credentialsDir is the standalone deployment's
// secrets directory; it is empty for every other source, so a credential
// reference resolves only in the standalone enterprise profile.
type observabilityV8RuntimeSecretResolver struct {
	credentialsDir string
}

func (observabilityV8RuntimeSecretResolver) ResolveObservabilitySecret(name string) (string, bool) {
	if value, ok := GetKey(name); ok && strings.TrimSpace(value) != "" {
		return value, true
	}
	value, ok := os.LookupEnv(name)
	return value, ok && strings.TrimSpace(value) != ""
}

func (resolver observabilityV8RuntimeSecretResolver) ResolveObservabilityCredential(name string) (string, bool) {
	return ResolveObservabilityV8ProtectedCredential(resolver.credentialsDir, name)
}

// ResolveObservabilityV8ProtectedCredential reads a protected credential
// from a standalone deployment's secrets directory, or from systemd's
// LoadCredential= directory in the gateway service, with the same trust
// checks as the AI Defense key. The value is never logged.
func ResolveObservabilityV8ProtectedCredential(secretsDir, name string) (string, bool) {
	if strings.TrimSpace(secretsDir) == "" {
		return "", false
	}
	value, _, err := managed.ResolveServiceCredential(name, secretsDir)
	if err != nil {
		return "", false
	}
	return string(value), true
}

type V8SecretReferenceError struct {
	Destination string
	Path        string
	Reference   string
	// Credential marks a protected credential reference.
	Credential bool
}

func (e *V8SecretReferenceError) Error() string {
	if e == nil {
		return ""
	}
	if e.Credential {
		return fmt.Sprintf(
			"observability destination %q: protected credential %q at %s is not stored or not trusted; "+
				"credential references work only in a standalone enterprise deployment, "+
				"after `enterprise secret set --name %s` stores the credential",
			e.Destination,
			e.Reference,
			e.Path,
			e.Reference,
		)
	}
	return fmt.Sprintf(
		"observability destination %q: unresolved secret reference at %s (%s)",
		e.Destination,
		e.Path,
		e.Reference,
	)
}

func validateObservabilityV8Secrets(
	source *ObservabilityV8Source,
	resolver ObservabilityV8SecretResolver,
) error {
	if source == nil {
		return nil
	}
	if resolver == nil {
		resolver = observabilityV8RuntimeSecretResolver{}
	}
	for index := range source.Destinations {
		destination := &source.Destinations[index]
		if destination.Enabled != nil && !*destination.Enabled {
			continue
		}
		for header, value := range destination.Headers {
			if value.Secret == nil {
				continue
			}
			path := fmt.Sprintf("observability.destinations[%d].headers[%q]", index, header)
			if value.Secret.Credential != "" {
				if _, ok := ResolveObservabilityV8Credential(resolver, value.Secret.Credential); !ok {
					return &V8SecretReferenceError{
						Destination: destination.Name, Path: path,
						Reference: value.Secret.Credential, Credential: true,
					}
				}
				continue
			}
			if _, ok := resolver.ResolveObservabilitySecret(value.Secret.Env); !ok {
				return &V8SecretReferenceError{
					Destination: destination.Name,
					Path:        path,
					Reference:   value.Secret.Env,
				}
			}
		}
		for _, reference := range []struct {
			path, name string
			credential bool
		}{
			{"token_env", destination.TokenEnv, false},
			{"bearer_env", destination.BearerEnv, false},
			{"token_credential", destination.TokenCredential, true},
			{"bearer_credential", destination.BearerCredential, true},
		} {
			if reference.name == "" {
				continue
			}
			var ok bool
			if reference.credential {
				_, ok = ResolveObservabilityV8Credential(resolver, reference.name)
			} else {
				_, ok = resolver.ResolveObservabilitySecret(reference.name)
			}
			if !ok {
				return &V8SecretReferenceError{
					Destination: destination.Name,
					Path:        fmt.Sprintf("observability.destinations[%d].%s", index, reference.path),
					Reference:   reference.name,
					Credential:  reference.credential,
				}
			}
		}
	}
	return nil
}
