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
)

type ObservabilityV8SecretResolver interface {
	ResolveObservabilitySecret(name string) (string, bool)
}

type ObservabilityV8SecretResolverFunc func(string) (string, bool)

func (resolve ObservabilityV8SecretResolverFunc) ResolveObservabilitySecret(name string) (string, bool) {
	return resolve(name)
}

type observabilityV8RuntimeSecretResolver struct{}

func (observabilityV8RuntimeSecretResolver) ResolveObservabilitySecret(name string) (string, bool) {
	if value, ok := GetKey(name); ok && strings.TrimSpace(value) != "" {
		return value, true
	}
	value, ok := os.LookupEnv(name)
	return value, ok && strings.TrimSpace(value) != ""
}

type V8SecretReferenceError struct {
	Destination string
	Path        string
	Reference   string
}

func (e *V8SecretReferenceError) Error() string {
	if e == nil {
		return ""
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
			if _, ok := resolver.ResolveObservabilitySecret(value.Secret.Env); !ok {
				return &V8SecretReferenceError{
					Destination: destination.Name,
					Path:        fmt.Sprintf("observability.destinations[%d].headers[%q]", index, header),
					Reference:   value.Secret.Env,
				}
			}
		}
		for _, reference := range []struct {
			path, name string
		}{
			{"token_env", destination.TokenEnv},
			{"bearer_env", destination.BearerEnv},
		} {
			if reference.name == "" {
				continue
			}
			if _, ok := resolver.ResolveObservabilitySecret(reference.name); !ok {
				return &V8SecretReferenceError{
					Destination: destination.Name,
					Path:        fmt.Sprintf("observability.destinations[%d].%s", index, reference.path),
					Reference:   reference.name,
				}
			}
		}
	}
	return nil
}
