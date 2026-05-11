// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"regexp"
	"strings"
)

var secretArgFlags = map[string]bool{
	"--value":        true,
	"--token":        true,
	"--api-key":      true,
	"--hec-token":    true,
	"--access-token": true,
	"--secret":       true,
	"--password":     true,
}

var envNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// MaskSecret returns a stable short preview that never exposes the
// whole value. The last four characters are enough for operators to
// distinguish two pasted tokens without turning the TUI into a secret
// disclosure surface.
func MaskSecret(value string) string {
	if strings.TrimSpace(value) == "" {
		return "(empty)"
	}
	if len(value) <= 4 {
		return "****"
	}
	return "****" + value[len(value)-4:]
}

func isSecretName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	for _, marker := range []string{"password", "secret", "token", "api_key", "apikey", "access_key", "private_key"} {
		if strings.Contains(n, marker) {
			return true
		}
	}
	return false
}

func IsSecretConfigField(f configField) bool {
	if f.Kind == "password" {
		return true
	}
	return isSecretName(f.Key) || isSecretName(f.Label)
}

func IsConfigEnvNameField(f configField) bool {
	return strings.HasSuffix(f.Key, "_env") ||
		strings.Contains(f.Key, ".api_key_env") ||
		strings.Contains(f.Key, ".token_env") ||
		strings.Contains(f.Label, " Env")
}

func MaskConfigValue(f configField, value string) string {
	if IsSecretConfigField(f) || (IsConfigEnvNameField(f) && LooksLikeSecretValue(value)) {
		return MaskSecret(value)
	}
	if strings.TrimSpace(value) == "" {
		return "(empty)"
	}
	return value
}

func SecretArgIndexes(args []string) map[int]bool {
	out := map[int]bool{}
	for i, arg := range args {
		if i > 0 && secretArgFlags[args[i-1]] {
			out[i] = true
			continue
		}
		if flag, _, ok := strings.Cut(arg, "="); ok && secretArgFlags[flag] {
			out[i] = true
			continue
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func MaskArgv(args []string) []string {
	masked := make([]string, len(args))
	copy(masked, args)
	secretIdx := SecretArgIndexes(args)
	for i := range secretIdx {
		if flag, val, ok := strings.Cut(masked[i], "="); ok {
			masked[i] = flag + "=" + MaskSecret(val)
		} else {
			masked[i] = MaskSecret(masked[i])
		}
	}
	return masked
}

func LooksLikeEnvName(value string) bool {
	return envNamePattern.MatchString(strings.TrimSpace(value))
}

// LooksLikeSecretValue catches common cases where an operator pasted a
// literal credential into an env-name field. It intentionally biases
// toward warning instead of blocking; the validator decides severity.
func LooksLikeSecretValue(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return false
	}
	lower := strings.ToLower(v)
	if strings.HasPrefix(v, "sk-") ||
		strings.HasPrefix(v, "ghp_") ||
		strings.HasPrefix(v, "gho_") ||
		strings.HasPrefix(v, "ghs_") ||
		strings.HasPrefix(v, "AIza") ||
		strings.HasPrefix(v, "AKIA") ||
		strings.HasPrefix(v, "ASIA") ||
		strings.HasPrefix(v, "eyJ") ||
		strings.Contains(lower, "bearer ") ||
		strings.Contains(v, "-----BEGIN ") {
		return true
	}
	if strings.Contains(v, ".") && strings.Count(v, ".") == 2 && len(v) > 40 {
		return true
	}
	return len(v) >= 32 && !LooksLikeEnvName(v)
}
