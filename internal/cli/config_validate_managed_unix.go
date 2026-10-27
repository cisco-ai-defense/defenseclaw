// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// configValidateManagedHost reports a standalone managed Linux or macOS host.
var configValidateManagedHost = managed.IsStandaloneManagedHost

// configValidatePlainRefusal words a refusal on a standalone managed host the
// way `enterprise linux|macos ensure` does: the file, the line, the setting
// and the fix in one sentence, without the validator's rule id or a JSONPath
// (r103.GAP-0087). Elsewhere it returns false and the diagnostic is printed
// as before.
func configValidatePlainRefusal(err error, failure configV8WireFailure, shown, path string) (string, bool) {
	if err == nil || !configValidateManagedHost() {
		return "", false
	}
	if env, envErr := newUnixLifecycleEnv(runtime.GOOS); envErr == nil && env != nil {
		raw, _ := readConfigV8Source(configV8AbsolutePath(path))
		if plain, ok := env.PlainConfigRefusal(err, shown, raw); ok {
			return plain, true
		}
	}
	field := strings.TrimPrefix(strings.TrimPrefix(failure.Path, "$"), ".")
	if field == "" {
		field = "the document"
	}
	reason := failure.Reason
	if strings.HasPrefix(reason, "[") {
		if _, rest, ok := strings.Cut(reason, "] "); ok {
			reason = rest
		}
	}
	return fmt.Sprintf("%s: %s: %s", shown, field, reason), true
}

// configValidateCredentialsDir is where a candidate's protected credential
// references resolve on a standalone managed host: the installed
// deployment's secrets directory, which ensure checks them against. A
// candidate kept anywhere else found no secrets folder next to it, so a
// stored credential was reported as not stored (GAP-0122). Elsewhere, and
// for a source that is not a standalone deployment's, the source's own path
// decides, as before.
func configValidateCredentialsDir(path string) string {
	if !configValidateManagedHost() {
		return ""
	}
	raw, err := readConfigV8Source(configV8AbsolutePath(path))
	if err != nil || !config.StandaloneManagedSource(raw) {
		return ""
	}
	layout, err := configValidateStandaloneLayout(runtime.GOOS)
	if err != nil {
		return ""
	}
	return layout.SecretsDir
}

var configValidateStandaloneLayout = managed.StandaloneLayoutFor

// configV8AbsolutePath is path as the loader reads it: the default config
// when it is empty.
func configV8AbsolutePath(path string) string {
	if path = strings.TrimSpace(path); path == "" {
		path = config.ConfigPath()
	}
	if absolute, err := filepath.Abs(path); err == nil {
		return absolute
	}
	return path
}
