// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"fmt"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// The actor environment is an allowlist (substrate-1 GAP-0354, GAP-0355).
// A variable of the image environment or of an ActorTemplate container's env
// is permitted only when it is
//   - one of the kit's own variables (kit.ImageEnv), with the kit's exact
//     value where the kit fixes one; or
//   - one of the ordinary settings base images carry (baseEnv, baseEnvPrefix,
//     baseEnvSuffix), with any value.
//
// Everything else is refused. A list of the variables that load code is
// never complete: the review of the earlier deny list ran code on the box
// through four variables it did not name (SHELLOPTS with PS4, PERLLIB,
// XDG_CONFIG_HOME, GIT_DIR). Names are compared exactly, as Linux does.

// PATH may name any folder: every hook and settings file names
// DefenseClaw's programs by absolute path, and every process the relay
// starts with this PATH runs as the agent's user, so a PATH entry the agent
// can write gives it nothing it does not have. A separated relay's own git
// review and push run as root with a PATH of their own: only the folders of
// this one that root alone can write, and programs it checks are root's
// (relay gitRelayEnv, GAP-0795). HOME
// is the image's; an ActorTemplate may not move it (GAP-0374,
// controller.ContainerSpecRefusal). VIRTUAL_ENV and UV_PYTHON_INSTALL_DIR
// (the uv environment of the OpenShell harness base, GAP-0447) name
// folders of the image, as the toolchain homes do.
//
// baseEnv are the base-image settings that load no code: locale and
// terminal, the user's identity, version pins and the toolchain homes base
// images set (a toolchain home names a folder of the scanned image, as PATH
// does). Commands a program runs (EDITOR, PAGER, SHELL, GIT_EDITOR) are not
// on it.
var baseEnv = map[string]bool{
	"PATH": true, "HOME": true, "LANG": true, "LANGUAGE": true, "TZ": true, "TERM": true, "COLORTERM": true,
	"USER": true, "LOGNAME": true, "HOSTNAME": true, "container": true, "DEBIAN_FRONTEND": true,
	"NODE_ENV": true, "NO_COLOR": true, "FORCE_COLOR": true, "CI": true,
	"PYTHONUNBUFFERED": true, "PYTHONDONTWRITEBYTECODE": true, "PYTHONIOENCODING": true, "PYTHON_SHA256": true, "GPG_KEY": true,
	"GIT_AUTHOR_NAME": true, "GIT_AUTHOR_EMAIL": true, "GIT_COMMITTER_NAME": true, "GIT_COMMITTER_EMAIL": true,
	"VIRTUAL_ENV": true, "UV_PYTHON_INSTALL_DIR": true, "JAVA_HOME": true, "GOPATH": true, "GOROOT": true, "GOTOOLCHAIN": true, "CARGO_HOME": true, "RUSTUP_HOME": true,
}

// baseEnvPrefix and baseEnvSuffix are families of base settings: the locale
// categories (LC_ALL, LC_CTYPE ...) and version pins (NODE_VERSION,
// YARN_VERSION, PYTHON_VERSION ...).
var (
	baseEnvPrefix = []string{"LC_"}
	baseEnvSuffix = []string{"_VERSION"}
)

// EnvRefusal is one variable the allowlist refuses.
type EnvRefusal struct {
	Name string
	// Want is the kit's fixed value when the variable is the kit's but set
	// to another value; "" when the variable is not permitted at all.
	Want string
}

func (r EnvRefusal) String() string {
	if r.Want != "" {
		return fmt.Sprintf("%s (the kit sets it to %q only)", r.Name, r.Want)
	}
	return r.Name + " (not on the allowlist)"
}

// envPermitted reports whether name=value is permitted, and the kit's value
// when the kit fixes another one.
func envPermitted(name, value string) (bool, string) {
	if r, ok := kit.ImageEnv()[name]; ok {
		if r.Fixed && value != r.Value {
			return false, r.Value
		}
		return true, ""
	}
	if baseEnv[name] {
		return true, ""
	}
	for _, p := range baseEnvPrefix {
		if strings.HasPrefix(name, p) && plainEnvName(name) {
			return true, ""
		}
	}
	for _, s := range baseEnvSuffix {
		if strings.HasSuffix(name, s) && len(name) > len(s) && plainEnvName(name) {
			return true, ""
		}
	}
	return false, ""
}

// plainEnvName is an upper-case name of letters, digits and underscores.
func plainEnvName(n string) bool {
	for _, c := range n {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return n != ""
}

// CheckEnv lists, sorted by name, the variables of env the actor
// environment allowlist refuses.
func CheckEnv(env map[string]string) []EnvRefusal {
	var out []EnvRefusal
	for k, v := range env {
		if ok, want := envPermitted(k, v); !ok {
			out = append(out, EnvRefusal{Name: k, Want: want})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// EnvRefusalNames are the refused variables' names.
func EnvRefusalNames(rs []EnvRefusal) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Name
	}
	return out
}

// FormatEnvRefusals is the operator-facing list of refusals.
func FormatEnvRefusals(rs []EnvRefusal) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = r.String()
	}
	return strings.Join(parts, ", ")
}
