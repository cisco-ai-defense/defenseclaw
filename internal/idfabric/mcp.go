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

package idfabric

import (
	"net/url"
	"path"
	"path/filepath"
	"strings"
)

// remoteURLSchemes are the only schemes projected into MCPServer.URL. Anything
// else (including stdio and file) is omitted rather than guessed at.
var remoteURLSchemes = map[string]bool{
	"http":  true,
	"https": true,
	"ws":    true,
	"wss":   true,
}

// SanitizeRemoteURL reduces a configured MCP endpoint to scheme://host[:port].
//
// User-info, path, query, and fragment are dropped rather than escaped,
// because each of them routinely carries tokens or workspace-identifying
// detail. The second return value is false when the value cannot be reduced
// safely, in which case the caller must omit the URL entirely.
func SanitizeRemoteURL(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if !remoteURLSchemes[scheme] {
		return "", false
	}
	// Hostname() strips any user-info and brackets; an empty host means the
	// value was relative or malformed and cannot be attributed to an endpoint.
	host := parsed.Hostname()
	if host == "" {
		return "", false
	}
	authority := host
	if strings.Contains(host, ":") {
		// IPv6 literal: restore brackets so the result stays parseable.
		authority = "[" + host + "]"
	}
	if port := parsed.Port(); port != "" {
		authority += ":" + port
	}
	return scheme + "://" + authority, true
}

// AuthHintFromURL reports what the dropped parts of an endpoint URL imply
// about authentication.
//
// SanitizeRemoteURL discards user-info and query strings because they carry
// credentials, but discarding them silently would let a server whose token
// lives in the URL be reported as unauthenticated. This recovers the
// classification without retaining the secret: embedded user-info is HTTP
// basic auth, and any query string is treated as an unidentified credential
// carrier. An empty result means the URL implied nothing.
func AuthHintFromURL(raw string) AuthMethod {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}
	if parsed.User != nil && parsed.User.String() != "" {
		return AuthMethodBasic
	}
	if strings.TrimSpace(parsed.RawQuery) != "" {
		return AuthMethodUnknown
	}
	return ""
}

// ClassifyAuthMethod derives the declared auth method of a remote server from
// configuration shape alone.
//
// headerNames must contain only header names; values are never inspected or
// retained beyond reading an Authorization scheme token. declaredType is the
// connector's own transport/auth type field when present. The result describes
// configuration, not a successful authentication.
//
// AuthMethodNone requires the configuration to say so. Absence of auth fields
// is not evidence of an unauthenticated server: agents hold OAuth grants
// outside the MCP config entirely - Cursor keeps its grant in its own storage,
// so a plain {"url": ...} entry is routinely a fully authenticated server.
// Treating that silence as "none" invented unauthenticated remote endpoints
// that an operator would then go hunting for.
func ClassifyAuthMethod(declaredType string, headerNames []string, authSchemeToken string, hasClientCert bool) AuthMethod {
	if hasClientCert {
		return AuthMethodMTLS
	}
	switch strings.ToLower(strings.TrimSpace(declaredType)) {
	case "oauth", "oauth2":
		return AuthMethodOAuth
	case "none", "unauthenticated":
		return AuthMethodNone
	}
	switch strings.ToLower(strings.TrimSpace(authSchemeToken)) {
	case "bearer":
		return AuthMethodBearerToken
	case "basic":
		return AuthMethodBasic
	}
	for _, name := range headerNames {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "authorization", "proxy-authorization":
			// Present but with no recognizable scheme token.
			return AuthMethodUnknown
		case "x-api-key", "api-key", "apikey", "x-goog-api-key":
			return AuthMethodAPIKeyHeader
		}
	}
	return AuthMethodUnknown
}

// InferRunner maps a configured launcher command to a recognized runner form.
// Only the command's basename is examined; the surrounding path is never
// retained.
func InferRunner(command string) Runner {
	base := commandBasename(command)
	if base == "" {
		return RunnerUnknown
	}
	switch base {
	case "npx", "npm", "pnpx", "bunx":
		return RunnerNPX
	case "uvx", "uv":
		return RunnerUVX
	case "node", "nodejs", "bun", "deno":
		return RunnerNode
	case "python", "python3", "py":
		return RunnerPython
	case "docker", "podman":
		return RunnerDocker
	default:
		return RunnerBinary
	}
}

// commandBasename returns the lowercased, extension-stripped basename of a
// command, tolerating both path separators regardless of host OS.
func commandBasename(command string) string {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return ""
	}
	trimmed = strings.ReplaceAll(trimmed, "\\", "/")
	base := path.Base(trimmed)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	return strings.ToLower(base)
}

// InferPackage extracts the package (or module, or image) name and an
// explicitly pinned version from a local server's launcher arguments.
//
// It deliberately declines to report anything that would be a filesystem path.
// A script invoked as `node ./server.js` yields no package, because the only
// identifying token is a path. Both return values are empty when nothing can
// be extracted unambiguously.
func InferPackage(runner Runner, command string, args []string) (pkg string, version string) {
	switch runner {
	case RunnerNPX, RunnerUVX:
		spec := firstPackageSpec(runner, args)
		if spec == "" {
			return "", ""
		}
		return splitPackageSpec(spec)
	case RunnerDocker:
		image := dockerImage(args)
		if image == "" {
			return "", ""
		}
		return splitImageRef(image)
	case RunnerPython:
		// Only the module form is path-free.
		for i, arg := range args {
			if arg == "-m" && i+1 < len(args) {
				return strings.TrimSpace(args[i+1]), ""
			}
		}
		return "", ""
	case RunnerBinary:
		// The command basename is an accepted identifier; the path is not.
		return commandBasename(command), ""
	default:
		return "", ""
	}
}

// firstPackageSpec returns the first argument that names a package rather than
// a flag. It honours the explicit --package/--from forms used by npx and uvx.
func firstPackageSpec(runner Runner, args []string) string {
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			continue
		}
		switch arg {
		case "-p", "--package", "--from":
			if i+1 < len(args) {
				return strings.TrimSpace(args[i+1])
			}
			return ""
		case "-y", "--yes", "--no-install", "-q", "--quiet", "--silent":
			continue
		}
		if strings.HasPrefix(arg, "-") {
			// Unrecognized flag; skip its value when it uses = or a separate token.
			continue
		}
		if runner == RunnerUVX && arg == "run" {
			continue
		}
		if isPathLike(arg) {
			return ""
		}
		return arg
	}
	return ""
}

// dockerImage returns the image reference from a docker/podman invocation.
func dockerImage(args []string) string {
	seenRun := false
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			continue
		}
		if !seenRun {
			if arg == "run" || arg == "create" {
				seenRun = true
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			// Flags that consume a following value must not swallow the image.
			switch arg {
			case "-e", "--env", "-v", "--volume", "--name", "--network",
				"--mount", "-p", "--publish", "-w", "--workdir", "-u", "--user":
				i++
			}
			continue
		}
		return arg
	}
	return ""
}

// splitPackageSpec separates a package spec into name and pinned version,
// preserving npm scopes such as @scope/name@1.2.3.
func splitPackageSpec(spec string) (string, string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", ""
	}
	// uv's PEP 508 pin form.
	if idx := strings.Index(spec, "=="); idx > 0 {
		return spec[:idx], spec[idx+2:]
	}
	scoped := strings.HasPrefix(spec, "@")
	body := spec
	prefix := ""
	if scoped {
		prefix = "@"
		body = spec[1:]
	}
	idx := strings.LastIndex(body, "@")
	if idx <= 0 {
		return spec, ""
	}
	name := prefix + body[:idx]
	version := body[idx+1:]
	if version == "" || version == "latest" {
		return name, ""
	}
	return name, version
}

// splitImageRef separates an image reference into repository and pinned tag or
// digest. A floating "latest" tag is not a pin.
func splitImageRef(ref string) (string, string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", ""
	}
	if idx := strings.Index(ref, "@"); idx > 0 {
		return ref[:idx], ref[idx+1:]
	}
	idx := strings.LastIndex(ref, ":")
	if idx <= 0 {
		return ref, ""
	}
	// A colon inside the final path segment is a tag; earlier ones are ports.
	if strings.Contains(ref[idx+1:], "/") {
		return ref, ""
	}
	tag := ref[idx+1:]
	if tag == "" || tag == "latest" {
		return ref[:idx], ""
	}
	return ref[:idx], tag
}

// isPathLike reports whether a token looks like a filesystem path, which must
// never be projected into telemetry.
func isPathLike(token string) bool {
	if strings.HasPrefix(token, ".") || strings.HasPrefix(token, "/") ||
		strings.HasPrefix(token, "~") || strings.HasPrefix(token, "\\") {
		return true
	}
	// Drive-letter form such as C:\ or C:/.
	if len(token) >= 3 && token[1] == ':' &&
		(token[2] == '\\' || token[2] == '/') {
		return true
	}
	return false
}
