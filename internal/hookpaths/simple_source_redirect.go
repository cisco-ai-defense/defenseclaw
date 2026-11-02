// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// SourceRedirectFactPrefix carries the resolved target of a single sourced
// assignment followed by one redirect. The command digest binds the fact to
// the shell text the gateway reads. A missing fact leaves the write unknown.
const SourceRedirectFactPrefix = "\x00source-redirect:"

var (
	simpleSourceRedirect = regexp.MustCompile(`\Af=[A-Za-z0-9._-]+;[ \t]*\.[ \t]+(\./[A-Za-z0-9._-]+);[ \t]*echo[ \t]+[A-Za-z0-9._-]+[ \t]*>>[ \t]*"\$f"\z`)
	simpleSourceValue    = regexp.MustCompile(`\Af=([A-Za-z0-9._-]+)\n?\z`)
)

// SimpleSourceRedirectFactKey is empty unless the command has exactly one
// sourced assignment and one write of its value. The source file's content
// is checked separately; the shape alone never proves an ordinary target.
func SimpleSourceRedirectFactKey(command string) string {
	if runtime.GOOS == "windows" || len(command) > 4096 || !simpleSourceRedirect.MatchString(command) {
		return ""
	}
	sum := sha256.Sum256([]byte(command))
	return SourceRedirectFactPrefix + hex.EncodeToString(sum[:])
}

// SimpleSourceRedirectTarget reads a regular source file under cwd only when
// its entire content is one literal assignment. It resolves the redirect as
// the hook user, including links and hard links to protected SSH files.
func SimpleSourceRedirectTarget(command, cwd, home string) (string, bool) {
	if SimpleSourceRedirectFactKey(command) == "" || !filepath.IsAbs(cwd) || !filepath.IsAbs(home) {
		return "", false
	}
	source := simpleSourceRedirect.FindStringSubmatch(command)[1]
	content, ok := readIndirectSource(source, cwd)
	if !ok {
		return "", false
	}
	assignment := simpleSourceValue.FindStringSubmatch(content)
	if len(assignment) != 2 {
		return "", false
	}
	resolved, ok := ResolveWriteTarget(OperandPath(assignment[1], cwd))
	if !ok {
		return "", false
	}
	return newProtectedFiles(home).target(resolved)
}

func validSourceRedirectFact(key, value string) bool {
	digest := strings.TrimPrefix(key, SourceRedirectFactPrefix)
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == digest &&
		filepath.IsAbs(value) && filepath.Clean(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n") && len(value) <= MaxWriteTargetPathBytes
}
