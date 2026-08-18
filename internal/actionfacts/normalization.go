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

package actionfacts

import (
	"net/netip"
	"path"
	"strconv"
	"strings"
)

type pathSyntax uint8

const (
	pathSyntaxUnknown pathSyntax = iota
	pathSyntaxPOSIX
	pathSyntaxWindows
)

type pathExpansionPolicy struct {
	literal     bool
	expandTilde bool
}

type pathNormalizationContext struct {
	syntax        pathSyntax
	trustedSyntax bool
	registry      bool
	expansion     pathExpansionPolicy
}

func normalizePathFacts(facts []PathFact, cwd string, activeHomes ...string) {
	activeHome := unambiguousActiveHome(activeHomes)
	normalizePathFactsForCommands(facts, cwd, activeHome, nil)
}

func normalizePathFactsForCommands(
	facts []PathFact,
	cwd string,
	activeHome string,
	commands []CommandFact,
) {
	commandByID := make(map[int64]*CommandFact, len(commands))
	for i := range commands {
		commandByID[commands[i].ID] = &commands[i]
	}
	for i := range facts {
		context := pathContextForCommand(
			facts[i],
			cwd,
			commandByID[facts[i].CommandID],
		)
		normalized, absolute, resolved := derivePathWithContext(
			facts[i],
			cwd,
			activeHome,
			context,
		)
		facts[i].Normalized = normalized
		facts[i].Absolute = absolute
		facts[i].Resolved = resolved
		facts[i].Flavor = normalizedPathFlavorWithContext(
			facts[i],
			cwd,
			normalized,
			resolved,
			context,
		)
	}
}

func pathContextForCommand(
	fact PathFact,
	cwd string,
	command *CommandFact,
) pathNormalizationContext {
	effectiveFlavor := fact.Flavor
	registry := false
	if fact.Flavor == PathFlavorRegistry {
		_, registry = canonicalRegistryPath(fact.Value)
		if !registry {
			effectiveFlavor = PathFlavorUnknown
		}
	}
	context := pathNormalizationContext{
		syntax:    syntaxForPath(fact.Value, effectiveFlavor, cwd),
		registry:  registry,
		expansion: pathExpansionPolicy{expandTilde: true},
	}
	if command == nil {
		return context
	}

	context.expansion.literal = commandProvesLiteralPath(*command, fact)
	switch command.Dialect {
	case DialectPOSIX:
		context.syntax = pathSyntaxPOSIX
		context.trustedSyntax = true
		context.registry = false
		context.expansion.expandTilde = posixCommandExpandsTilde(
			*command,
			fact,
		)
	case DialectCMD:
		context.syntax = pathSyntaxWindows
		context.trustedSyntax = true
		context.expansion.expandTilde = false
	case DialectPowerShell:
		// PowerShell is cross-platform. Its classifiers deliberately retain
		// an explicitly proven POSIX operand, while Windows-owned relative,
		// rooted, drive, and UNC operands carry a Windows/unknown flavor.
		if fact.Flavor == PathFlavorPOSIX {
			context.syntax = pathSyntaxPOSIX
			context.registry = false
		} else {
			context.syntax = pathSyntaxWindows
		}
		context.trustedSyntax = true
		context.expansion.expandTilde = true
	case DialectArgv:
		// Structured argv and exact tool schemas are already runtime values,
		// so shell metacharacters in their paths are literal data. A trusted
		// CWD supplies the otherwise absent filesystem dialect.
		context.expansion.literal = true
		if syntax := syntaxForNormalizationCWD(cwd); syntax != pathSyntaxUnknown {
			context.syntax = syntax
			context.trustedSyntax = true
			if syntax == pathSyntaxPOSIX {
				context.registry = false
			}
		}
	}
	return context
}

func commandProvesLiteralPath(command CommandFact, fact PathFact) bool {
	matched := false
	static := true
	for _, argument := range command.Arguments {
		if argument.Value != fact.Value {
			continue
		}
		matched = true
		static = static && !argument.Expands
	}
	for _, redirect := range command.Redirects {
		if redirect.Target != fact.Value || redirect.Access != fact.Access {
			continue
		}
		matched = true
		static = static && !redirect.Expands
	}
	return matched && static
}

func posixCommandExpandsTilde(
	command CommandFact,
	fact PathFact,
) bool {
	matched := false
	expands := true
	for _, argument := range command.Arguments {
		if argument.Value != fact.Value {
			continue
		}
		matched = true
		expands = expands &&
			!argument.Expands &&
			argument.Quote == QuoteNone
	}
	for _, redirect := range command.Redirects {
		if redirect.Target != fact.Value || redirect.Access != fact.Access {
			continue
		}
		// A static raw POSIX redirect beginning with '~' was quoted or
		// escaped: an actually unquoted tilde is marked as an expansion by
		// the parser and cannot produce an exact redirect target.
		matched = true
		expands = false
	}
	return matched && expands
}

func syntaxForNormalizationCWD(cwd string) pathSyntax {
	if looksWindowsUNCPath(cwd) {
		return pathSyntaxWindows
	}
	return syntaxForCWD(cwd)
}

func looksWindowsUNCPath(value string) bool {
	slashed := strings.ReplaceAll(value, `\`, "/")
	if !strings.HasPrefix(slashed, "//") {
		return false
	}
	return len(nonEmptyPathParts(strings.TrimLeft(slashed, "/"))) >= 2
}

func unambiguousActiveHome(activeHomes []string) string {
	if len(activeHomes) != 1 {
		return ""
	}
	activeHome, ok := normalizeActiveHome(activeHomes[0])
	if !ok {
		return ""
	}
	return activeHome
}

func reconcileNormalizedDeviceWrites(
	commands []CommandFact,
	paths []PathFact,
) {
	commandIndexes := make(map[int64]int, len(commands))
	for i := range commands {
		commandIndexes[commands[i].ID] = i
	}
	for _, fact := range paths {
		if fact.Flavor != PathFlavorDevice ||
			(fact.Access != PathAccessWrite &&
				fact.Access != PathAccessAppend) {
			continue
		}
		target := fact.Resolved
		if target == "" {
			target = fact.Normalized
		}
		if target == "" {
			target = fact.Value
		}
		if !isRawBlockDeviceTarget(target) {
			continue
		}
		index, ok := commandIndexes[fact.CommandID]
		if !ok {
			continue
		}
		addOperation(&commands[index], OperationDiskWrite)
	}
}

func normalizedPathFlavorWithContext(
	fact PathFact,
	cwd string,
	normalized string,
	resolved string,
	context pathNormalizationContext,
) PathFlavor {
	if context.registry {
		return PathFlavorRegistry
	}
	fallbackFlavor := fact.Flavor
	if fallbackFlavor == PathFlavorRegistry {
		// The classifier's broad registry lookalike heuristic is only a
		// candidate. Normalization must never retain registry identity after
		// exact canonical validation rejects it or trusted POSIX context
		// establishes filesystem semantics.
		fallbackFlavor = PathFlavorUnknown
	}
	effective := normalized
	if resolved != "" {
		effective = resolved
	}
	if effective == "" {
		return fallbackFlavor
	}

	switch context.syntax {
	case pathSyntaxPOSIX:
		if hasUnresolvedPathSyntaxWithPolicy(
			effective,
			context.expansion,
		) {
			return fallbackFlavor
		}
		lower := strings.ToLower(effective)
		if strings.TrimSpace(effective) == effective &&
			strings.HasPrefix(lower, "/dev/") {
			return PathFlavorDevice
		}
		if context.trustedSyntax ||
			strings.HasPrefix(effective, "/") ||
			fact.Flavor == PathFlavorPOSIX ||
			fact.Flavor == PathFlavorDevice {
			return PathFlavorPOSIX
		}
	case pathSyntaxWindows:
		if context.trustedSyntax ||
			resolved != "" ||
			fact.Flavor == PathFlavorWindows ||
			fact.Flavor == PathFlavorDevice {
			return windowsPathFlavor(effective)
		}
	}
	return fallbackFlavor
}

func derivePath(fact PathFact, cwd string) (string, bool, string) {
	return derivePathWithHome(fact, cwd, "")
}

func derivePathWithHome(
	fact PathFact,
	cwd string,
	activeHome string,
) (string, bool, string) {
	return derivePathWithContext(
		fact,
		cwd,
		activeHome,
		pathContextForCommand(fact, cwd, nil),
	)
}

func derivePathWithContext(
	fact PathFact,
	cwd string,
	activeHome string,
	context pathNormalizationContext,
) (string, bool, string) {
	if fact.Value == "" {
		return "", false, ""
	}
	if context.registry {
		canonical, ok := canonicalRegistryPath(fact.Value)
		if !ok {
			return "", false, ""
		}
		return canonical, true, canonical
	}
	switch context.syntax {
	case pathSyntaxPOSIX:
		return derivePOSIXPathWithPolicy(
			fact.Value,
			cwd,
			activeHome,
			context.expansion,
		)
	case pathSyntaxWindows:
		return deriveWindowsPathWithPolicy(
			fact.Value,
			cwd,
			activeHome,
			context.expansion,
		)
	default:
		return "", false, ""
	}
}

func syntaxForPath(value string, flavor PathFlavor, cwd string) pathSyntax {
	switch flavor {
	case PathFlavorPOSIX:
		return pathSyntaxPOSIX
	case PathFlavorWindows:
		return pathSyntaxWindows
	case PathFlavorDevice:
		if strings.HasPrefix(value, "/") {
			return pathSyntaxPOSIX
		}
		if looksWindowsPath(value) {
			return pathSyntaxWindows
		}
		return pathSyntaxUnknown
	case PathFlavorRegistry:
		return pathSyntaxUnknown
	}

	if strings.HasPrefix(value, "/") {
		return pathSyntaxPOSIX
	}
	if looksWindowsPath(value) {
		return pathSyntaxWindows
	}
	if cwdSyntax := syntaxForCWD(cwd); cwdSyntax != pathSyntaxUnknown {
		return cwdSyntax
	}
	if strings.Contains(value, "/") {
		return pathSyntaxPOSIX
	}
	// A separator-free relative path has identical lexical normalization in
	// both supported filesystems. POSIX is the neutral fallback; without an
	// absolute CWD no resolution is attempted.
	return pathSyntaxPOSIX
}

func syntaxForCWD(cwd string) pathSyntax {
	switch {
	case strings.HasPrefix(cwd, "/"):
		return pathSyntaxPOSIX
	case looksWindowsPath(cwd):
		return pathSyntaxWindows
	default:
		return pathSyntaxUnknown
	}
}

func looksWindowsPath(value string) bool {
	return strings.Contains(value, `\`) ||
		len(value) >= 2 && isASCIILetter(value[0]) && value[1] == ':'
}

func isASCIILetter(value byte) bool {
	return (value >= 'a' && value <= 'z') ||
		(value >= 'A' && value <= 'Z')
}

func derivePOSIXPathWithPolicy(
	value string,
	cwd string,
	activeHome string,
	expansion pathExpansionPolicy,
) (string, bool, string) {
	if expansion.expandTilde &&
		(value == "~" || strings.HasPrefix(value, "~/")) {
		if strings.HasPrefix(activeHome, "/") {
			remainder := strings.TrimPrefix(value, "~")
			resolved := path.Clean(activeHome + "/" + strings.TrimPrefix(remainder, "/"))
			if len(resolved) <= maxScalarBytes {
				return value, false, resolved
			}
		}
	}
	unresolved := hasUnresolvedPathSyntaxWithPolicy(value, expansion)
	absolute := strings.HasPrefix(value, "/")
	normalized := value
	if !unresolved {
		normalized = path.Clean(value)
	}
	if len(normalized) > maxScalarBytes {
		return "", absolute, ""
	}
	if unresolved {
		return normalized, absolute, ""
	}
	if absolute {
		return normalized, true, normalized
	}
	if syntaxForCWD(cwd) != pathSyntaxPOSIX ||
		hasUnresolvedPathSyntax(cwd) ||
		!strings.HasPrefix(cwd, "/") {
		return normalized, false, ""
	}
	resolved := path.Clean(path.Join(cwd, normalized))
	if len(resolved) > maxScalarBytes {
		resolved = ""
	}
	return normalized, false, resolved
}

type windowsPath struct {
	normalized string
	volume     string
	tail       string
	absolute   bool
	rooted     bool
	unresolved bool
}

const (
	powerShellFileSystemProviderPrefix  = `microsoft.powershell.core\filesystem::`
	powerShellEnvironmentProviderPrefix = `microsoft.powershell.core\environment::`
)

// canonicalWindowsFilesystemPath removes only provider/device prefixes whose
// target can be represented without changing Win32 path semantics. Extended
// paths with dot segments, special trailing characters, or reserved device
// names remain non-authoritative because stripping \\?\ would retarget them.
func canonicalWindowsFilesystemPath(value string) (string, bool) {
	if value == "" {
		return "", false
	}

	lower := strings.ToLower(value)
	providerQualified := false
	switch {
	case strings.HasPrefix(lower, powerShellFileSystemProviderPrefix):
		value = value[len(powerShellFileSystemProviderPrefix):]
		if value == "" || strings.Contains(strings.ToLower(value), "::") {
			return "", false
		}
		providerQualified = true
	case strings.HasPrefix(lower, `microsoft.powershell.core\filesystem`),
		strings.HasPrefix(lower, `microsoft.powershell.core/`),
		strings.HasPrefix(lower, `microsoft.powershell.core\`),
		strings.HasPrefix(lower, `filesystem::`),
		strings.Contains(lower, "::"):
		return "", false
	}
	if windowsNonFilesystemProviderPath(value) {
		return "", false
	}

	canonical, extended, ok := canonicalExtendedWindowsPath(value)
	if !ok {
		return "", false
	}
	if extended {
		return canonical, true
	}
	if !safeOrdinaryWindowsPath(canonical) {
		return "", false
	}
	if providerQualified {
		lower = strings.ToLower(canonical)
		if strings.HasPrefix(lower, "registry::") ||
			strings.HasPrefix(lower, "hkcu:") ||
			strings.HasPrefix(lower, "hklm:") ||
			strings.HasPrefix(lower, "hkcr:") ||
			strings.HasPrefix(lower, "hku:") ||
			strings.HasPrefix(lower, "hkcc:") {
			return "", false
		}
	}
	return canonical, true
}

func safeOrdinaryWindowsPath(value string) bool {
	slashed := strings.ReplaceAll(value, `\`, "/")
	uncNamespaceComponents := 0
	if len(slashed) >= 2 && isASCIILetter(slashed[0]) &&
		slashed[1] == ':' {
		slashed = slashed[2:]
	} else if strings.HasPrefix(slashed, "//") &&
		!strings.HasPrefix(slashed, "//./") {
		// A UNC server and share identify the namespace root; they are not
		// ordinary file/directory basenames subject to DOS device aliases.
		slashed = strings.TrimPrefix(slashed, "//")
		uncNamespaceComponents = 2
	}
	for _, part := range strings.Split(slashed, "/") {
		// Empty components preserve roots, repeated separators, and trailing
		// separators. Exact dot segments are intentionally normalized later.
		if part == "" || part == "." || part == ".." {
			continue
		}
		filesystemName := windowsPreADSComponent(part)
		namespaceComponent := uncNamespaceComponents > 0
		if namespaceComponent {
			uncNamespaceComponents--
		}
		if filesystemName == "" ||
			strings.HasSuffix(filesystemName, " ") ||
			strings.HasSuffix(filesystemName, ".") ||
			strings.HasSuffix(part, " ") ||
			strings.HasSuffix(part, ".") ||
			!namespaceComponent &&
				windowsReservedDeviceComponent(filesystemName) {
			return false
		}
	}
	return true
}

func windowsEnvironmentProviderPath(value string) bool {
	lower := strings.ToLower(value)
	return strings.HasPrefix(lower, "env:") ||
		strings.HasPrefix(lower, "environment::") ||
		strings.HasPrefix(lower, powerShellEnvironmentProviderPrefix)
}

func windowsNonFilesystemProviderPath(value string) bool {
	if windowsEnvironmentProviderPath(value) {
		return true
	}
	lower := strings.ToLower(value)
	slashed := strings.ReplaceAll(lower, `\`, "/")
	if strings.HasPrefix(slashed, "//?/") ||
		strings.HasPrefix(slashed, "//./") {
		return false
	}
	if strings.HasPrefix(lower, "variable:") ||
		strings.HasPrefix(lower, "cert:") ||
		strings.HasPrefix(lower, "function:") ||
		strings.HasPrefix(lower, "alias:") ||
		strings.HasPrefix(lower, "wsman:") {
		return true
	}
	colon := strings.IndexByte(value, ':')
	return colon > 1 && colon+1 < len(value) &&
		(value[colon+1] == '\\' || value[colon+1] == '/')
}

func canonicalExtendedWindowsPath(value string) (string, bool, bool) {
	slashed := strings.ReplaceAll(value, `\`, "/")
	if !strings.HasPrefix(slashed, "//?/") {
		return value, false, true
	}

	remainder := slashed[len("//?/"):]
	if len(remainder) >= len("UNC/") &&
		strings.EqualFold(remainder[:len("UNC/")], "UNC/") {
		parts := strings.Split(remainder[len("UNC/"):], "/")
		if len(parts) < 2 || !safeExtendedWindowsParts(parts, 2) {
			return "", true, false
		}
		return `\\` + strings.Join(parts, `\`), true, true
	}
	if len(remainder) < 3 || !isASCIILetter(remainder[0]) ||
		remainder[1] != ':' || remainder[2] != '/' {
		return "", true, false
	}
	parts := strings.Split(remainder[3:], "/")
	if len(parts) == 1 && parts[0] == "" {
		parts = nil
	}
	if !safeExtendedWindowsParts(parts, 0) {
		return "", true, false
	}
	canonical := strings.ToUpper(remainder[:1]) + `:\`
	if len(parts) > 0 {
		canonical += strings.Join(parts, `\`)
	}
	return canonical, true, true
}

func safeExtendedWindowsParts(
	parts []string,
	reservedComponentStart int,
) bool {
	for index, part := range parts {
		if part == "" || part == "." || part == ".." ||
			strings.HasSuffix(part, " ") ||
			strings.HasSuffix(part, ".") ||
			strings.ContainsAny(part, `*?`) ||
			index >= reservedComponentStart &&
				windowsReservedDeviceComponent(
					windowsPreADSComponent(part),
				) {
			return false
		}
	}
	return true
}

func windowsPreADSComponent(component string) string {
	if index := strings.IndexByte(component, ':'); index >= 0 {
		return component[:index]
	}
	return component
}

func windowsReservedDeviceComponent(component string) bool {
	name := component
	if index := strings.IndexByte(name, '.'); index >= 0 {
		name = name[:index]
	}
	name = strings.ToLower(name)
	switch name {
	case "con", "prn", "aux", "nul",
		"com¹", "com²", "com³",
		"lpt¹", "lpt²", "lpt³":
		return true
	}
	if len(name) == 4 &&
		(name[:3] == "com" || name[:3] == "lpt") &&
		name[3] >= '1' && name[3] <= '9' {
		return true
	}
	return false
}

func deriveWindowsPathWithPolicy(
	value string,
	cwd string,
	activeHome string,
	expansion pathExpansionPolicy,
) (string, bool, string) {
	if expansion.expandTilde &&
		(value == "~" || strings.HasPrefix(value, `~\`) ||
			strings.HasPrefix(value, "~/")) {
		home := parseWindowsPath(activeHome)
		if home.absolute && !home.unresolved {
			remainder := strings.TrimLeft(value[1:], `/\`)
			resolved := parseWindowsPathWithPolicy(
				joinWindowsPath(home.normalized, remainder),
				expansion,
			)
			if resolved.absolute && !resolved.unresolved &&
				len(resolved.normalized) <= maxScalarBytes {
				return strings.ReplaceAll(value, `\`, "/"), false, resolved.normalized
			}
		}
	}
	parsed := parseWindowsPathWithPolicy(value, expansion)
	if parsed.normalized == "" || len(parsed.normalized) > maxScalarBytes {
		return "", parsed.absolute, ""
	}
	if parsed.unresolved {
		return parsed.normalized, parsed.absolute, ""
	}
	if parsed.absolute {
		return parsed.normalized, true, parsed.normalized
	}
	if (syntaxForCWD(cwd) != pathSyntaxWindows &&
		!strings.HasPrefix(cwd, "//")) ||
		hasUnresolvedPathSyntax(cwd) {
		return parsed.normalized, false, ""
	}
	base := parseWindowsPath(cwd)
	if !base.absolute || base.unresolved {
		return parsed.normalized, false, ""
	}

	var resolved string
	switch {
	case parsed.rooted:
		if isDriveVolume(base.volume) {
			resolved = base.volume + "/" + parsed.tail
		}
	case parsed.volume != "":
		if strings.EqualFold(parsed.volume, base.volume) {
			resolved = joinWindowsPath(base.normalized, parsed.tail)
		}
	default:
		resolved = joinWindowsPath(base.normalized, parsed.normalized)
	}
	if resolved == "" {
		return parsed.normalized, false, ""
	}
	resolvedPath := parseWindowsPathWithPolicy(resolved, expansion)
	if !resolvedPath.absolute || len(resolvedPath.normalized) > maxScalarBytes {
		return parsed.normalized, false, ""
	}
	return parsed.normalized, false, resolvedPath.normalized
}

func validateActiveHome(value string) IssueCode {
	if value == "" {
		return ""
	}
	if issue := validateScalar(value, maxScalarBytes); issue != "" {
		return issue
	}
	_, ok := normalizeActiveHome(value)
	if !ok {
		return IssueInvalidSyntax
	}
	return ""
}

func normalizeActiveHome(value string) (string, bool) {
	if value == "" {
		return "", true
	}
	if strings.TrimSpace(value) != value || hasUnresolvedPathSyntax(value) {
		return "", false
	}
	if strings.HasPrefix(value, "/") {
		cleaned := path.Clean(value)
		if cleaned == "/" || len(cleaned) > maxScalarBytes {
			return "", false
		}
		return cleaned, true
	}
	parsed := parseWindowsPath(value)
	if !parsed.absolute || parsed.unresolved || parsed.normalized == "" ||
		parsed.normalized == parsed.volume+"/" ||
		len(parsed.normalized) > maxScalarBytes {
		return "", false
	}
	return parsed.normalized, true
}

func canonicalRegistryPath(value string) (string, bool) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", false
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{
		`microsoft.powershell.core\registry::`,
		`registry::`,
	} {
		if strings.HasPrefix(lower, prefix) {
			value = value[len(prefix):]
			lower = strings.ToLower(value)
			break
		}
	}
	if strings.Contains(lower, "::") || value == "" {
		return "", false
	}
	value = strings.ReplaceAll(value, `\`, "/")
	root, remainder, hasRemainder := strings.Cut(value, "/")
	root = strings.TrimSuffix(root, ":")
	canonicalRoot := ""
	switch strings.ToLower(root) {
	case "hkcu", "hkey_current_user":
		canonicalRoot = "HKCU"
	case "hklm", "hkey_local_machine":
		canonicalRoot = "HKLM"
	case "hkcr", "hkey_classes_root":
		canonicalRoot = "HKCR"
	case "hku", "hkey_users":
		canonicalRoot = "HKU"
	case "hkcc", "hkey_current_config":
		canonicalRoot = "HKCC"
	default:
		return "", false
	}
	if !hasRemainder {
		return canonicalRoot, true
	}
	if remainder == "" {
		return "", false
	}
	parts := strings.Split(remainder, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." ||
			strings.ContainsAny(part, `*?$%:`) {
			return "", false
		}
	}
	return canonicalRoot + "/" + strings.Join(parts, "/"), true
}

func parseWindowsPath(value string) windowsPath {
	return parseWindowsPathWithPolicy(
		value,
		pathExpansionPolicy{expandTilde: true},
	)
}

func parseWindowsPathWithPolicy(
	value string,
	expansion pathExpansionPolicy,
) windowsPath {
	canonical, ok := canonicalWindowsFilesystemPath(value)
	if !ok {
		slashed := strings.ReplaceAll(value, `\`, "/")
		return windowsPath{
			normalized: slashed,
			absolute:   strings.HasPrefix(slashed, "//?/"),
			rooted:     strings.HasPrefix(slashed, "//?/"),
			unresolved: true,
		}
	}
	value = canonical
	// Windows forbids '*' and '?' in exact filesystem path components. Treat
	// them as unresolved only after canonicalizing an extended \\?\ path so
	// the prefix's literal question mark does not invalidate a safe target.
	unresolved := hasUnresolvedPathSyntaxWithPolicy(value, expansion) ||
		strings.ContainsAny(value, `*?`)
	value = strings.ReplaceAll(value, `\`, "/")
	result := windowsPath{unresolved: unresolved}

	if strings.HasPrefix(value, "//") {
		parts := nonEmptyPathParts(strings.TrimLeft(value, "/"))
		if len(parts) < 2 {
			result.normalized = value
			return result
		}
		result.volume = "//" + parts[0] + "/" + parts[1]
		result.absolute = true
		result.rooted = true
		result.tail = strings.Join(parts[2:], "/")
		if !unresolved {
			result.tail = cleanRelativePath(result.tail, true)
		}
		result.normalized = result.volume
		if result.tail != "" && result.tail != "." {
			result.normalized += "/" + result.tail
		}
		return result
	}

	remainder := value
	if len(value) >= 2 && isASCIILetter(value[0]) && value[1] == ':' {
		result.volume = strings.ToUpper(value[:1]) + ":"
		remainder = value[2:]
		if strings.HasPrefix(remainder, "/") {
			result.absolute = true
			result.rooted = true
			remainder = strings.TrimLeft(remainder, "/")
		}
	} else if strings.HasPrefix(value, "/") {
		result.rooted = true
		remainder = strings.TrimLeft(value, "/")
	}

	if unresolved {
		result.tail = remainder
	} else {
		result.tail = cleanRelativePath(remainder, result.rooted)
	}
	switch {
	case result.volume != "" && result.rooted:
		result.normalized = result.volume + "/"
		if result.tail != "" && result.tail != "." {
			result.normalized += result.tail
		}
	case result.volume != "":
		result.normalized = result.volume
		if result.tail != "" && result.tail != "." {
			result.normalized += result.tail
		}
	case result.rooted:
		result.normalized = "/"
		if result.tail != "" && result.tail != "." {
			result.normalized += result.tail
		}
	default:
		result.normalized = result.tail
		if result.normalized == "" {
			result.normalized = "."
		}
	}
	return result
}

func nonEmptyPathParts(value string) []string {
	raw := strings.Split(value, "/")
	parts := make([]string, 0, len(raw))
	for _, part := range raw {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func cleanRelativePath(value string, rooted bool) string {
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "/")
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(cleaned) > 0 && cleaned[len(cleaned)-1] != ".." {
				cleaned = cleaned[:len(cleaned)-1]
			} else if !rooted {
				cleaned = append(cleaned, part)
			}
		default:
			cleaned = append(cleaned, part)
		}
	}
	if len(cleaned) == 0 && !rooted {
		return "."
	}
	return strings.Join(cleaned, "/")
}

func joinWindowsPath(base, relative string) string {
	if relative == "" || relative == "." {
		return base
	}
	return strings.TrimRight(base, "/") + "/" + relative
}

func isDriveVolume(volume string) bool {
	return len(volume) == 2 && isASCIILetter(volume[0]) && volume[1] == ':'
}

func hasUnresolvedPathSyntax(value string) bool {
	return hasUnresolvedPathSyntaxWithPolicy(
		value,
		pathExpansionPolicy{expandTilde: true},
	)
}

func hasUnresolvedPathSyntaxWithPolicy(
	value string,
	expansion pathExpansionPolicy,
) bool {
	if value == "" {
		return false
	}
	neutral := strings.ReplaceAll(value, `\`, "/")
	if strings.HasPrefix(neutral, "~") &&
		(expansion.expandTilde || !expansion.literal) {
		return true
	}
	// Percent is ordinary filesystem content once argv is structured. Raw
	// CMD %VAR% expansion is identified by the CMD lexer before path facts
	// are classified, so treating every percent as unresolved here would
	// also disable exact POSIX and structured-path normalization.
	if expansion.literal {
		return false
	}
	if containsDollarExpansion(value) {
		return true
	}
	return containsPairedExpansion(value, '!')
}

func containsDollarExpansion(value string) bool {
	for offset := 0; offset < len(value); {
		index := strings.IndexByte(value[offset:], '$')
		if index < 0 {
			return false
		}
		index += offset
		if index+1 < len(value) {
			next := value[index+1]
			if next == '{' || next == '(' || next == '_' ||
				isASCIILetter(next) ||
				next >= '0' && next <= '9' ||
				strings.ContainsRune("@*#?$!-", rune(next)) {
				return true
			}
		}
		offset = index + 1
	}
	return false
}

func containsPairedExpansion(value string, delimiter byte) bool {
	start := strings.IndexByte(value, delimiter)
	return start >= 0 && strings.IndexByte(value[start+1:], delimiter) >= 0
}

func normalizeNetworkFacts(facts []NetworkFact) {
	for i := range facts {
		normalized, scope, kind, prefixLength := deriveNetworkTarget(facts[i].Host)
		facts[i].NormalizedHost = normalized
		facts[i].Scope = scope
		facts[i].TargetKind = kind
		facts[i].PrefixLength = prefixLength
	}
}

func deriveNetworkTarget(host string) (string, NetworkScope, NetworkTargetKind, int64) {
	if host == "" || strings.TrimSpace(host) != host ||
		len(host) > maxScalarBytes {
		return "", NetworkScopeUnknown, NetworkTargetUnknown, 0
	}
	if strings.Contains(host, ",") {
		return deriveNetworkList(host)
	}
	if prefix, err := netip.ParsePrefix(host); err == nil {
		prefix = prefix.Masked()
		kind := NetworkTargetMultiAddressCIDR
		if prefix.Bits() == prefix.Addr().BitLen() {
			kind = NetworkTargetSingleAddressCIDR
		}
		return prefix.String(), scopePrefix(prefix), kind, int64(prefix.Bits())
	}
	if normalized, first, last, ok := parseNetworkRange(host); ok {
		return normalized, commonAddressScope(first, last), NetworkTargetRange, 0
	}
	if looksIPv4RangeCandidate(host) {
		return "", NetworkScopeUnknown, NetworkTargetUnknown, 0
	}
	if normalized, first, last, ok := parseGeneratedTarget(host); ok {
		return normalized, commonAddressScope(first, last), NetworkTargetGenerated, 0
	}
	canonical, ok := canonicalNetworkHost(host)
	if !ok {
		return "", NetworkScopeUnknown, NetworkTargetUnknown, 0
	}
	if address, err := netip.ParseAddr(canonical); err == nil {
		return address.String(), scopeAddress(address), NetworkTargetSingleHost, 0
	}
	return canonical, NetworkScopeUnknown, NetworkTargetSingleHost, 0
}

func deriveNetworkList(host string) (string, NetworkScope, NetworkTargetKind, int64) {
	parts := strings.Split(host, ",")
	if len(parts) < 2 || len(parts) > maxNetworkFacts {
		return "", NetworkScopeUnknown, NetworkTargetUnknown, 0
	}
	normalized := make([]string, 0, len(parts))
	scope := NetworkScopeUnknown
	scopeKnown := true
	for _, part := range parts {
		if part == "" || strings.TrimSpace(part) != part {
			return "", NetworkScopeUnknown, NetworkTargetUnknown, 0
		}
		value, itemScope, kind, _ := deriveNetworkTarget(part)
		if value == "" || kind == NetworkTargetUnknown || kind == NetworkTargetList {
			return "", NetworkScopeUnknown, NetworkTargetUnknown, 0
		}
		normalized = append(normalized, value)
		if itemScope == NetworkScopeUnknown {
			scopeKnown = false
			continue
		}
		if scope == NetworkScopeUnknown {
			scope = itemScope
		} else if scope != itemScope {
			scopeKnown = false
		}
	}
	if !scopeKnown {
		scope = NetworkScopeUnknown
	}
	value := strings.Join(normalized, ",")
	if len(value) > maxScalarBytes {
		return "", NetworkScopeUnknown, NetworkTargetUnknown, 0
	}
	return value, scope, NetworkTargetList, 0
}

func parseNetworkRange(host string) (string, netip.Addr, netip.Addr, bool) {
	if strings.Count(host, "-") == 1 {
		left, right, _ := strings.Cut(host, "-")
		if left == "" || right == "" ||
			strings.TrimSpace(left) != left ||
			strings.TrimSpace(right) != right {
			return "", netip.Addr{}, netip.Addr{}, false
		}
		first, firstErr := netip.ParseAddr(left)
		last, lastErr := netip.ParseAddr(right)
		if firstErr == nil && lastErr == nil && first.BitLen() == last.BitLen() &&
			first.Compare(last) <= 0 {
			return first.String() + "-" + last.String(), first, last, true
		}
	}

	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return "", netip.Addr{}, netip.Addr{}, false
	}
	var firstBytes, lastBytes [4]byte
	normalized := make([]string, len(parts))
	haveRange := false
	for i, part := range parts {
		first, last, rangePart, ok := parseIPv4RangePart(part)
		if !ok {
			return "", netip.Addr{}, netip.Addr{}, false
		}
		firstBytes[i] = byte(first)
		lastBytes[i] = byte(last)
		haveRange = haveRange || rangePart
		if rangePart {
			normalized[i] = strconv.Itoa(first) + "-" + strconv.Itoa(last)
		} else {
			normalized[i] = strconv.Itoa(first)
		}
	}
	if !haveRange {
		return "", netip.Addr{}, netip.Addr{}, false
	}
	return strings.Join(normalized, "."),
		netip.AddrFrom4(firstBytes),
		netip.AddrFrom4(lastBytes),
		true
}

func parseIPv4RangePart(
	value string,
) (first, last int, rangePart, ok bool) {
	if strings.Count(value, "-") > 1 {
		return 0, 0, false, false
	}
	left, right, hasRange := strings.Cut(value, "-")
	first, ok = parseCanonicalIPv4Octet(left)
	if !ok {
		return 0, 0, false, false
	}
	if !hasRange {
		return first, first, false, true
	}
	last, ok = parseCanonicalIPv4Octet(right)
	if !ok || last < first {
		return 0, 0, false, false
	}
	return first, last, true, true
}

func looksIPv4RangeCandidate(host string) bool {
	left, right, hasRange := strings.Cut(host, "-")
	if hasRange && !strings.Contains(right, "-") &&
		looksDottedDecimalIPv4(left) && looksDottedDecimalIPv4(right) {
		return true
	}

	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	haveRange := false
	for _, part := range parts {
		if part == "" {
			return false
		}
		for i := range len(part) {
			switch {
			case part[i] >= '0' && part[i] <= '9':
			case part[i] == '-':
				haveRange = true
			default:
				return false
			}
		}
	}
	return haveRange
}

func looksDottedDecimalIPv4(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for i := range len(part) {
			if part[i] < '0' || part[i] > '9' {
				return false
			}
		}
	}
	return true
}

func parseCanonicalIPv4Octet(value string) (int, bool) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	octet, err := strconv.Atoi(value)
	return octet, err == nil && octet <= 255
}

func parseGeneratedTarget(host string) (string, netip.Addr, netip.Addr, bool) {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return "", netip.Addr{}, netip.Addr{}, false
	}
	var firstBytes, lastBytes [4]byte
	normalized := make([]string, len(parts))
	haveWildcard := false
	for i, part := range parts {
		if part == "*" {
			firstBytes[i] = 0
			lastBytes[i] = 255
			normalized[i] = "*"
			haveWildcard = true
			continue
		}
		value, ok := parseCanonicalIPv4Octet(part)
		if !ok {
			return "", netip.Addr{}, netip.Addr{}, false
		}
		firstBytes[i] = byte(value)
		lastBytes[i] = byte(value)
		normalized[i] = strconv.Itoa(value)
	}
	if !haveWildcard {
		return "", netip.Addr{}, netip.Addr{}, false
	}
	return strings.Join(normalized, "."),
		netip.AddrFrom4(firstBytes),
		netip.AddrFrom4(lastBytes),
		true
}

func scopePrefix(prefix netip.Prefix) NetworkScope {
	first := prefix.Masked().Addr()
	last := lastPrefixAddress(prefix)
	if !last.IsValid() {
		return NetworkScopeUnknown
	}
	return commonAddressScope(first, last)
}

func lastPrefixAddress(prefix netip.Prefix) netip.Addr {
	prefix = prefix.Masked()
	address := prefix.Addr()
	if !address.IsValid() || prefix.Bits() < 0 {
		return netip.Addr{}
	}
	bits := address.BitLen()
	hostBits := bits - prefix.Bits()
	if address.Is4() {
		bytes := address.As4()
		for bit := 0; bit < hostBits; bit++ {
			index := len(bytes) - 1 - bit/8
			bytes[index] |= 1 << uint(bit%8)
		}
		return netip.AddrFrom4(bytes)
	}
	zone := address.Zone()
	bytes := address.As16()
	for bit := 0; bit < hostBits; bit++ {
		index := len(bytes) - 1 - bit/8
		bytes[index] |= 1 << uint(bit%8)
	}
	return netip.AddrFrom16(bytes).WithZone(zone)
}

func commonAddressScope(first, last netip.Addr) NetworkScope {
	if !first.IsValid() || !last.IsValid() {
		return NetworkScopeUnknown
	}
	if first.Zone() != "" {
		first = first.WithZone("")
	}
	if last.Zone() != "" {
		last = last.WithZone("")
	}
	first = first.Unmap()
	last = last.Unmap()
	if first.BitLen() != last.BitLen() || first.Compare(last) > 0 {
		return NetworkScopeUnknown
	}
	firstScope := scopeAddress(first)
	if firstScope == NetworkScopeUnknown || firstScope != scopeAddress(last) {
		return NetworkScopeUnknown
	}
	if first == last {
		return firstScope
	}
	for _, block := range networkScopeBlocks {
		if block.scope == firstScope &&
			block.prefix.Contains(first) &&
			block.prefix.Contains(last) {
			return firstScope
		}
	}
	if firstScope != NetworkScopePublic {
		return NetworkScopeUnknown
	}
	for _, block := range nonPublicNetworkBlocks {
		if addressRangesOverlap(
			first,
			last,
			block.Masked().Addr(),
			lastPrefixAddress(block),
		) {
			return NetworkScopeUnknown
		}
	}
	return NetworkScopePublic
}

type scopedNetworkPrefix struct {
	prefix netip.Prefix
	scope  NetworkScope
}

var networkScopeBlocks = []scopedNetworkPrefix{
	{prefix: netip.MustParsePrefix("127.0.0.0/8"), scope: NetworkScopeLoopback},
	{prefix: netip.MustParsePrefix("::1/128"), scope: NetworkScopeLoopback},
	{prefix: netip.MustParsePrefix("169.254.0.0/16"), scope: NetworkScopeLinkLocal},
	{prefix: netip.MustParsePrefix("224.0.0.0/24"), scope: NetworkScopeLinkLocal},
	{prefix: netip.MustParsePrefix("fe80::/10"), scope: NetworkScopeLinkLocal},
	{prefix: netip.MustParsePrefix("ff02::/16"), scope: NetworkScopeLinkLocal},
	{prefix: netip.MustParsePrefix("10.0.0.0/8"), scope: NetworkScopePrivate},
	{prefix: netip.MustParsePrefix("172.16.0.0/12"), scope: NetworkScopePrivate},
	{prefix: netip.MustParsePrefix("192.168.0.0/16"), scope: NetworkScopePrivate},
	{prefix: netip.MustParsePrefix("fc00::/7"), scope: NetworkScopePrivate},
}

var nonPublicNetworkBlocks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func addressInPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func addressRangesOverlap(first, last, otherFirst, otherLast netip.Addr) bool {
	if !otherFirst.IsValid() || !otherLast.IsValid() ||
		first.BitLen() != otherFirst.BitLen() {
		return false
	}
	return first.Compare(otherLast) <= 0 && otherFirst.Compare(last) <= 0
}

func scopeAddress(address netip.Addr) NetworkScope {
	if !address.IsValid() {
		return NetworkScopeUnknown
	}
	if address.Zone() != "" {
		address = address.WithZone("")
	}
	address = address.Unmap()
	switch {
	case address.IsLoopback():
		return NetworkScopeLoopback
	case address.IsLinkLocalUnicast(), address.IsLinkLocalMulticast():
		return NetworkScopeLinkLocal
	case address.IsPrivate():
		return NetworkScopePrivate
	case addressInPrefixes(address, nonPublicNetworkBlocks):
		return NetworkScopeUnknown
	case address.IsGlobalUnicast():
		return NetworkScopePublic
	default:
		return NetworkScopeUnknown
	}
}
