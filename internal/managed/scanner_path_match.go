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

package managed

import "strings"

// windowsPathWithinProfileRoots compares Windows paths on component boundaries.
// The Windows caller resolves existing reparse points and short names first.
func windowsPathWithinProfileRoots(path string, roots []string) bool {
	candidate := normalizeWindowsProfileComparePath(path)
	if candidate == "" {
		return false
	}
	for _, root := range roots {
		base := normalizeWindowsProfileComparePath(root)
		if base != "" && (candidate == base || strings.HasPrefix(candidate, strings.TrimSuffix(base, `\`)+`\`)) {
			return true
		}
	}
	return false
}

func normalizeWindowsProfileComparePath(path string) string {
	path = strings.ReplaceAll(path, "/", `\`)
	lower := strings.ToLower(path)
	if strings.HasPrefix(lower, `\\?\unc\`) {
		path = `\\` + path[len(`\\?\UNC\`):]
	} else if strings.HasPrefix(lower, `\\?\`) {
		path = path[len(`\\?\`):]
	}
	var prefix, rest string
	if len(path) >= 3 && path[1] == ':' && path[2] == '\\' {
		prefix, rest = strings.ToLower(path[:2])+`\`, path[3:]
	} else if strings.HasPrefix(path, `\\`) {
		parts := strings.Split(path[2:], `\`)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return ""
		}
		prefix = `\\` + strings.ToLower(parts[0]+`\`+parts[1])
		rest = strings.Join(parts[2:], `\`)
	} else {
		return ""
	}
	var components []string
	for _, component := range strings.Split(rest, `\`) {
		switch component {
		case "", ".":
			continue
		case "..":
			if len(components) > 0 {
				components = components[:len(components)-1]
			}
			continue
		}
		component = strings.TrimRight(component, " .")
		if component != "" {
			components = append(components, strings.ToLower(component))
		}
	}
	if len(components) == 0 {
		return prefix
	}
	if strings.HasSuffix(prefix, `\`) {
		return prefix + strings.Join(components, `\`)
	}
	return prefix + `\` + strings.Join(components, `\`)
}
