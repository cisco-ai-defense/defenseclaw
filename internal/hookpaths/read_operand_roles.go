// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"regexp"
	"strings"
)

var plainAWKPrint = regexp.MustCompile(`^\{[ \t]*print(?:[ \t]+\$[0-9]+(?:[ \t]*,[ \t]*\$[0-9]+)*)?[ \t]*\}$`)

// ProvedReadOnlyFileOperands recognizes a complete process invocation whose
// path arguments are inputs. Each accepted utility has its output-capable
// options checked here; the shell caller still checks redirects and nested
// substitutions at their own positions.
func ProvedReadOnlyFileOperands(executable string, argv []string) bool {
	if !actionBareReaderExecutable(executable) || len(argv) == 0 || argv[0] != executable {
		return false
	}
	switch executable {
	case "md5sum", "b2sum", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "cksum", "sum":
		for _, arg := range argv[1:] {
			if actionReadOptionMayWrite(arg) {
				return false
			}
		}
		return true
	case "sort":
		for _, arg := range argv[1:] {
			if actionReadOptionMayWrite(arg) || strings.HasPrefix(arg, "--compress-program") ||
				strings.HasPrefix(arg, "--temporary-directory") || arg == "-T" || strings.HasPrefix(arg, "-T") {
				return false
			}
			if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg[1:], "o") {
				return false
			}
		}
		return true
	case "file":
		for _, arg := range argv[1:] {
			if actionReadOptionMayWrite(arg) {
				return false
			}
		}
		return true
	case "awk", "gawk", "mawk", "nawk":
		if len(argv) < 3 {
			return false
		}
		index := 1
		for index < len(argv) && strings.HasPrefix(argv[index], "-F") {
			if argv[index] == "-F" {
				index += 2
			} else {
				index++
			}
		}
		return index < len(argv)-1 && plainAWKPrint.MatchString(argv[index])
	}
	return false
}

func actionBareReaderExecutable(program string) bool {
	return program != "" && !strings.ContainsAny(program, `/\`) && !strings.HasPrefix(program, ".")
}
