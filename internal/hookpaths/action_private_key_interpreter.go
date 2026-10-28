// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"regexp"
	"strings"
)

// Inline interpreter code that names a private key under .ssh and calls a
// file reader in executable code reads the key as cat does (GAP-0281):
// python3 -c "print(open(os.path.expanduser('~/.ssh/id_ed25519')).read())".
// The public key and its certificate are not private keys.
var (
	actionInterpreterPrivateKeyName = regexp.MustCompile(`\bid_(?:rsa|ed25519|ecdsa|dsa)\b`)
	actionInterpreterReader         = regexp.MustCompile(`\b(?:open|openSync|FileIO|read_text|read_bytes|readFile\w*|createReadStream|File\.(?:read|open|binread|readlines|foreach)|IO\.(?:read|binread|readlines))\s*\(|\bopen\s+[A-Za-z_$]`)
)

// actionInterpreterReadsPrivateKey reports python -c, node -e, perl -e or
// ruby -e code that names a private key in .ssh and has an executable
// reader call.
func actionInterpreterReadsPrivateKey(code, language string) bool {
	if !actionInterpreterSSHName.MatchString(code) {
		return false
	}
	named := false
	for _, location := range actionInterpreterPrivateKeyName.FindAllStringIndex(code, -1) {
		rest := code[location[1]:]
		if !strings.HasPrefix(rest, ".pub") && !strings.HasPrefix(rest, "-cert") {
			named = true
			break
		}
	}
	if !named {
		return false
	}
	for _, location := range actionInterpreterReader.FindAllStringIndex(code, -1) {
		if language == "python" {
			if pythonExecutableCodePosition(code, location[0]) {
				return true
			}
		} else if literalCodePosition(code, location[0], language) {
			return true
		}
	}
	return false
}
