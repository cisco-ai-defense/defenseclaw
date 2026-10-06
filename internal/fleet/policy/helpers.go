package policy

import (
	"encoding/binary"
	"os"
)

// File I/O helpers — thin wrappers so tests can verify compiler invocation
// without needing to mock the entire os package.

func makeTempDir() (string, error) {
	return os.MkdirTemp("", "dclaw-policy-*")
}

func removeAll(path string) error {
	return os.RemoveAll(path)
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// stripDevSignature detects and removes the Python compiler's dev-stub
// signature from a policy blob, if present (Comment 51 fix).
//
// The dev stub format (from policy_compiler.py):
//
//	b'\xED' + hashlib.sha256(blob).digest()[:63]  = 64 bytes
//
// Detection criteria:
//  1. Blob must be longer than HeaderSize + 64 bytes
//  2. The byte at position len(blob)-64 must be 0xED (dev marker)
//  3. Stripping 64 bytes must leave a valid header where
//     HeaderSize + payload_len == remaining length
//
// If all criteria match, the last 64 bytes are stripped. Otherwise,
// the blob is returned unchanged.
func stripDevSignature(blob []byte) []byte {
	const devSigSize = 64
	const devMarker = 0xED

	if len(blob) <= HeaderSize+devSigSize {
		return blob
	}

	sigStart := len(blob) - devSigSize
	if blob[sigStart] != devMarker {
		return blob // no dev marker — raw policy, no stripping
	}

	// Verify that stripping leaves a valid header with consistent payload_len
	candidate := blob[:sigStart]
	if len(candidate) < HeaderSize {
		return blob
	}

	payloadLen := binary.BigEndian.Uint16(candidate[2:4])
	expectedLen := HeaderSize + int(payloadLen)
	if expectedLen != len(candidate) {
		return blob // payload_len doesn't match — don't strip
	}

	return candidate
}
