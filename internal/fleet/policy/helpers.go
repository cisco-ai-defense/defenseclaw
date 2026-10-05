package policy

import "os"

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
