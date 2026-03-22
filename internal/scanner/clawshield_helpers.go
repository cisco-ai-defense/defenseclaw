package scanner

import (
	"fmt"
	"os"
	"path/filepath"
)

// csTextExtensions is the set of file extensions scanned by text-based ClawShield scanners.
var csTextExtensions = map[string]bool{
	// code
	".py": true, ".js": true, ".ts": true, ".go": true,
	".java": true, ".rb": true, ".php": true, ".sh": true,
	".c": true, ".cpp": true, ".h": true, ".rs": true,
	// config / data
	".yaml": true, ".yml": true, ".json": true, ".toml": true, ".xml": true,
	".env": true, ".ini": true, ".cfg": true, ".conf": true,
	// docs / templates
	".md": true, ".txt": true, ".rst": true, ".html": true, ".jinja": true,
}

// csCollectTextFiles returns all text-extension files under root.
func csCollectTextFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "__pycache__" || name == ".venv" || name == "venv" {
				return filepath.SkipDir
			}
			return nil
		}
		if csTextExtensions[filepath.Ext(path)] {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// csCollectAllFiles returns all non-directory files under root (for binary-aware scanning).
func csCollectAllFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		files = append(files, path)
		return nil
	})
	return files, err
}

// csOffsetToLine returns the 1-based line number for a byte offset in content.
func csOffsetToLine(content []byte, offset int) int {
	if offset > len(content) {
		offset = len(content)
	}
	line := 1
	for i := 0; i < offset; i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}

// csTruncateMatch caps a match string at 100 chars for display.
func csTruncateMatch(s string) string {
	if len(s) > 100 {
		return s[:100] + "..."
	}
	return s
}

// csLocation formats a file:line location string.
func csLocation(path string, content []byte, offset int) string {
	return fmt.Sprintf("%s:%d", path, csOffsetToLine(content, offset))
}
