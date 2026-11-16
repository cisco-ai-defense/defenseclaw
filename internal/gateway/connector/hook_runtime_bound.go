// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"io"
	"os"
)

// openPinnedHookRuntime keeps cleanup on the hooks directory that was
// inspected. A link at hooks, including one substituted while opening it,
// is not a hook directory owned by this data directory.
func openPinnedHookRuntime(dataDir string) (data, hooks *os.Root, err error) {
	data, err = os.OpenRoot(dataDir)
	if err != nil {
		return nil, nil, err
	}
	info, err := data.Lstat("hooks")
	if err != nil {
		_ = data.Close()
		return nil, nil, err
	}
	if !info.IsDir() {
		_ = data.Close()
		return nil, nil, fmt.Errorf("hook runtime folder is not a directory")
	}
	hooks, err = data.OpenRoot("hooks")
	if err != nil {
		_ = data.Close()
		return nil, nil, err
	}
	opened, err := hooks.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = hooks.Close()
		_ = data.Close()
		return nil, nil, fmt.Errorf("hook runtime folder changed while opening it")
	}
	return data, hooks, nil
}

func readPinnedRegularFile(root *os.Root, name string, maxBytes int64) ([]byte, error) {
	named, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !named.Mode().IsRegular() || named.Size() > maxBytes {
		return nil, fmt.Errorf("hook runtime file is not bounded regular data: %s", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(named, opened) {
		return nil, fmt.Errorf("hook runtime file changed while opening it: %s", name)
	}
	body, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("hook runtime file exceeds its size limit: %s", name)
	}
	return body, nil
}

func removePinnedRegularFile(root *os.Root, name string, expected os.FileInfo) error {
	current, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || !os.SameFile(expected, current) {
		return fmt.Errorf("hook runtime file changed before removal: %s", name)
	}
	return root.Remove(name)
}
