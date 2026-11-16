// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"os"
)

// The reach reader shares the existing bounded network path operations.
func ShareUnanswered(err error) bool { return errors.Is(err, errNetworkShareUnanswered) }
func SharePath(name string) bool     { return networkShareRootOf(name) != "" }
func PathStat(name string) (os.FileInfo, error) {
	return pathStat(name)
}
func PathLstat(name string) (os.FileInfo, error) {
	return pathLstat(name)
}
func PathReadlink(name string) (string, error) {
	return pathReadlink(name)
}
