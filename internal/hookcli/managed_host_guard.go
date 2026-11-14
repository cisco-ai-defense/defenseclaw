// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookcli

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedHostDescriptorPath is where a standalone managed deployment
// publishes its runtime descriptor on this OS ("" where the check does not
// apply). A seam for tests.
var ManagedHostDescriptorPath = func() string {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return ""
	}
	return layout.DescriptorPath
}

// managedRecordTrusted reports whether a managed-deployment record at path
// can only have been written by an administrator. validateFile checks the
// record and its ancestors; validateDir checks a directory that admits no
// writer other than an administrator and whose ancestors cannot be replaced.
//
// A standard user cannot inspect an administrator-only record, or the
// administrator-only directory holding it. For that caller the nearest
// ancestor strictly below stop that it can inspect decides: when that
// directory admits only administrator writers, everything below it was
// created by an administrator. Any other trust failure (a user-owned file,
// a user-writable directory, a reparse point) or reaching stop without such a
// directory means the record could have been planted, so it is untrusted.
func ManagedRecordTrusted(path, stop string, validateFile, validateDir func(string) error) error {
	err := validateFile(path)
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return err
	}
	stop = filepath.Clean(stop)
	for dir := filepath.Dir(filepath.Clean(path)); pathStrictlyWithin(dir, stop); dir = filepath.Dir(dir) {
		dirErr := validateDir(dir)
		if dirErr == nil {
			return nil
		}
		if !errors.Is(dirErr, fs.ErrPermission) {
			return dirErr
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	return fmt.Errorf("%s cannot be inspected and no administrator-only directory below %s holds it: %w", path, stop, err)
}

// managedStandaloneRecordCounts decides whether a recorded Windows
// standalone deployment disables the per-user gateway, and names what proves
// it. The record counts when recordTrusted shows that an administrator wrote
// it. A standard user usually cannot show that. It cannot read the security
// settings of the administrator-only product directory under %ProgramData%.
// The vendor directory above that one often keeps the ProgramData
// create-child grant for Users, so the ancestor walk ends at a directory a
// user could have written. For that caller the gateway service decides
// instead. Only an administrator can register a service, so a gateway service
// that runs the standalone gateway executable proves the deployment is real.
// standaloneService describes that service or says why there is none. A
// planted record on a host without the service still counts for nothing.
func ManagedStandaloneRecordCounts(record string, recordTrusted func(string) error, standaloneService func() (string, error)) (string, error) {
	recordErr := recordTrusted(record)
	if recordErr == nil {
		return record, nil
	}
	service, serviceErr := standaloneService()
	if serviceErr == nil {
		return service, nil
	}
	return "", fmt.Errorf("%w; no administrator-registered standalone gateway service confirms it: %v", recordErr, serviceErr)
}

// standaloneGatewayServiceImageMatches checks that a service's registered
// image path launches exactly gatewayPath. The lifecycle registers the
// standalone gateway as its quoted executable path. The Secure Client profile
// uses the same service name with its own executable, so the path is what
// tells the two apart.
func StandaloneGatewayServiceImageMatches(imagePath, gatewayPath string) error {
	executable := serviceImageExecutable(imagePath)
	if executable == "" || gatewayPath == "" || !strings.EqualFold(executable, gatewayPath) {
		return fmt.Errorf("service image %q does not run %s", imagePath, gatewayPath)
	}
	return nil
}

// serviceImageExecutable returns the executable of a service image path: the
// quoted first token, or the text before the first blank when it is unquoted.
func serviceImageExecutable(imagePath string) string {
	image := strings.TrimSpace(imagePath)
	if strings.HasPrefix(image, `"`) {
		end := strings.IndexByte(image[1:], '"')
		if end < 0 {
			return ""
		}
		return image[1 : 1+end]
	}
	if index := strings.IndexAny(image, " \t"); index >= 0 {
		return image[:index]
	}
	return image
}

// pathStrictlyWithin reports whether dir lies below root (not root itself).
func pathStrictlyWithin(dir, root string) bool {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
