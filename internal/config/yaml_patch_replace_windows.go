// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

const (
	configReplaceMaxAttempts  = 8
	configReplaceInitialDelay = 10 * time.Millisecond
	configReplaceMaxDelay     = 50 * time.Millisecond
)

type configRenameFunc func(string, string) error
type configSleepFunc func(time.Duration)

// replaceConfigFile keeps os.Rename as the single atomic commit operation but
// tolerates the short-lived sharing locks that Windows indexers and security
// scanners can take between closing the same-directory staging file and the
// replacement. It never deletes the destination and gives up after a bounded
// 270 ms backoff, so permanent ACL failures still surface promptly.
func replaceConfigFile(source, target string) error {
	return replaceConfigFileWith(source, target, os.Rename, time.Sleep)
}

func replaceConfigFileWith(
	source string,
	target string,
	rename configRenameFunc,
	sleep configSleepFunc,
) error {
	delay := configReplaceInitialDelay
	for attempt := 1; attempt < configReplaceMaxAttempts; attempt++ {
		err := rename(source, target)
		if err == nil {
			return nil
		}
		if !isTransientConfigReplaceError(err) {
			return err
		}
		sleep(delay)
		if delay < configReplaceMaxDelay {
			delay *= 2
			if delay > configReplaceMaxDelay {
				delay = configReplaceMaxDelay
			}
		}
	}
	return rename(source, target)
}

func isTransientConfigReplaceError(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
