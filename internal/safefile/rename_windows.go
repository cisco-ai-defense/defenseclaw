// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

const (
	replaceFileMaxAttempts = 100
	replaceFileRetryDelay  = 5 * time.Millisecond
)

func replaceFile(source, destination string) error {
	return replaceFileWith(source, destination, os.Rename, time.Sleep)
}

func replaceFileWith(
	source string,
	destination string,
	rename func(string, string) error,
	sleep func(time.Duration),
) error {
	var err error
	for attempt := 0; attempt < replaceFileMaxAttempts; attempt++ {
		err = rename(source, destination)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) &&
			!errors.Is(err, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return err
		}
		if attempt+1 == replaceFileMaxAttempts {
			return err
		}
		sleep(replaceFileRetryDelay)
	}
	return err
}
