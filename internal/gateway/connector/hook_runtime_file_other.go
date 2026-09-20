// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"fmt"
	"os"
	"reflect"
)

// FileInfo.Sys uses platform-specific stat structures, but supported Unix
// targets consistently expose an integer Nlink field. Reflection keeps this
// small check portable without a build-tag matrix for every Unix ABI.
//
// Every non-happy branch here now fails CLOSED with a targeted error:
// silently returning nil when Sys() is nil / not a struct / lacks Nlink /
// has a non-integer Nlink would let a caller believe the hardlink check
// ran when in fact we could not verify link count. On supported Linux
// and macOS builds the reflection succeeds and the fail-closed branches
// are unreachable; on an exotic Unix ABI that ships a Stat_t without a
// numeric Nlink, we refuse to accept the file rather than treat it as
// trusted.
func validateHookRuntimeOpenedFile(file *os.File, label string) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened %s: %w", label, err)
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return fmt.Errorf("%s Sys() returned a nil pointer; cannot verify link count", label)
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return fmt.Errorf("%s Sys() is not a struct; cannot verify link count on this platform", label)
	}
	links := value.FieldByName("Nlink")
	if !links.IsValid() {
		return fmt.Errorf("%s Sys() has no Nlink field; cannot verify link count on this platform", label)
	}
	var count uint64
	switch links.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		count = links.Uint()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if links.Int() < 0 {
			return fmt.Errorf("%s has an invalid link count", label)
		}
		count = uint64(links.Int())
	default:
		return fmt.Errorf("%s Nlink field has unexpected kind %s; cannot verify link count", label, links.Kind())
	}
	if count != 1 {
		return fmt.Errorf("%s must be a single-link regular file (links=%d)", label, count)
	}
	return nil
}
