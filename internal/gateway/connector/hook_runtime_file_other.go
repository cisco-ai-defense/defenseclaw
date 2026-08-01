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
func validateHookRuntimeOpenedFile(file *os.File, label string) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened %s: %w", label, err)
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return nil
	}
	links := value.FieldByName("Nlink")
	if !links.IsValid() {
		return nil
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
		return nil
	}
	if count != 1 {
		return fmt.Errorf("%s must be a single-link regular file (links=%d)", label, count)
	}
	return nil
}
