// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"strings"
	"testing"
)

// TestEnterpriseBlockEmptyCoversEveryField sets each exported field of
// EnterpriseConfig, recursively, to a non-zero value and requires
// enterpriseBlockEmpty to notice. Both refusals (an enterprise block in an
// unmanaged config, a standalone knob in a Secure Client config) go through
// that hand-written function, so a new field it forgets would validate
// silently in exactly the configs that must refuse it. This test fails the
// day such a field is added.
func TestEnterpriseBlockEmptyCoversEveryField(t *testing.T) {
	if !enterpriseBlockEmpty(EnterpriseConfig{}) {
		t.Fatal("the zero EnterpriseConfig is not empty")
	}
	leaves := 0
	var walk func(path []int, names []string, typ reflect.Type)
	walk = func(path []int, names []string, typ reflect.Type) {
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			if !field.IsExported() {
				continue
			}
			fieldPath := append(append([]int{}, path...), index)
			fieldNames := append(append([]string{}, names...), field.Name)
			if field.Type.Kind() == reflect.Struct {
				walk(fieldPath, fieldNames, field.Type)
				continue
			}
			leaves++
			var block EnterpriseConfig
			target := reflect.ValueOf(&block).Elem().FieldByIndex(fieldPath)
			if !setNonZero(target) {
				t.Fatalf("%s: no non-zero value for kind %s; extend setNonZero", strings.Join(fieldNames, "."), target.Kind())
			}
			if enterpriseBlockEmpty(block) {
				t.Errorf("enterpriseBlockEmpty ignores %s: an unmanaged or Secure Client config carrying it would validate", strings.Join(fieldNames, "."))
			}
		}
	}
	walk(nil, nil, reflect.TypeOf(EnterpriseConfig{}))
	if leaves < 30 {
		t.Fatalf("walked only %d fields; the walk is broken", leaves)
	}
}

// setNonZero stores a value enterpriseBlockEmpty must treat as set: a
// non-blank string, true, 1, a pointer to false (an explicit setting), or a
// one-element slice or map.
func setNonZero(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.String:
		value.SetString("x")
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value.SetInt(1)
	case reflect.Pointer:
		elem := reflect.New(value.Type().Elem())
		value.Set(elem)
	case reflect.Slice:
		slice := reflect.MakeSlice(value.Type(), 1, 1)
		_ = setNonZero(slice.Index(0))
		value.Set(slice)
	case reflect.Map:
		entry := reflect.MakeMap(value.Type())
		key := reflect.New(value.Type().Key()).Elem()
		_ = setNonZero(key)
		entry.SetMapIndex(key, reflect.New(value.Type().Elem()).Elem())
		value.Set(entry)
	default:
		return false
	}
	return true
}
