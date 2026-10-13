package gateway

import (
	"path"
	"reflect"
	"strings"
)

// configValuesEqualForDiff compares effective config values without treating
// different spellings of the same Windows path as a policy edit. The runtime
// loader and the v8 reload compiler can produce slash, case, and trailing
// separator differences for default paths. Keep the comparison lexical: a
// filesystem lookup here would make a diff depend on whether an asset exists.
func configValuesEqualForDiff(left, right any, goos string) bool {
	if goos != "windows" || reflect.DeepEqual(left, right) {
		return reflect.DeepEqual(left, right)
	}
	return configDiffValuesEqual(reflect.ValueOf(left), reflect.ValueOf(right), false)
}

func configDiffValuesEqual(left, right reflect.Value, isPath bool) bool {
	if !left.IsValid() || !right.IsValid() {
		return !left.IsValid() && !right.IsValid()
	}
	if left.Type() != right.Type() {
		return false
	}
	if left.CanInterface() && right.CanInterface() && reflect.DeepEqual(left.Interface(), right.Interface()) {
		return true
	}
	switch left.Kind() {
	case reflect.String:
		if isPath {
			return equalWindowsConfigPath(left.String(), right.String())
		}
		return left.String() == right.String()
	case reflect.Bool:
		return left.Bool() == right.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return left.Int() == right.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return left.Uint() == right.Uint()
	case reflect.Float32, reflect.Float64:
		return left.Float() == right.Float()
	case reflect.Complex64, reflect.Complex128:
		return left.Complex() == right.Complex()
	case reflect.Func:
		return left.IsNil() && right.IsNil()
	case reflect.Chan, reflect.UnsafePointer:
		return left.Pointer() == right.Pointer()
	case reflect.Interface, reflect.Pointer:
		if left.IsNil() || right.IsNil() {
			return left.IsNil() && right.IsNil()
		}
		return configDiffValuesEqual(left.Elem(), right.Elem(), isPath)
	case reflect.Struct:
		for i := 0; i < left.NumField(); i++ {
			field := left.Type().Field(i)
			if !configDiffValuesEqual(left.Field(i), right.Field(i), isPath || configDiffPathField(left.Type(), field)) {
				return false
			}
		}
		return true
	case reflect.Slice, reflect.Array:
		if left.Kind() == reflect.Slice && left.IsNil() != right.IsNil() || left.Len() != right.Len() {
			return false
		}
		for i := 0; i < left.Len(); i++ {
			if !configDiffValuesEqual(left.Index(i), right.Index(i), isPath) {
				return false
			}
		}
		return true
	case reflect.Map:
		if left.IsNil() != right.IsNil() || left.Len() != right.Len() {
			return false
		}
		for iter := left.MapRange(); iter.Next(); {
			other := right.MapIndex(iter.Key())
			if !other.IsValid() || !configDiffValuesEqual(iter.Value(), other, isPath) {
				return false
			}
		}
		return true
	}
	return false
}

func configDiffPathField(parent reflect.Type, field reflect.StructField) bool {
	name := strings.Split(field.Tag.Get("yaml"), ",")[0]
	if name == "" || name == "-" {
		name = strings.ToLower(field.Name)
	}
	for _, suffix := range []string{"_path", "_paths", "_dir", "_dirs", "_file", "_files", "_root", "_roots", "_db"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	switch name {
	case "path":
		// A bare path can also be a case-sensitive URL route (the
		// observability signal override). Only these are filesystem paths.
		switch parent.Name() {
		case "AssetFileRef", "CustomRulePack", "ObservabilityV8LocalSource", "ObservabilityV8DestinationSource":
			return true
		}
	case "dirs", "root", "audit_db", "judge_bodies_db", "clawhome", "ca_cert", "cacert":
		return true
	}
	return false
}

func equalWindowsConfigPath(left, right string) bool {
	if left == "" || right == "" {
		return left == right
	}
	clean := func(value string) string {
		return path.Clean(strings.ReplaceAll(value, `\`, "/"))
	}
	return strings.EqualFold(clean(left), clean(right))
}

func equalConfigPathForDiff(left, right, goos string) bool {
	if goos != "windows" {
		return left == right
	}
	return equalWindowsConfigPath(left, right)
}
