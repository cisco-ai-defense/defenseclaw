// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"
)

// A fully populated RouteOnlySetup encodes, as the standalone guardian
// encodes it into each worker request: the render facts cross, the
// in-process gate fields stay behind. Every field is given a value by
// reflection, so a new func or chan field without json:"-" fails here
// instead of on a managed host (rel-1-0-10:GAP-1311).
func TestRouteOnlySetupFullyPopulatedEncodesForTheWorker(t *testing.T) {
	var route RouteOnlySetup
	value := reflect.ValueOf(&route).Elem()
	for i := 0; i < value.NumField(); i++ {
		field, name := value.Field(i), value.Type().Field(i).Name
		switch field.Kind() {
		case reflect.String:
			field.SetString("value-" + strconv.Itoa(i))
		case reflect.Bool:
			field.SetBool(true)
		case reflect.Pointer:
			field.Set(reflect.New(field.Type().Elem()))
		case reflect.Func:
			fn := field.Type()
			field.Set(reflect.MakeFunc(fn, func([]reflect.Value) []reflect.Value {
				out := make([]reflect.Value, fn.NumOut())
				for j := range out {
					out[j] = reflect.Zero(fn.Out(j))
				}
				return out
			}))
		default:
			t.Fatalf("RouteOnlySetup.%s is a %s: give it a value here", name, field.Kind())
		}
	}
	raw, err := json.Marshal(route)
	if err != nil {
		t.Fatalf("a fully populated RouteOnlySetup does not encode: %v", err)
	}
	var back RouteOnlySetup
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Gate != nil || back.ParkOnly || back.HeldElsewhere != nil {
		t.Fatalf("an in-process gate field crossed the encoding: %s", raw)
	}
	want := route
	want.Gate, want.ParkOnly, want.HeldElsewhere = nil, false, nil
	if !reflect.DeepEqual(back, want) {
		t.Fatalf("decoded %+v, want the render facts %+v (wire %s)", back, want, raw)
	}
}
