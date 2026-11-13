// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
)

// observedMayBeZero are the fleet.Observed members a check reads that the
// collector rightly leaves zero on a healthy cluster: a zero is a reading
// there, not a missing one.
var observedMayBeZero = map[string]string{
	"OtherIssuers":    "one cluster in the config: no other issuers",
	"OpenAPPA":        "the install file does not turn OpenAPPA on",
	"BodyOptIn":       "nil is the reading 'the body opt-in setting does not exist'",
	"KeysErr":         "the keys URL answered",
	"KeysNote":        "the keys URL was read",
	"PoliciesNote":    "the access policies were read",
	"ActorRoutesNote": "the actor listener's routes were read",
}

// TestEveryCheckedObservedMemberHasAProducer is the class test of GAP-0200
// and GAP-0209: a verify check may report only what the collector read. A
// member of fleet.Observed that changes the outcome of a check must be set
// by collectFleet on a cluster that has everything, or be listed in
// observedMayBeZero with the reason a zero is a reading.
func TestEveryCheckedObservedMemberHasAProducer(t *testing.T) {
	fakeKubectl(t, nil)
	f := &substrateClusterFlags{installFile: writeInstall(t, fleetInstallOK), namespace: "defenseclaw-system",
		substrateNS: "ate-system", timeout: 10 * time.Second}
	collected, _, err := collectFleet(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	// A reference where every member is set: what was collected, and a
	// sample value for each member the collector left zero.
	full := collected
	fv := reflect.ValueOf(&full).Elem()
	cv := reflect.ValueOf(collected)
	for i := range fv.NumField() {
		if fv.Field(i).IsZero() {
			fv.Field(i).Set(sampleValue(fv.Field(i).Type()))
		}
	}
	want := fleet.RunChecks(full)
	typ := fv.Type()
	for i := range fv.NumField() {
		name := typ.Field(i).Name
		probe := full
		pv := reflect.ValueOf(&probe).Elem()
		pv.Field(i).Set(reflect.Zero(pv.Field(i).Type()))
		if reflect.DeepEqual(fleet.RunChecks(probe), want) {
			continue // no check reads it
		}
		if cv.Field(i).IsZero() {
			if why, ok := observedMayBeZero[name]; ok {
				t.Logf("%s: zero is a reading (%s)", name, why)
				continue
			}
			t.Errorf("fleet.Observed.%s feeds a verify check, but collectFleet never set it: the check reports a "+
				"state nobody measured. Read it from the cluster, or remove the check", name)
		}
	}
}

// sampleValue is a non-zero value of type t.
func sampleValue(t reflect.Type) reflect.Value {
	v := reflect.New(t).Elem()
	switch t.Kind() {
	case reflect.String:
		v.SetString("sample")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(7)
	case reflect.Pointer:
		v.Set(reflect.New(t.Elem()))
	case reflect.Slice:
		v.Set(reflect.MakeSlice(t, 1, 1))
		v.Index(0).Set(sampleValue(t.Elem()))
	case reflect.Map:
		v.Set(reflect.MakeMap(t))
		v.SetMapIndex(sampleValue(t.Key()), sampleValue(t.Elem()))
	}
	return v
}

// statusMayBeZero are the status document members (dotted paths, "[]" for
// every element of a list) that the collector rightly leaves zero on a
// healthy cluster: a zero is a reading there, not a missing one.
var statusMayBeZero = map[string]string{
	"Cluster.IssuerDefault": "the cluster has its own issuer, so it is not the default one",
}

// TestEveryPrintedStatusMemberHasAProducer is the class test of GAP-0216: a
// status line shows a reading or is not printed. Every member of the status
// document `status --cluster` prints must be set by collectFleet on a
// cluster that has everything, or be listed in statusMayBeZero with the
// reason a zero is a reading. A member of a list counts as set when one
// element sets it.
func TestEveryPrintedStatusMemberHasAProducer(t *testing.T) {
	fakeKubectl(t, nil)
	oldVersion := appVersion
	appVersion = "1.0.10" // a release build sets it
	t.Cleanup(func() { appVersion = oldVersion })
	f := &substrateClusterFlags{installFile: writeInstall(t, fleetInstallOK), namespace: "defenseclaw-system",
		substrateNS: "ate-system", timeout: 10 * time.Second, managedAtespaces: []string{"data-team"}}
	o, r, err := collectFleet(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range zeroMembers(reflect.ValueOf(fleet.BuildStatus(o, r)), "") {
		if why, ok := statusMayBeZero[path]; ok {
			t.Logf("%s: zero is a reading (%s)", path, why)
			continue
		}
		t.Errorf("status prints %s, but collectFleet never set it: the line shows a state nobody measured. "+
			"Read it from the cluster, or stop printing it", path)
	}
}

// zeroMembers lists the leaf members of v that are zero: a zero scalar, a
// nil pointer, an empty list or map. Structs and list elements are walked;
// a list member is zero only when it is zero in every element.
func zeroMembers(v reflect.Value, path string) []string {
	join := func(name string) string {
		if path == "" {
			return name
		}
		return path + "." + name
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return []string{path}
		}
		return zeroMembers(v.Elem(), path)
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			if v.IsZero() {
				return []string{path}
			}
			return nil
		}
		var out []string
		for i := range v.NumField() {
			out = append(out, zeroMembers(v.Field(i), join(v.Type().Field(i).Name))...)
		}
		return out
	case reflect.Map:
		if v.Len() == 0 {
			return []string{path}
		}
		return nil
	case reflect.Slice:
		if v.Len() == 0 {
			return []string{path}
		}
		if v.Type().Elem().Kind() != reflect.Struct {
			return nil
		}
		count := map[string]int{}
		for i := range v.Len() {
			for _, p := range zeroMembers(v.Index(i), path+"[]") {
				count[p]++
			}
		}
		var out []string
		for p, n := range count {
			if n == v.Len() {
				out = append(out, p)
			}
		}
		slices.Sort(out)
		return out
	}
	if v.IsZero() {
		return []string{path}
	}
	return nil
}
