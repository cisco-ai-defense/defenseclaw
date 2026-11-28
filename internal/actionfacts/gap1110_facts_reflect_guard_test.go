// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

// gap1110IsWaitState reports the state type of a wait for walk slots, by
// name, so the test reads the same at a head where the state was a struct
// that held the call's context.
func gap1110IsWaitState(typ reflect.Type) bool {
	return typ.PkgPath() == reflect.TypeFor[Facts]().PkgPath() && typ.Name() == "credentialWalkWait"
}

// gap1110SyncKind names the kind of a type that must not be reachable from
// Facts or Input by reflection, by type: a sync primitive (Mutex, RWMutex,
// Once, WaitGroup, Cond, Map, Pool, and the rest of package sync), an atomic
// value (sync/atomic), or a channel other than the walk budget's (substrate-1:
// GAP-1115). A reflection walk over Facts that meets one reads it (DeepEqual
// compares a lock's state, a Once's counter) while another goroutine may hold
// it, the race GAP-1110 had with a context. "" when typ is none of them.
func gap1110SyncKind(typ reflect.Type) string {
	switch typ.PkgPath() {
	case "sync":
		return "a sync primitive"
	case "sync/atomic":
		return "an atomic value"
	}
	if typ.Kind() == reflect.Chan && typ != reflect.TypeFor[CredentialWalkBudget]() {
		return "a channel that is not the walk budget"
	}
	return ""
}

// gap1110SyncAllowed lists the two sync primitives that are reachable from
// Facts on purpose: credentialPathResult.once and .mu. Both are touched only
// by the request's own goroutine (RV-0674U section C): the resolve, the thin
// (ThinCredentialPathReads) and every reflection walk over Facts run on it,
// and no Facts value crosses goroutines (toolChainHookCapture is per request);
// the artifact file read, the one other goroutine on the path, carries no
// Facts. So they stay as they are, and the guard allows them by name, not by
// type: a new primitive, or a use of one of these in a new place, turns the
// test red (substrate-1:GAP-1115, test-only, as the finding allowed).
func gap1110SyncAllowed(owner reflect.Type, field string) bool {
	return owner == reflect.TypeFor[credentialPathResult]() && (field == "once" || field == "mu")
}

// gap1110LiveReach is the path to the first value reachable from value, by
// the descent of a reflection walk over Facts (mentionsString, the dispatch
// memos' reflect.DeepEqual), that is a context or the state of a wait for
// walk slots; "" when there is none. Like those walks it goes through
// pointers, interfaces, structs, slices, arrays and maps, and never into a
// channel or a func.
func gap1110LiveReach(value reflect.Value, path string, seen map[uintptr]bool, depth int) string {
	if depth > 64 || !value.IsValid() {
		return ""
	}
	contextType := reflect.TypeFor[context.Context]()
	typ := value.Type()
	if typ.Kind() != reflect.Interface && (typ.Implements(contextType) || reflect.PointerTo(typ).Implements(contextType)) {
		return path + " (" + typ.String() + ", a context)"
	}
	if gap1110IsWaitState(typ) {
		return path + " (the wait's state)"
	}
	if kind := gap1110SyncKind(typ); kind != "" {
		return path + " (" + typ.String() + ", " + kind + ")"
	}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() || seen[value.Pointer()] {
			return ""
		}
		seen[value.Pointer()] = true
		return gap1110LiveReach(value.Elem(), path, seen, depth+1)
	case reflect.Interface:
		if value.IsNil() {
			return ""
		}
		return gap1110LiveReach(value.Elem(), path, seen, depth+1)
	case reflect.Struct:
		for index := range value.NumField() {
			if gap1110SyncAllowed(typ, typ.Field(index).Name) {
				continue
			}
			if found := gap1110LiveReach(value.Field(index), path+"."+typ.Field(index).Name, seen, depth+1); found != "" {
				return found
			}
		}
	case reflect.Slice, reflect.Array:
		for index := range value.Len() {
			if found := gap1110LiveReach(value.Index(index), path+"[]", seen, depth+1); found != "" {
				return found
			}
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if found := gap1110LiveReach(iterator.Key(), path+"{k}", seen, depth+1); found != "" {
				return found
			}
			if found := gap1110LiveReach(iterator.Value(), path+"{v}", seen, depth+1); found != "" {
				return found
			}
		}
	}
	return ""
}

// gap1110LiveType is gap1110LiveReach over the types Facts and Input are
// made of, so a field that is empty in the values below is still covered.
func gap1110LiveType(typ reflect.Type, path string, seen map[reflect.Type]bool) string {
	if seen[typ] {
		return ""
	}
	seen[typ] = true
	contextType := reflect.TypeFor[context.Context]()
	if typ == contextType || (typ.Kind() != reflect.Interface && (typ.Implements(contextType) || reflect.PointerTo(typ).Implements(contextType))) {
		return path + " (" + typ.String() + ", a context)"
	}
	if gap1110IsWaitState(typ) {
		return path + " (the wait's state)"
	}
	if kind := gap1110SyncKind(typ); kind != "" {
		return path + " (" + typ.String() + ", " + kind + ")"
	}
	switch typ.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return gap1110LiveType(typ.Elem(), path+"[]", seen)
	case reflect.Map:
		if found := gap1110LiveType(typ.Key(), path+"{k}", seen); found != "" {
			return found
		}
		return gap1110LiveType(typ.Elem(), path+"{v}", seen)
	case reflect.Struct:
		for index := range typ.NumField() {
			if gap1110SyncAllowed(typ, typ.Field(index).Name) {
				continue
			}
			if found := gap1110LiveType(typ.Field(index).Type, path+"."+typ.Field(index).Name, seen); found != "" {
				return found
			}
		}
	}
	return ""
}

// gap1110CallKey keys a value on the call's context, so the context the
// test makes is a chain of contexts, as the hook's is.
type gap1110CallKey struct{}

// TestGAP1110NoContextReachableFromFactsByReflection: Facts and Input carry
// the call's wait for walk slots, and mentionsString and the dispatch memos
// walk them by reflection while the rule evaluator cancels contexts derived
// from the call's. No context and no state of the wait may be reachable that
// way: a budget that held the call's context made the walk iterate the
// context's children while a child was cancelled, a fatal concurrent map
// read (substrate-1:GAP-1110, from GAP-1083's one wait per call).
func TestGAP1110NoContextReachableFromFactsByReflection(t *testing.T) {
	root, home := gap1083Tree(t)
	call, cancel := context.WithCancel(context.WithValue(context.Background(), gap1110CallKey{}, "call"))
	defer cancel()
	// A child, as the evaluator's, so a context reached here has children.
	_, cancelChild := context.WithCancel(call)
	defer cancelChild()
	input := Input{Tool: "exec", Command: "grep -r KEY tree", CWD: root, ActiveHome: home, CredentialWalkBudget: NewCredentialWalkBudget(call)}
	if input.CredentialWalkBudget == nil {
		t.Fatal("no budget was made")
	}
	if found := gap1110LiveReach(reflect.ValueOf(input), "Input", map[uintptr]bool{}, 0); found != "" {
		t.Errorf("reflection over Input reaches %s", found)
	}
	facts := Analyze(input)
	if facts.credentialPaths == nil || facts.credentialPaths.budget == nil {
		t.Fatal("the parse has no private record on the call's budget; the test reads nothing")
	}
	if found := gap1110LiveReach(reflect.ValueOf(facts), "Facts", map[uintptr]bool{}, 0); found != "" {
		t.Errorf("reflection over unresolved Facts reaches %s", found)
	}
	_ = facts.CredentialPathReadCaps(call)
	if found := gap1110LiveReach(reflect.ValueOf(facts), "Facts", map[uintptr]bool{}, 0); found != "" {
		t.Errorf("reflection over resolved Facts reaches %s", found)
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[Facts](), reflect.TypeFor[Input]()} {
		if found := gap1110LiveType(typ, typ.Name(), map[reflect.Type]bool{}); found != "" {
			t.Errorf("the type %s holds %s", typ.Name(), found)
		}
	}
}

// TestGAP1115AllowedSyncFieldsAreTheOnesTheGuardNames keeps the allow-list
// honest: both fields exist and are the primitives the comment says, so a
// removal or a change of type of either shows here, not as a silent hole.
func TestGAP1115AllowedSyncFieldsAreTheOnesTheGuardNames(t *testing.T) {
	owner := reflect.TypeFor[credentialPathResult]()
	for name, want := range map[string]reflect.Type{"once": reflect.TypeFor[sync.Once](), "mu": reflect.TypeFor[sync.Mutex]()} {
		field, ok := owner.FieldByName(name)
		if !ok || field.Type != want {
			t.Errorf("credentialPathResult.%s is %v (found %v), want %v: update gap1110SyncAllowed", name, field.Type, ok, want)
		}
		if !gap1110SyncAllowed(owner, name) {
			t.Errorf("%s is not allowed by gap1110SyncAllowed", name)
		}
	}
	if gap1110SyncAllowed(owner, "budget") || gap1110SyncAllowed(reflect.TypeFor[Facts](), "once") {
		t.Error("the allow-list is wider than the two fields of credentialPathResult")
	}
}

// TestGAP1115GuardNamesEverySyncKind: the predicate the guard uses names each
// primitive GAP-1115 lists, an atomic value and a channel other than the walk
// budget, and not the walk budget.
func TestGAP1115GuardNamesEverySyncKind(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeFor[sync.Mutex](), reflect.TypeFor[sync.RWMutex](), reflect.TypeFor[sync.Once](),
		reflect.TypeFor[sync.WaitGroup](), reflect.TypeFor[sync.Cond](), reflect.TypeFor[sync.Map](),
		reflect.TypeFor[atomic.Int64](), reflect.TypeFor[atomic.Bool](), reflect.TypeFor[atomic.Pointer[int]](), reflect.TypeFor[atomic.Value](),
		reflect.TypeFor[chan struct{}](), reflect.TypeFor[<-chan struct{}](), reflect.TypeFor[chan credentialWalkWait](),
	} {
		if gap1110SyncKind(typ) == "" {
			t.Errorf("%v is not named as a sync primitive", typ)
		}
	}
	if kind := gap1110SyncKind(reflect.TypeFor[CredentialWalkBudget]()); kind != "" {
		t.Errorf("the walk budget channel is named as %s", kind)
	}
	// And the type walk finds one inside a struct, a slice, a map and a
	// pointer, as the walk over Facts would.
	type holder struct {
		list []struct{ lock sync.RWMutex }
		byID map[string]*struct{ n atomic.Int64 }
		c    chan int
	}
	if found := gap1110LiveType(reflect.TypeFor[holder](), "holder", map[reflect.Type]bool{}); found == "" {
		t.Error("the type walk found no sync primitive in a struct that holds three")
	}
	value := holder{byID: map[string]*struct{ n atomic.Int64 }{"k": {}}}
	_, _, _ = value.list, value.byID, value.c // read, so the linter sees the fields used
	if found := gap1110LiveReach(reflect.ValueOf(value), "holder", map[uintptr]bool{}, 0); found == "" {
		t.Error("the value walk found no sync primitive in a struct that holds one")
	}
}
