// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"context"
	"reflect"
	"testing"
)

// gap1110IsWaitState reports the state type of a wait for walk slots, by
// name, so the test reads the same at a head where the state was a struct
// that held the call's context.
func gap1110IsWaitState(typ reflect.Type) bool {
	return typ.PkgPath() == reflect.TypeFor[Facts]().PkgPath() && typ.Name() == "credentialWalkWait"
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
