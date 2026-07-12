// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const generatedTelemetryOverlayRootEnvironment = "DEFENSECLAW_GENERATED_TELEMETRY_ROOT"

var familyBuilderForbiddenReachableTypes = map[string]struct{}{
	"Bucket":        {},
	"EventIdentity": {},
	"EventName":     {},
	"FamilyBuilder": {},
	"FieldClass":    {},
	"Record":        {},
	"RecordBuilder": {},
	"RecordInput":   {},
	"Signal":        {},
	"Value":         {},
}

var familyBuilderCatalogAuthorityFields = map[string]struct{}{
	"Bucket":                {},
	"EventName":             {},
	"Family":                {},
	"FamilyID":              {},
	"FamilySchemaVersion":   {},
	"FieldClasses":          {},
	"FloorOnly":             {},
	"Identity":              {},
	"Instrument":            {},
	"InstrumentName":        {},
	"InstrumentType":        {},
	"Mandatory":             {},
	"RegistrySchemaVersion": {},
	"Signal":                {},
	"SpanName":              {},
	"Temporality":           {},
	"Unit":                  {},
}

var familyBuilderClosedPrivateFieldTypes = map[string]struct{}{
	"TraceEventInput":    {},
	"TraceLinkInput":     {},
	"TraceResourceInput": {},
	"TraceScopeInput":    {},
	"TraceStatusInput":   {},
}

var familyBuilderAllowedExternalTypes = map[string]struct{}{
	"time.Time": {},
}

type familyBuilderMethodStaticContract struct {
	Name             string   `json:"name"`
	ReceiverType     string   `json:"receiver_type"`
	ReceiverPointer  bool     `json:"receiver_pointer"`
	InputType        string   `json:"input_type"`
	InputNamedStruct bool     `json:"input_named_struct"`
	ResultTypes      []string `json:"result_types"`
	Variadic         bool     `json:"variadic"`
}

type parsedPackageSource struct {
	path string
	set  *token.FileSet
	file *ast.File
}

type familyBuilderSourceTypeSpec struct {
	spec    *ast.TypeSpec
	imports map[string]string
}

func TestFamilyBuilderPublicInputsDoNotExposeCatalogAuthority(t *testing.T) {
	for name, typ := range map[string]reflect.Type{
		"FamilyEnvelopeInput":   reflect.TypeOf(FamilyEnvelopeInput{}),
		"FamilyProvenanceInput": reflect.TypeOf(FamilyProvenanceInput{}),
		"TraceResourceInput":    reflect.TypeOf(TraceResourceInput{}),
		"TraceScopeInput":       reflect.TypeOf(TraceScopeInput{}),
		"TraceEventInput":       reflect.TypeOf(TraceEventInput{}),
		"TraceLinkInput":        reflect.TypeOf(TraceLinkInput{}),
		"TraceStatusInput":      reflect.TypeOf(TraceStatusInput{}),
	} {
		t.Run(name, func(t *testing.T) {
			for index := 0; index < typ.NumField(); index++ {
				field := typ.Field(index)
				if field.PkgPath != "" { // Package-private generated bindings are trusted.
					continue
				}
				switch field.Name {
				case "Bucket", "Signal", "Identity", "EventName", "Family", "FamilyID",
					"FamilySchemaVersion", "RegistrySchemaVersion", "SpanName",
					"Instrument", "InstrumentName", "InstrumentType", "Unit", "Temporality",
					"FieldClasses", "Mandatory", "FloorOnly":
					t.Fatalf("%s exposes catalog-owned field %s", name, field.Name)
				}
				if field.Type == reflect.TypeOf(EventIdentity{}) || field.Type == reflect.TypeOf(FieldClass("")) {
					t.Fatalf("%s exposes catalog-owned type through %s", name, field.Name)
				}
				if field.Type.Kind() == reflect.Map {
					t.Fatalf("%s exposes free-form map through %s", name, field.Name)
				}
			}
		})
	}
}

func TestGeneratedTelemetryFamilyBuilderPublicAPIMatchesGeneratedCatalog(t *testing.T) {
	sources := observabilityPackageSources(t)
	contracts, err := generatedFamilyBuilderContracts(sources)
	if err != nil {
		t.Fatal(err)
	}
	assertFamilyBuilderStaticSourceAPIWithSources(t, contracts, sources)
	if err := validateFamilyBuilderReflectedAPI(contracts); err != nil {
		t.Fatalf("FamilyBuilder compiled API: %v", err)
	}
}

func TestGeneratedTelemetryFilesHaveNoInitOrCurrentRegistryMutation(t *testing.T) {
	if err := validateGeneratedTelemetrySourceSafety(observabilityPackageSources(t)); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedTelemetryExplicitOverlayCandidate(t *testing.T) {
	generatedRoot := os.Getenv(generatedTelemetryOverlayRootEnvironment)
	if generatedRoot == "" {
		t.Skip("no explicit generated telemetry overlay")
	}
	sources := observabilityPackageSourcesWithGeneratedOverlay(t, generatedRoot)
	contracts, err := generatedFamilyBuilderContracts(sources)
	if err != nil {
		t.Fatal(err)
	}
	assertFamilyBuilderStaticSourceAPIWithSources(t, contracts, sources)
	if err := validateFamilyBuilderReflectedAPI(contracts); err != nil {
		t.Fatalf("FamilyBuilder compiled API: %v", err)
	}
	if err := validateGeneratedTelemetrySourceSafety(sources); err != nil {
		t.Fatal(err)
	}
}

func assertFamilyBuilderStaticSourceAPIWithSources(
	t *testing.T,
	contracts []familyBuilderMethodStaticContract,
	sources []parsedPackageSource,
) {
	t.Helper()
	if err := validateFamilyBuilderSourceAPI(sources, contracts); err != nil {
		t.Fatalf("FamilyBuilder source API: %v", err)
	}
}

func validateFamilyBuilderReflectedAPI(contracts []familyBuilderMethodStaticContract) error {
	want := make(map[string]familyBuilderMethodStaticContract, len(contracts))
	for _, contract := range contracts {
		want[contract.Name] = contract
	}
	builderPointer := reflect.TypeOf(&FamilyBuilder{})
	packagePath := builderPointer.Elem().PkgPath()
	recordType := reflect.TypeOf(Record{})
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	seen := make(map[string]struct{}, builderPointer.NumMethod())
	validatedInputs := make(map[reflect.Type]struct{}, len(contracts))
	for index := 0; index < builderPointer.NumMethod(); index++ {
		method := builderPointer.Method(index)
		contract, exists := want[method.Name]
		if !exists {
			return fmt.Errorf("unexpected exported method %s", method.Name)
		}
		if method.Type.IsVariadic() || method.Type.NumIn() != 2 || method.Type.In(0) != builderPointer ||
			method.Type.In(1).Kind() != reflect.Struct || method.Type.In(1).Name() != contract.InputType ||
			method.Type.NumOut() != 2 || method.Type.Out(0) != recordType || method.Type.Out(1) != errorType {
			return fmt.Errorf("method %s has the wrong compiled signature", method.Name)
		}
		inputType := method.Type.In(1)
		if _, validated := validatedInputs[inputType]; !validated {
			if err := validateFamilyBuilderReflectedInputType(inputType, packagePath, make(map[reflect.Type]bool)); err != nil {
				return fmt.Errorf("method %s input graph: %w", method.Name, err)
			}
			validatedInputs[inputType] = struct{}{}
		}
		seen[method.Name] = struct{}{}
	}
	for name := range want {
		if _, exists := seen[name]; !exists {
			return fmt.Errorf("allowlisted method %s is missing", name)
		}
	}
	return nil
}

func validateFamilyBuilderReflectedInputType(
	typ reflect.Type,
	packagePath string,
	visiting map[reflect.Type]bool,
) error {
	switch typ.Kind() {
	case reflect.Map:
		return fmt.Errorf("type %s exposes a map", typ)
	case reflect.Func:
		return fmt.Errorf("type %s exposes a function", typ)
	case reflect.Chan:
		return fmt.Errorf("type %s exposes a channel", typ)
	case reflect.UnsafePointer:
		return fmt.Errorf("type %s exposes an unsafe pointer", typ)
	}
	if typ.Name() != "" && typ.PkgPath() != "" && typ.PkgPath() != packagePath {
		if !token.IsExported(typ.Name()) {
			return fmt.Errorf("type %s is not exported", typ)
		}
		externalType := typ.PkgPath() + "." + typ.Name()
		if _, allowed := familyBuilderAllowedExternalTypes[externalType]; !allowed {
			return fmt.Errorf("type %s is not an allowlisted external type", typ)
		}
		return nil
	}
	if typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		if typ.Name() != "" && typ.PkgPath() == packagePath {
			if _, forbidden := familyBuilderForbiddenReachableTypes[typ.Name()]; forbidden {
				return fmt.Errorf("type %s exposes forbidden observability authority", typ)
			}
			if !token.IsExported(typ.Name()) {
				return fmt.Errorf("type %s is not exported", typ)
			}
		}
		return validateFamilyBuilderReflectedInputType(typ.Elem(), packagePath, visiting)
	}
	if typ.PkgPath() == "" {
		switch typ.Kind() {
		case reflect.Bool,
			reflect.Complex64, reflect.Complex128,
			reflect.Float32, reflect.Float64,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.String,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			return nil
		}
	}
	if typ.Name() == "" {
		if typ.Kind() == reflect.Interface {
			return fmt.Errorf("type %s exposes an open interface", typ)
		}
		if typ.Kind() == reflect.Struct {
			return fmt.Errorf("type %s exposes an anonymous struct", typ)
		}
		return nil
	}
	name := typ.Name()
	if _, forbidden := familyBuilderForbiddenReachableTypes[name]; forbidden {
		return fmt.Errorf("type %s exposes forbidden observability authority", typ)
	}
	if !token.IsExported(strings.SplitN(name, "[", 2)[0]) {
		return fmt.Errorf("type %s is not exported", typ)
	}
	if visiting[typ] {
		return nil
	}
	visiting[typ] = true
	defer delete(visiting, typ)
	if strings.HasPrefix(name, "Optional[") {
		if typ.Kind() != reflect.Struct || typ.NumField() != 2 || typ.Field(0).Name != "value" ||
			typ.Field(1).Name != "present" || typ.Field(1).Type.Kind() != reflect.Bool {
			return fmt.Errorf("type %s is not the closed Optional representation", typ)
		}
		return validateFamilyBuilderReflectedInputType(typ.Field(0).Type, packagePath, visiting)
	}
	if typ.Kind() == reflect.Interface {
		return validateFamilyBuilderReflectedSealedInterface(typ)
	}
	if typ.Kind() != reflect.Struct {
		return nil
	}
	_, closedPrivateFields := familyBuilderClosedPrivateFieldTypes[name]
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if field.PkgPath != "" {
			if closedPrivateFields {
				continue
			}
			return fmt.Errorf("type %s exposes unexported field %s", typ, field.Name)
		}
		if _, catalogOwned := familyBuilderCatalogAuthorityFields[field.Name]; catalogOwned {
			return fmt.Errorf("type %s exposes catalog-authority field %s", typ, field.Name)
		}
		if err := validateFamilyBuilderReflectedInputType(field.Type, packagePath, visiting); err != nil {
			return fmt.Errorf("field %s: %w", field.Name, err)
		}
	}
	return nil
}

func validateFamilyBuilderReflectedSealedInterface(typ reflect.Type) error {
	if typ.NumMethod() == 0 {
		return fmt.Errorf("type %s exposes an empty interface", typ)
	}
	for index := 0; index < typ.NumMethod(); index++ {
		method := typ.Method(index)
		if method.PkgPath == "" || method.Type.NumIn() != 0 || method.Type.NumOut() != 0 || method.Type.IsVariadic() {
			return fmt.Errorf("type %s exposes a non-sealing interface method", typ)
		}
	}
	return nil
}

func validateFamilyBuilderSourceAPI(
	sources []parsedPackageSource,
	contracts []familyBuilderMethodStaticContract,
) error {
	typeSpecs := make(map[string]familyBuilderSourceTypeSpec)
	for _, source := range sources {
		imports, err := familyBuilderSourceImports(source.file)
		if err != nil {
			return err
		}
		for _, declaration := range source.file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, raw := range general.Specs {
				spec, ok := raw.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if _, duplicate := typeSpecs[spec.Name.Name]; duplicate {
					return fmt.Errorf("type %s is declared more than once", spec.Name.Name)
				}
				typeSpecs[spec.Name.Name] = familyBuilderSourceTypeSpec{spec: spec, imports: imports}
			}
		}
	}
	want := make(map[string]familyBuilderMethodStaticContract, len(contracts))
	for _, contract := range contracts {
		want[contract.Name] = contract
		typeSpec, exists := typeSpecs[contract.InputType]
		if !exists {
			return fmt.Errorf("allowlisted input %s has no package-local type", contract.InputType)
		}
		if _, isStruct := typeSpec.spec.Type.(*ast.StructType); !isStruct {
			return fmt.Errorf("allowlisted input %s is not a named struct", contract.InputType)
		}
		if err := validateFamilyBuilderSourceNamedType(
			contract.InputType,
			typeSpecs,
			make(map[string]bool),
		); err != nil {
			return fmt.Errorf("allowlisted input %s graph: %w", contract.InputType, err)
		}
	}
	seen := make(map[string]struct{}, len(contracts))
	for _, source := range sources {
		for _, declaration := range source.file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || !token.IsExported(function.Name.Name) {
				continue
			}
			receiverName, receiverPointer := familyBuilderReceiver(function.Recv)
			if receiverName != "FamilyBuilder" {
				continue
			}
			contract, exists := want[function.Name.Name]
			if !exists {
				return fmt.Errorf("unexpected exported method %s", function.Name.Name)
			}
			if _, duplicate := seen[function.Name.Name]; duplicate {
				return fmt.Errorf("method %s is declared more than once", function.Name.Name)
			}
			seen[function.Name.Name] = struct{}{}
			if function.Type.TypeParams != nil && len(function.Type.TypeParams.List) != 0 {
				return fmt.Errorf("method %s is generic", function.Name.Name)
			}
			if receiverPointer != contract.ReceiverPointer || function.Type.Params == nil ||
				len(function.Type.Params.List) != 1 || len(function.Type.Params.List[0].Names) != 1 {
				return fmt.Errorf("method %s has the wrong receiver or parameter count", function.Name.Name)
			}
			if _, variadic := function.Type.Params.List[0].Type.(*ast.Ellipsis); variadic {
				return fmt.Errorf("method %s is variadic", function.Name.Name)
			}
			input, ok := function.Type.Params.List[0].Type.(*ast.Ident)
			if !ok || input.Name != contract.InputType {
				return fmt.Errorf("method %s input is not the allowlisted named type", function.Name.Name)
			}
			if function.Type.Results == nil || len(function.Type.Results.List) != 2 ||
				identifierName(function.Type.Results.List[0].Type) != "Record" ||
				identifierName(function.Type.Results.List[1].Type) != "error" {
				return fmt.Errorf("method %s results are not (Record, error)", function.Name.Name)
			}
		}
	}
	for name := range want {
		if _, exists := seen[name]; !exists {
			return fmt.Errorf("allowlisted method %s is missing", name)
		}
	}
	return nil
}

func familyBuilderSourceImports(file *ast.File) (map[string]string, error) {
	imports := make(map[string]string, len(file.Imports))
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || importPath == "" {
			return nil, fmt.Errorf("source contains an invalid import path")
		}
		alias := ""
		if spec.Name != nil {
			alias = spec.Name.Name
			if alias == "_" || alias == "." {
				continue
			}
		} else {
			parts := strings.Split(importPath, "/")
			alias = parts[len(parts)-1]
		}
		if prior, duplicate := imports[alias]; duplicate && prior != importPath {
			return nil, fmt.Errorf("source reuses import alias %s", alias)
		}
		imports[alias] = importPath
	}
	return imports, nil
}

func validateFamilyBuilderSourceNamedType(
	name string,
	typeSpecs map[string]familyBuilderSourceTypeSpec,
	visiting map[string]bool,
) error {
	if _, forbidden := familyBuilderForbiddenReachableTypes[name]; forbidden {
		return fmt.Errorf("type %s exposes forbidden observability authority", name)
	}
	if !token.IsExported(name) {
		return fmt.Errorf("type %s is not exported", name)
	}
	if visiting[name] {
		return nil
	}
	typeSpec, exists := typeSpecs[name]
	if !exists {
		return fmt.Errorf("type %s is not declared in the package", name)
	}
	visiting[name] = true
	defer delete(visiting, name)
	if interfaceType, ok := typeSpec.spec.Type.(*ast.InterfaceType); ok {
		return validateFamilyBuilderSourceSealedInterface(name, interfaceType)
	}
	return validateFamilyBuilderSourceType(typeSpec.spec.Type, name, typeSpecs, typeSpec.imports, visiting)
}

func validateFamilyBuilderSourceType(
	expression ast.Expr,
	owner string,
	typeSpecs map[string]familyBuilderSourceTypeSpec,
	imports map[string]string,
	visiting map[string]bool,
) error {
	switch typ := expression.(type) {
	case *ast.Ident:
		switch typ.Name {
		case "any", "error":
			return fmt.Errorf("type %s exposes an interface", typ.Name)
		case "bool", "byte", "complex128", "complex64", "float32", "float64", "int", "int16", "int32",
			"int64", "int8", "rune", "string", "uint", "uint16", "uint32", "uint64", "uint8", "uintptr":
			return nil
		default:
			return validateFamilyBuilderSourceNamedType(typ.Name, typeSpecs, visiting)
		}
	case *ast.SelectorExpr:
		qualifier, ok := typ.X.(*ast.Ident)
		if !ok || !token.IsExported(typ.Sel.Name) {
			return fmt.Errorf("type selector is not an exported external type")
		}
		importPath, exists := imports[qualifier.Name]
		if !exists {
			return fmt.Errorf("type selector %s.%s has no exact import", qualifier.Name, typ.Sel.Name)
		}
		externalType := importPath + "." + typ.Sel.Name
		if _, allowed := familyBuilderAllowedExternalTypes[externalType]; !allowed {
			return fmt.Errorf("type %s is not an allowlisted external type", externalType)
		}
		return nil
	case *ast.StarExpr:
		return validateFamilyBuilderSourceType(typ.X, owner, typeSpecs, imports, visiting)
	case *ast.ArrayType:
		return validateFamilyBuilderSourceType(typ.Elt, owner, typeSpecs, imports, visiting)
	case *ast.MapType:
		return fmt.Errorf("type %s exposes a map", owner)
	case *ast.FuncType:
		return fmt.Errorf("type %s exposes a function", owner)
	case *ast.ChanType:
		return fmt.Errorf("type %s exposes a channel", owner)
	case *ast.InterfaceType:
		return fmt.Errorf("type %s exposes an anonymous interface", owner)
	case *ast.StructType:
		_, closedPrivateFields := familyBuilderClosedPrivateFieldTypes[owner]
		for _, field := range typ.Fields.List {
			if len(field.Names) == 0 {
				return fmt.Errorf("type %s exposes an embedded field", owner)
			}
			privateField := false
			for _, name := range field.Names {
				if !token.IsExported(name.Name) {
					if closedPrivateFields {
						privateField = true
						continue
					}
					return fmt.Errorf("type %s exposes unexported field %s", owner, name.Name)
				}
				if _, catalogOwned := familyBuilderCatalogAuthorityFields[name.Name]; catalogOwned {
					return fmt.Errorf("type %s exposes catalog-authority field %s", owner, name.Name)
				}
			}
			if privateField {
				if len(field.Names) != 1 {
					return fmt.Errorf("type %s mixes private and public field names", owner)
				}
				continue
			}
			if err := validateFamilyBuilderSourceType(field.Type, owner, typeSpecs, imports, visiting); err != nil {
				return err
			}
		}
		return nil
	case *ast.IndexExpr:
		name, ok := typ.X.(*ast.Ident)
		if !ok || name.Name != "Optional" {
			return fmt.Errorf("type %s exposes an unreviewed generic", owner)
		}
		return validateFamilyBuilderSourceType(typ.Index, owner, typeSpecs, imports, visiting)
	case *ast.IndexListExpr:
		return fmt.Errorf("type %s exposes an unreviewed multi-argument generic", owner)
	case *ast.ParenExpr:
		return validateFamilyBuilderSourceType(typ.X, owner, typeSpecs, imports, visiting)
	default:
		return fmt.Errorf("type %s exposes unsupported type syntax %T", owner, expression)
	}
}

func validateFamilyBuilderSourceSealedInterface(name string, interfaceType *ast.InterfaceType) error {
	if interfaceType.Methods == nil || len(interfaceType.Methods.List) == 0 {
		return fmt.Errorf("type %s exposes an empty interface", name)
	}
	for _, method := range interfaceType.Methods.List {
		if len(method.Names) != 1 || token.IsExported(method.Names[0].Name) {
			return fmt.Errorf("type %s exposes a non-sealing interface element", name)
		}
		signature, ok := method.Type.(*ast.FuncType)
		if !ok || (signature.TypeParams != nil && len(signature.TypeParams.List) != 0) ||
			(signature.Params != nil && len(signature.Params.List) != 0) ||
			(signature.Results != nil && len(signature.Results.List) != 0) {
			return fmt.Errorf("type %s exposes a non-marker interface method", name)
		}
	}
	return nil
}

func familyBuilderReceiver(receivers *ast.FieldList) (string, bool) {
	if receivers == nil || len(receivers.List) != 1 {
		return "", false
	}
	switch receiver := receivers.List[0].Type.(type) {
	case *ast.Ident:
		return receiver.Name, false
	case *ast.StarExpr:
		return identifierName(receiver.X), true
	default:
		return "", false
	}
}

func identifierName(expression ast.Expr) string {
	identifier, ok := expression.(*ast.Ident)
	if !ok {
		return ""
	}
	return identifier.Name
}

func observabilityPackageSources(t *testing.T) []parsedPackageSource {
	t.Helper()
	packageDir := observabilityPackageDir(t)
	paths, err := filepath.Glob(filepath.Join(packageDir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	byBase := make(map[string]string, len(paths))
	for _, path := range paths {
		byBase[filepath.Base(path)] = path
	}
	return parseObservabilityPackageSources(t, byBase)
}

func observabilityPackageSourcesWithGeneratedOverlay(t *testing.T, generatedRoot string) []parsedPackageSource {
	t.Helper()
	packageDir := observabilityPackageDir(t)
	basePaths, err := filepath.Glob(filepath.Join(packageDir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	byBase := make(map[string]string, len(basePaths))
	expectedGenerated := make(map[string]struct{})
	for _, path := range basePaths {
		base := filepath.Base(path)
		byBase[base] = path
		if strings.HasPrefix(base, "zz_generated_telemetry_") && strings.HasSuffix(base, ".go") {
			expectedGenerated[base] = struct{}{}
		}
	}
	generated, err := filepath.Glob(
		filepath.Join(generatedRoot, "internal", "observability", "zz_generated_telemetry_*.go"),
	)
	if err != nil {
		t.Fatal(err)
	}
	observedGenerated := make(map[string]struct{}, len(generated))
	for _, path := range generated {
		base := filepath.Base(path)
		observedGenerated[base] = struct{}{}
		byBase[base] = path
	}
	if !reflect.DeepEqual(observedGenerated, expectedGenerated) {
		t.Fatalf("generated telemetry overlay does not replace the exact checked-in generated set")
	}
	return parseObservabilityPackageSources(t, byBase)
}

func parseObservabilityPackageSources(t *testing.T, byBase map[string]string) []parsedPackageSource {
	t.Helper()
	bases := make([]string, 0, len(byBase))
	for base := range byBase {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	sources := make([]parsedPackageSource, 0, len(bases))
	for _, base := range bases {
		fileSet := token.NewFileSet()
		parsed, parseErr := parser.ParseFile(fileSet, byBase[base], nil, parser.AllErrors)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", byBase[base], parseErr)
		}
		sources = append(sources, parsedPackageSource{byBase[base], fileSet, parsed})
	}
	return sources
}

func generatedFamilyBuilderContracts(sources []parsedPackageSource) ([]familyBuilderMethodStaticContract, error) {
	const descriptorPrefix = "generated"
	const descriptorSuffix = "Descriptor"
	stems := make(map[string]struct{})
	for _, source := range sources {
		if filepath.Base(source.path) != "zz_generated_telemetry_catalog.go" {
			continue
		}
		for _, declaration := range source.file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, raw := range general.Specs {
				spec, ok := raw.(*ast.TypeSpec)
				if !ok {
					continue
				}
				name := spec.Name.Name
				if !strings.HasPrefix(name, descriptorPrefix) || !strings.HasSuffix(name, descriptorSuffix) {
					continue
				}
				stem := strings.TrimSuffix(strings.TrimPrefix(name, descriptorPrefix), descriptorSuffix)
				if !strings.HasPrefix(stem, "Log") && !strings.HasPrefix(stem, "Span") &&
					!strings.HasPrefix(stem, "Metric") {
					continue
				}
				if stem == "" || !token.IsExported(stem) {
					return nil, fmt.Errorf("generated family descriptor %s has an invalid stem", name)
				}
				if _, duplicate := stems[stem]; duplicate {
					return nil, fmt.Errorf("generated family descriptor stem %s is duplicated", stem)
				}
				stems[stem] = struct{}{}
			}
		}
	}
	if len(stems) == 0 {
		return nil, fmt.Errorf("generated telemetry catalog has no family descriptors")
	}
	ordered := make([]string, 0, len(stems))
	for stem := range stems {
		ordered = append(ordered, stem)
	}
	sort.Strings(ordered)
	contracts := make([]familyBuilderMethodStaticContract, 0, len(ordered))
	for _, stem := range ordered {
		contracts = append(contracts, familyBuilderMethodStaticContract{
			Name: "Build" + stem, ReceiverType: "FamilyBuilder", ReceiverPointer: true,
			InputType: stem + "Input", InputNamedStruct: true,
			ResultTypes: []string{"Record", "error"},
		})
	}
	return contracts, nil
}

func validateGeneratedTelemetrySourceSafety(sources []parsedPackageSource) error {
	forbiddenRegistryIdentifiers := map[string]struct{}{
		"buildEventNameRegistry":       {},
		"registeredEventNameSet":       {},
		"registeredEventNameOrder":     {},
		"registeredLogEventNameSet":    {},
		"registeredTraceEventNameSet":  {},
		"registeredMetricEventNameSet": {},
	}
	for _, source := range sources {
		if !strings.HasPrefix(filepath.Base(source.path), "zz_generated_telemetry_") {
			continue
		}
		for _, declaration := range source.file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil && function.Name.Name == "init" {
				return fmt.Errorf("generated file %s declares init", filepath.Base(source.path))
			}
		}
		var violation string
		ast.Inspect(source.file, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			if _, forbidden := forbiddenRegistryIdentifiers[identifier.Name]; forbidden {
				violation = identifier.Name
				return false
			}
			return true
		})
		if violation != "" {
			return fmt.Errorf("generated file %s references current registry %s", filepath.Base(source.path), violation)
		}
	}
	return nil
}

func TestFamilyBuilderStaticGateRejectsAdversarialMethodShapes(t *testing.T) {
	contract := familyBuilderMethodStaticContract{
		Name: "BuildGood", ReceiverType: "FamilyBuilder", ReceiverPointer: true,
		InputType: "GoodInput", InputNamedStruct: true,
		ResultTypes: []string{"Record", "error"},
	}
	prefix := "package observability\ntype FamilyBuilder struct{}\ntype Record struct{}\n"
	goodInput := "type GoodInput struct{}\n"
	method := "func (builder *FamilyBuilder) BuildGood(input GoodInput) (Record, error) { return Record{}, nil }\n"
	valid := prefix + goodInput + method
	if err := validateFamilyBuilderRawSource(valid, []familyBuilderMethodStaticContract{contract}); err != nil {
		t.Fatalf("valid method rejected: %v", err)
	}
	timeInput := "package observability\nimport clock \"time\"\ntype FamilyBuilder struct{}\ntype Record struct{}\ntype GoodInput struct { At clock.Time }\n" + method
	if err := validateFamilyBuilderRawSource(timeInput, []familyBuilderMethodStaticContract{contract}); err != nil {
		t.Fatalf("allowlisted external time.Time rejected: %v", err)
	}
	mutations := map[string]string{
		"missing":          prefix + goodInput,
		"extra":            valid + "func (*FamilyBuilder) BuildExtra(input GoodInput) (Record, error) { return Record{}, nil }\n",
		"generic":          prefix + goodInput + "func (*FamilyBuilder) BuildGood[T any](input GoodInput) (Record, error) { return Record{}, nil }\n",
		"map-any":          prefix + goodInput + "func (*FamilyBuilder) BuildGood(input map[string]any) (Record, error) { return Record{}, nil }\n",
		"named-map-any":    prefix + "type GoodInput struct { Extra map[string]any }\n" + method,
		"nested-raw-value": prefix + "type Value struct{}\ntype Nested struct { Raw Value }\ntype GoodInput struct { Nested Nested }\n" + method,
		"external-raw":     "package observability\nimport wire \"encoding/json\"\ntype FamilyBuilder struct{}\ntype Record struct{}\ntype GoodInput struct { Raw wire.RawMessage }\n" + method,
		"wrong receiver":   prefix + goodInput + "func (FamilyBuilder) BuildGood(input GoodInput) (Record, error) { return Record{}, nil }\n",
		"wrong signature":  prefix + goodInput + "func (*FamilyBuilder) BuildGood(input GoodInput) error { return nil }\n",
	}
	for name, source := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := validateFamilyBuilderRawSource(source, []familyBuilderMethodStaticContract{contract}); err == nil {
				t.Fatal("adversarial method shape passed the static gate")
			}
		})
	}
}

type FamilyBuilderStaticMapInput struct {
	Extra map[string]any
}

type FamilyBuilderStaticRawNested struct {
	Raw Value
}

type FamilyBuilderStaticRawInput struct {
	Nested FamilyBuilderStaticRawNested
}

type FamilyBuilderStaticExternalInput struct {
	Raw json.RawMessage
}

type FamilyBuilderStaticSafeInput struct {
	ObservedAt time.Time
	Values     []string
	Codes      [2]uint32
	Next       *FamilyBuilderStaticSafeInput
}

func TestFamilyBuilderReflectedInputGraphRejectsNestedEscapeHatches(t *testing.T) {
	packagePath := reflect.TypeOf(FamilyBuilder{}).PkgPath()
	if err := validateFamilyBuilderReflectedInputType(
		reflect.TypeOf(FamilyBuilderStaticSafeInput{}),
		packagePath,
		make(map[reflect.Type]bool),
	); err != nil {
		t.Fatalf("safe recursive input rejected: %v", err)
	}
	for name, typ := range map[string]reflect.Type{
		"named-map-any":    reflect.TypeOf(FamilyBuilderStaticMapInput{}),
		"nested-raw-value": reflect.TypeOf(FamilyBuilderStaticRawInput{}),
		"external-raw":     reflect.TypeOf(FamilyBuilderStaticExternalInput{}),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateFamilyBuilderReflectedInputType(
				typ,
				packagePath,
				make(map[reflect.Type]bool),
			); err == nil {
				t.Fatal("unsafe reflected input graph passed the static gate")
			}
		})
	}
}

func TestGeneratedTelemetrySourceSafetyRejectsInitAndRegistryReferences(t *testing.T) {
	for name, source := range map[string]string{
		"init":     "package observability\nfunc init() {}\n",
		"registry": "package observability\nvar _ = registeredEventNameSet\n",
	} {
		t.Run(name, func(t *testing.T) {
			fileSet := token.NewFileSet()
			parsed, err := parser.ParseFile(fileSet, "zz_generated_telemetry_test.go", source, parser.AllErrors)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateGeneratedTelemetrySourceSafety([]parsedPackageSource{{
				path: "zz_generated_telemetry_test.go", set: fileSet, file: parsed,
			}}); err == nil {
				t.Fatal("unsafe generated source passed the static gate")
			}
		})
	}
}

func validateFamilyBuilderRawSource(
	source string,
	contracts []familyBuilderMethodStaticContract,
) error {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "synthetic.go", source, parser.AllErrors)
	if err != nil {
		return err
	}
	return validateFamilyBuilderSourceAPI([]parsedPackageSource{{
		path: "synthetic.go", set: fileSet, file: parsed,
	}}, contracts)
}

func TestSchemaDerivedConstructorsAreTerminatedByFamilyBuilder(t *testing.T) {
	packageDir := observabilityPackageDir(t)
	files, err := filepath.Glob(filepath.Join(packageDir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var unauthorized []string
	for _, filename := range files {
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}
		fileSet := token.NewFileSet()
		parsed, err := parser.ParseFile(fileSet, filename, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			identifier, ok := call.Fun.(*ast.Ident)
			if !ok || (identifier.Name != "newSchemaDerivedRecord" && identifier.Name != "newSchemaDerivedLogRecord") {
				return true
			}
			if filepath.Base(filename) != "family_builder.go" {
				position := fileSet.Position(call.Pos())
				unauthorized = append(unauthorized, filepath.Base(filename)+":"+position.String())
			}
			return true
		})
	}
	if len(unauthorized) != 0 {
		sort.Strings(unauthorized)
		t.Fatalf("schema-derived constructors bypass the family kernel: %v", unauthorized)
	}
}

func TestSchemaDerivedLogConstructorRequiresPrivateFamilyContract(t *testing.T) {
	packageDir := observabilityPackageDir(t)
	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(packageDir, "record.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "newSchemaDerivedLogRecord" {
			continue
		}
		found = true
		if function.Type.Params == nil || len(function.Type.Params.List) != 2 {
			t.Fatalf("newSchemaDerivedLogRecord parameters changed")
		}
		contractType, ok := function.Type.Params.List[1].Type.(*ast.Ident)
		if !ok || contractType.Name != "schemaDerivedLogFamilyContract" {
			t.Fatalf("newSchemaDerivedLogRecord no longer requires the private family contract")
		}
	}
	if !found {
		t.Fatal("newSchemaDerivedLogRecord declaration not found")
	}
}

func observabilityPackageDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve observability package directory")
	}
	return filepath.Dir(filename)
}
