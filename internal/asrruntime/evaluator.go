package asrruntime

import (
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"sort"
	"strings"
)

const (
	maxNativeProfileItems  = 256
	maxNativeResourceFacts = 1_024
	maxNativeEffects       = 1_024
	maxNativeFlows         = 1_024
)

type compiledProfile struct {
	SchemaVersion string            `json:"schema_version"`
	MappingID     string            `json:"mapping_id"`
	Revision      int               `json:"revision"`
	Command       mappingCommand    `json:"command"`
	Summary       string            `json:"summary"`
	Provenance    []json.RawMessage `json:"provenance"`
	Semantics     profileSemantics  `json:"semantics"`
	Syntax        profileSyntax     `json:"syntax"`
	Coverage      profileCoverage   `json:"coverage"`
}

type profileCoverage struct {
	Status            string   `json:"status"`
	EvaluationDefault string   `json:"evaluation_default"`
	Basis             string   `json:"basis"`
	ReviewState       string   `json:"review_state"`
	DocumentedOptions []string `json:"documented_options"`
	Notes             []string `json:"notes"`
}

type profileSemantics struct {
	Mode          string           `json:"mode"`
	ScopeStrategy string           `json:"scope_strategy"`
	Resources     []resourceSpec   `json:"resources"`
	Effects       []effectTemplate `json:"effects"`
	Flows         []flowTemplate   `json:"flows"`
}

type profileSyntax struct {
	OptionStyle               string            `json:"option_style"`
	AllowShortClusters        bool              `json:"allow_short_clusters"`
	OptionTerminator          string            `json:"option_terminator"`
	OptionsBeforeOperandsOnly bool              `json:"options_before_operands_only"`
	Operands                  operandSpec       `json:"operands"`
	Options                   []optionSpec      `json:"options"`
	Assignments               []assignmentSpec  `json:"assignments"`
	Controls                  []controlSpec     `json:"controls"`
	Constraints               syntaxConstraints `json:"constraints"`
}

type operandSpec struct {
	Minimum         int      `json:"min"`
	Maximum         *int     `json:"max"`
	ZeroAllowedWith []string `json:"zero_allowed_with"`
	MinUnconsumed   *int     `json:"min_unconsumed"`
}

type syntaxConstraints struct {
	RequireAnyOptions []string            `json:"require_any_options"`
	MutuallyExclusive [][]string          `json:"mutually_exclusive_options"`
	OptionRequiresAll map[string][]string `json:"option_requires_all"`
	OperandCounts     []conditionalCount  `json:"operand_counts"`
}

type conditionalCount struct {
	Minimum    int        `json:"min"`
	Maximum    *int       `json:"max"`
	ActiveWhen activation `json:"active_when"`
}

type optionSpec struct {
	ID          string        `json:"id"`
	Spellings   []string      `json:"spellings"`
	Arity       string        `json:"arity"`
	Support     string        `json:"support"`
	Roles       []string      `json:"roles"`
	Effects     optionEffects `json:"effects"`
	Value       *valueSpec    `json:"value"`
	Overrides   []string      `json:"overrides"`
	Description string        `json:"description"`
}

type assignmentSpec struct {
	ID          string        `json:"id"`
	Key         string        `json:"key"`
	Support     string        `json:"support"`
	Roles       []string      `json:"roles"`
	Effects     optionEffects `json:"effects"`
	Value       *valueSpec    `json:"value"`
	Description string        `json:"description"`
}

type optionEffects struct {
	EffectsAdd    []effectTemplate `json:"effects_add"`
	EffectsRemove []string         `json:"effects_remove"`
	Mode          string           `json:"mode"`
	Scope         string           `json:"scope"`
	Extent        string           `json:"extent"`
	Modifiers     []string         `json:"modifiers"`
	ConditionsAdd []string         `json:"conditions_add"`
	ApplyTo       []string         `json:"apply_to"`
}

type valueSpec struct {
	Disposition   string         `json:"disposition"`
	Decoder       string         `json:"decoder"`
	SemanticType  string         `json:"type"`
	DecoderConfig map[string]any `json:"decoder_config"`
	Parameter     string         `json:"parameter"`
	BindTo        []string       `json:"bind_to"`
	Default       *string        `json:"default"`
	Justification string         `json:"justification"`
}

type controlSpec struct {
	ID          string        `json:"id"`
	Source      controlSource `json:"source"`
	Value       valueSpec     `json:"value"`
	Consume     *bool         `json:"consume"`
	Required    *bool         `json:"required"`
	ActiveWhen  activation    `json:"active_when"`
	Description string        `json:"description"`
}

type controlSource struct {
	Kind  string `json:"kind"`
	Index *int   `json:"index"`
}

type activation struct {
	OptionPresent     []string     `json:"option_present"`
	OptionAbsent      []string     `json:"option_absent"`
	AssignmentPresent []string     `json:"assignment_present"`
	AssignmentAbsent  []string     `json:"assignment_absent"`
	OperandCount      operandRange `json:"operand_count"`
}

type operandRange struct {
	Minimum *int `json:"min"`
	Maximum *int `json:"max"`
}

type resourceSpec struct {
	ID         string           `json:"id"`
	Kind       string           `json:"kind"`
	Type       string           `json:"type"`
	Role       string           `json:"role"`
	Selector   resourceSelector `json:"selector"`
	ActiveWhen activation       `json:"active_when"`
}

type resourceSelector struct {
	Kind       string                 `json:"kind"`
	Index      *int                   `json:"index"`
	Option     string                 `json:"option"`
	Key        string                 `json:"key"`
	Assignment string                 `json:"assignment"`
	Literal    *string                `json:"literal"`
	Base       *resourceSelector      `json:"base"`
	Items      *resourceSelector      `json:"items"`
	Cases      []resourceSelectorCase `json:"cases"`
}

type resourceSelectorCase struct {
	Selector   resourceSelector `json:"selector"`
	ActiveWhen activation       `json:"active_when"`
}

type effectTemplate struct {
	ID            string           `json:"id"`
	Operation     string           `json:"operation"`
	EffectBuckets []string         `json:"effect_buckets"`
	ResourceRef   string           `json:"resource_ref"`
	Conditions    []string         `json:"conditions"`
	Scope         string           `json:"scope"`
	Extent        string           `json:"extent"`
	When          *effectPredicate `json:"when"`
}

type effectPredicate struct {
	Control        string `json:"control"`
	Field          string `json:"field"`
	Values         []any  `json:"values"`
	Negate         bool   `json:"negate"`
	MatchIfMissing bool   `json:"match_if_missing"`
}

type flowTemplate struct {
	Kind       string   `json:"kind"`
	From       string   `json:"from"`
	To         string   `json:"to"`
	Pairing    string   `json:"pairing"`
	Conditions []string `json:"conditions"`
}

type nativeProfile struct {
	profile           compiledProfile
	optionsBySpelling map[string]*optionSpec
	assignmentsByKey  map[string]*assignmentSpec
}

type nativeEvaluator struct {
	profiles []nativeProfile
}

type parsedOption struct {
	spec  *optionSpec
	value *string
}

type parsedAssignment struct {
	spec  *assignmentSpec
	value string
}

type parsedInvocation struct {
	options            []parsedOption
	assignments        []parsedAssignment
	operands           []string
	issues             []string
	uncertainArguments bool
	uncertainResources bool
	consumedOperands   map[int]struct{}
}

type evaluatedControl struct {
	fact      map[string]any
	parameter string
	bindTo    []string
}

func newNativeEvaluator(snapshot snapshotDocument) (Evaluator, error) {
	profiles := make([]nativeProfile, 0, len(snapshot.Mappings))
	for index, raw := range snapshot.Mappings {
		var profile compiledProfile
		if err := json.Unmarshal(raw, &profile); err != nil {
			return nil, fmt.Errorf("asrruntime: native mapping %d: %w", index, err)
		}
		if profile.MappingID == "" || profile.Command.Name == "" ||
			profile.SchemaVersion != PinnedSchemaVersion {
			return nil, fmt.Errorf("asrruntime: native mapping %d has invalid identity", index)
		}
		if len(profile.Syntax.Options) > maxNativeProfileItems ||
			len(profile.Syntax.Assignments) > maxNativeProfileItems ||
			len(profile.Syntax.Controls) > maxNativeProfileItems ||
			len(profile.Semantics.Resources) > maxNativeProfileItems ||
			len(profile.Semantics.Effects) > maxNativeProfileItems ||
			len(profile.Semantics.Flows) > maxNativeProfileItems {
			return nil, fmt.Errorf("asrruntime: mapping %q exceeds native profile limits", profile.MappingID)
		}
		compiled := nativeProfile{
			profile:           profile,
			optionsBySpelling: make(map[string]*optionSpec),
			assignmentsByKey:  make(map[string]*assignmentSpec),
		}
		for optionIndex := range compiled.profile.Syntax.Options {
			option := &compiled.profile.Syntax.Options[optionIndex]
			for _, spelling := range option.Spellings {
				if spelling == "" || compiled.optionsBySpelling[spelling] != nil {
					return nil, fmt.Errorf("asrruntime: mapping %q has duplicate option spelling %q", profile.MappingID, spelling)
				}
				compiled.optionsBySpelling[spelling] = option
			}
		}
		for assignmentIndex := range compiled.profile.Syntax.Assignments {
			assignment := &compiled.profile.Syntax.Assignments[assignmentIndex]
			if assignment.Key == "" || compiled.assignmentsByKey[assignment.Key] != nil {
				return nil, fmt.Errorf("asrruntime: mapping %q has duplicate assignment key %q", profile.MappingID, assignment.Key)
			}
			compiled.assignmentsByKey[assignment.Key] = assignment
		}
		profiles = append(profiles, compiled)
	}
	return &nativeEvaluator{profiles: profiles}, nil
}

func (e *nativeEvaluator) Evaluate(invocation NormalizedInvocation) Result {
	profile := e.selectProfile(invocation)
	if profile == nil {
		return Result{Status: StatusUnsupported, Issues: []string{"no_mapping"}}
	}
	return profile.evaluate(invocation)
}

func (e *nativeEvaluator) selectProfile(invocation NormalizedInvocation) *nativeProfile {
	program := invocation.Program
	if program == "" && len(invocation.Argv) != 0 {
		program = path.Base(invocation.Argv[0])
	}
	var candidates []*nativeProfile
	for index := range e.profiles {
		profile := &e.profiles[index]
		if !contains(profile.profile.Command.Surfaces, string(invocation.Surface)) ||
			!profileHasName(profile.profile.Command, program) {
			continue
		}
		if invocation.Profile != "" && profile.profile.Command.Profile != invocation.Profile {
			continue
		}
		candidates = append(candidates, profile)
	}
	if invocation.Profile == "" {
		var universal []*nativeProfile
		for _, candidate := range candidates {
			if candidate.profile.Command.Profile == "universal-linux" {
				universal = append(universal, candidate)
			}
		}
		if len(universal) != 0 {
			candidates = universal
		}
	}
	if len(candidates) != 1 {
		return nil
	}
	return candidates[0]
}

func profileHasName(command mappingCommand, name string) bool {
	return command.Name == name || contains(command.Aliases, name)
}

func (profile *nativeProfile) evaluate(invocation NormalizedInvocation) Result {
	parsed := profile.parseArgv(invocation.Argv[1:])
	issues := append([]string(nil), parsed.issues...)
	if containsAny(issues, "missing_option_value", "unexpected_option_value", "option_after_operand") {
		return nativeResult(StatusInvalid, issues, emptyNativeSemantics())
	}

	status := Status(profile.profile.Coverage.EvaluationDefault)
	if status == "" {
		status = Status(profile.profile.Coverage.Status)
	}
	if status != StatusComplete {
		status = StatusPartial
		issues = append(issues, "profile_coverage_partial")
	}
	if !invocation.ArgvComplete {
		status = StatusPartial
		issues = append(issues, "argv_incomplete")
		parsed.uncertainArguments = true
	}

	activeOptions, activeOptionOrder := activateOptions(parsed.options, &issues)
	activeAssignments, activeAssignmentOrder := activateAssignments(parsed.assignments, &issues)
	for _, option := range activeOptionOrder {
		if option.spec.Support == "UNSUPPORTED" {
			issues = append(issues, "unsupported_option")
			if intersects(option.spec.Roles, "RESOURCE_SELECTOR", "NESTED_INVOCATION") {
				parsed.uncertainResources = true
			}
		}
	}
	for _, assignment := range activeAssignmentOrder {
		if assignment.spec.Support == "UNSUPPORTED" {
			issues = append(issues, "unsupported_assignment")
			if intersects(assignment.spec.Roles, "RESOURCE_SELECTOR", "NESTED_INVOCATION") {
				parsed.uncertainResources = true
			}
		}
	}

	mode := profile.profile.Semantics.Mode
	modifiers := makeStringSet()
	conditions := makeStringSet()
	globalEffectModifiers := makeStringSet()
	effectModifiers := make(map[string]stringSet)
	effectConditions := make(map[string]stringSet)
	effectTemplates := make(map[string]effectTemplate, len(profile.profile.Semantics.Effects))
	for _, effect := range profile.profile.Semantics.Effects {
		effectTemplates[effect.ID] = effect
	}
	scopeOverride, extentOverride := "", ""
	effectScopeOverrides := make(map[string]string)
	effectExtentOverrides := make(map[string]string)
	for _, option := range activeOptionOrder {
		applyOptionEffects(option.spec.Effects, &mode, modifiers, conditions,
			globalEffectModifiers, effectModifiers, effectConditions, effectTemplates,
			&scopeOverride, &extentOverride, effectScopeOverrides, effectExtentOverrides)
	}
	for _, assignment := range activeAssignmentOrder {
		applyOptionEffects(assignment.spec.Effects, &mode, modifiers, conditions,
			globalEffectModifiers, effectModifiers, effectConditions, effectTemplates,
			&scopeOverride, &extentOverride, effectScopeOverrides, effectExtentOverrides)
	}

	if parsed.uncertainArguments {
		status = StatusPartial
	}
	if len(issues) != 0 {
		status = StatusPartial
	}

	nonEffectMode := mode == "HELP" || mode == "VALIDATE"
	controls, controlStatus, controlIssues := profile.evaluateControls(
		parsed, activeOptions, activeAssignments, activeOptionOrder, activeAssignmentOrder,
		!nonEffectMode,
	)
	issues = append(issues, controlIssues...)
	if controlStatus == StatusInvalid {
		semantics := profile.baseSemantics(mode, modifiers, controls)
		return nativeResult(StatusInvalid, issues, semantics)
	}
	if controlStatus == StatusPartial {
		status = StatusPartial
	}

	if !nonEffectMode && !parsed.uncertainArguments {
		if constraintIssues := checkConstraints(profile.profile.Syntax.Constraints, activeOptions, activeAssignments, len(parsed.operands)); len(constraintIssues) != 0 {
			issues = append(issues, constraintIssues...)
			semantics := profile.baseSemantics(mode, modifiers, controls)
			return nativeResult(StatusInvalid, issues, semantics)
		}
	}

	operandCount := len(parsed.operands)
	zeroAllowed := intersectsKeys(activeOptions, profile.profile.Syntax.Operands.ZeroAllowedWith)
	if operandCount < profile.profile.Syntax.Operands.Minimum && !zeroAllowed && !nonEffectMode {
		issues = append(issues, "missing_operand")
		return nativeResult(StatusInvalid, issues, emptyNativeSemantics())
	}
	if maximum := profile.profile.Syntax.Operands.Maximum; maximum != nil && operandCount > *maximum {
		issues = append(issues, "too_many_operands")
		return nativeResult(StatusInvalid, issues, emptyNativeSemantics())
	}
	if minimum := profile.profile.Syntax.Operands.MinUnconsumed; minimum != nil && !nonEffectMode {
		if operandCount-len(parsed.consumedOperands) < *minimum {
			issues = append(issues, "missing_unconsumed_operand")
			return nativeResult(StatusInvalid, issues, emptyNativeSemantics())
		}
	}
	if nonEffectMode {
		return nativeResult(status, issues, profile.baseSemantics(mode, modifiers, controls))
	}

	resourceArgumentsUncertain := parsed.uncertainArguments || parsed.uncertainResources
	resourcesByRef := make(map[string][]map[string]any)
	resourceFactCount := 0
	for _, resource := range profile.profile.Semantics.Resources {
		if !activationActive(resource.ActiveWhen, activeOptions, activeAssignments, operandCount) {
			continue
		}
		selected, supported := selectResourceValues(
			resource.Selector, parsed, activeOptions, activeAssignments,
		)
		if !supported {
			status = StatusPartial
			issues = append(issues, "unsupported_resource_selector:"+resource.ID)
			selected = []*string{nil}
		}
		if resourceArgumentsUncertain && !contains([]string{"STDIN", "STDOUT", "LITERAL"}, resource.Selector.Kind) {
			selected = []*string{nil}
		}
		if remaining := maxNativeResourceFacts - resourceFactCount; len(selected) > remaining {
			status = StatusPartial
			issues = append(issues, "resource_fact_limit")
			selected = selected[:remaining]
		}
		for _, value := range selected {
			if value != nil && *value == "" {
				issues = append(issues, "empty_resource_value")
				return nativeResult(StatusInvalid, issues, profile.baseSemantics(mode, modifiers, controls))
			}
			fact, resourceIssues := enrichNativeResource(resource, value, invocation)
			resourcesByRef[resource.ID] = append(resourcesByRef[resource.ID], fact)
			resourceFactCount++
			if !resourceArgumentsUncertain && len(resourceIssues) != 0 {
				status = StatusPartial
				issues = append(issues, resourceIssues...)
			}
		}
	}

	effects := buildNativeEffects(
		profile.profile, effectTemplates, resourcesByRef, controls, mode,
		conditions, globalEffectModifiers, effectModifiers, effectConditions,
		scopeOverride, extentOverride, effectScopeOverrides, effectExtentOverrides,
		resourceArgumentsUncertain, &status, &issues,
	)
	flows, flowIssue := buildNativeFlows(profile.profile, resourcesByRef)
	if flowIssue != "" {
		status = StatusPartial
		issues = append(issues, flowIssue)
	}
	semantics := profile.baseSemantics(mode, modifiers, controls)
	semantics["effects"] = effects
	semantics["flows"] = flows
	return nativeResult(status, issues, semantics)
}

func (profile *nativeProfile) parseArgv(argv []string) parsedInvocation {
	parsed := parsedInvocation{consumedOperands: make(map[int]struct{})}
	optionsEnded, sawOperand := false, false
	for index := 0; index < len(argv); {
		token := argv[index]
		if !optionsEnded && token == profile.profile.Syntax.OptionTerminator {
			optionsEnded = true
			index++
			continue
		}
		optionLike := strings.HasPrefix(token, "-") && token != "-"
		parseAsOption := !optionsEnded && optionLike
		if parseAsOption && sawOperand && profile.profile.Syntax.OptionsBeforeOperandsOnly {
			parsed.issues = append(parsed.issues, "option_after_operand")
		}
		if parseAsOption && strings.HasPrefix(token, "--") {
			spelling, inline, hasEquals := token, "", false
			if before, after, found := strings.Cut(token, "="); found {
				spelling, inline, hasEquals = before, after, true
			}
			option := profile.optionsBySpelling[spelling]
			if option == nil {
				parsed.issues = append(parsed.issues, "unknown_option")
				parsed.uncertainArguments = true
				index++
				continue
			}
			var value *string
			if hasEquals {
				value = stringPointer(inline)
			}
			switch option.Arity {
			case "NONE":
				if hasEquals {
					parsed.issues = append(parsed.issues, "unexpected_option_value")
				}
			case "REQUIRED":
				if value == nil {
					if index+1 >= len(argv) {
						parsed.issues = append(parsed.issues, "missing_option_value")
						parsed.uncertainArguments = true
					} else {
						index++
						value = stringPointer(argv[index])
					}
				}
			case "OPTIONAL":
			default:
				parsed.issues = append(parsed.issues, "unknown_option_arity")
				parsed.uncertainArguments = true
			}
			parsed.options = append(parsed.options, parsedOption{spec: option, value: value})
			index++
			continue
		}
		if parseAsOption {
			if exact := profile.optionsBySpelling[token]; exact != nil {
				var value *string
				if exact.Arity == "REQUIRED" {
					if index+1 >= len(argv) {
						parsed.issues = append(parsed.issues, "missing_option_value")
						parsed.uncertainArguments = true
					} else {
						index++
						value = stringPointer(argv[index])
					}
				} else if exact.Arity != "NONE" && exact.Arity != "OPTIONAL" {
					parsed.issues = append(parsed.issues, "unknown_option_arity")
					parsed.uncertainArguments = true
				}
				parsed.options = append(parsed.options, parsedOption{spec: exact, value: value})
				index++
				continue
			}
			if profile.profile.Syntax.AllowShortClusters && len(token) > 2 {
				cluster := token[1:]
				for clusterIndex := 0; clusterIndex < len(cluster); {
					spelling := "-" + cluster[clusterIndex:clusterIndex+1]
					option := profile.optionsBySpelling[spelling]
					if option == nil {
						parsed.issues = append(parsed.issues, "unknown_option")
						parsed.uncertainArguments = true
						clusterIndex++
						continue
					}
					var value *string
					if option.Arity == "REQUIRED" || option.Arity == "OPTIONAL" {
						remainder := cluster[clusterIndex+1:]
						if remainder != "" {
							value = stringPointer(remainder)
							clusterIndex = len(cluster)
						} else if option.Arity == "REQUIRED" {
							if index+1 >= len(argv) {
								parsed.issues = append(parsed.issues, "missing_option_value")
								parsed.uncertainArguments = true
							} else {
								index++
								value = stringPointer(argv[index])
							}
							clusterIndex = len(cluster)
						} else {
							clusterIndex++
						}
					} else if option.Arity == "NONE" {
						clusterIndex++
					} else {
						parsed.issues = append(parsed.issues, "unknown_option_arity")
						parsed.uncertainArguments = true
						clusterIndex++
					}
					parsed.options = append(parsed.options, parsedOption{spec: option, value: value})
				}
				index++
				continue
			}
			parsed.issues = append(parsed.issues, "unknown_option")
			parsed.uncertainArguments = true
			index++
			continue
		}
		if len(profile.assignmentsByKey) != 0 && strings.Contains(token, "=") {
			key, value, _ := strings.Cut(token, "=")
			assignment := profile.assignmentsByKey[key]
			if assignment == nil {
				parsed.issues = append(parsed.issues, "unknown_assignment")
				parsed.uncertainArguments = true
			} else {
				parsed.assignments = append(parsed.assignments, parsedAssignment{spec: assignment, value: value})
			}
			index++
			continue
		}
		parsed.operands = append(parsed.operands, token)
		sawOperand = true
		index++
	}
	return parsed
}

func activateOptions(parsed []parsedOption, issues *[]string) (map[string]parsedOption, []parsedOption) {
	active := make(map[string]parsedOption)
	order := make([]string, 0, len(parsed))
	seen := make(map[string]struct{})
	for _, option := range parsed {
		if _, exists := seen[option.spec.ID]; exists {
			*issues = append(*issues, "repeated_option_unmodeled:"+option.spec.ID)
		}
		seen[option.spec.ID] = struct{}{}
		for _, overridden := range option.spec.Overrides {
			delete(active, overridden)
			order = removeString(order, overridden)
		}
		if _, exists := active[option.spec.ID]; !exists {
			order = append(order, option.spec.ID)
		}
		active[option.spec.ID] = option
	}
	result := make([]parsedOption, 0, len(order))
	for _, id := range order {
		result = append(result, active[id])
	}
	return active, result
}

func activateAssignments(parsed []parsedAssignment, issues *[]string) (map[string]parsedAssignment, []parsedAssignment) {
	active := make(map[string]parsedAssignment)
	order := make([]string, 0, len(parsed))
	for _, assignment := range parsed {
		if _, exists := active[assignment.spec.ID]; exists {
			*issues = append(*issues, "repeated_assignment_unmodeled:"+assignment.spec.ID)
		} else {
			order = append(order, assignment.spec.ID)
		}
		active[assignment.spec.ID] = assignment
	}
	result := make([]parsedAssignment, 0, len(order))
	for _, id := range order {
		result = append(result, active[id])
	}
	return active, result
}

func applyOptionEffects(
	effects optionEffects,
	mode *string,
	modifiers, conditions, globalEffectModifiers stringSet,
	effectModifiers, effectConditions map[string]stringSet,
	effectTemplates map[string]effectTemplate,
	scopeOverride, extentOverride *string,
	effectScopeOverrides, effectExtentOverrides map[string]string,
) {
	for _, removed := range effects.EffectsRemove {
		delete(effectTemplates, removed)
	}
	for _, added := range effects.EffectsAdd {
		effectTemplates[added.ID] = added
	}
	modifiers.add(effects.Modifiers...)
	if len(effects.ApplyTo) != 0 {
		for _, effectID := range effects.ApplyTo {
			ensureSet(effectModifiers, effectID).add(effects.Modifiers...)
			ensureSet(effectConditions, effectID).add(effects.ConditionsAdd...)
			if effects.Scope != "" {
				effectScopeOverrides[effectID] = effects.Scope
			}
			if effects.Extent != "" {
				effectExtentOverrides[effectID] = effects.Extent
			}
		}
	} else {
		globalEffectModifiers.add(effects.Modifiers...)
		conditions.add(effects.ConditionsAdd...)
		if effects.Scope != "" {
			*scopeOverride = effects.Scope
		}
		if effects.Extent != "" {
			*extentOverride = effects.Extent
		}
	}
	if effects.Mode != "" {
		*mode = effects.Mode
	}
}

func (profile *nativeProfile) evaluateControls(
	parsed parsedInvocation,
	activeOptions map[string]parsedOption,
	activeAssignments map[string]parsedAssignment,
	optionOrder []parsedOption,
	assignmentOrder []parsedAssignment,
	includePositional bool,
) ([]evaluatedControl, Status, []string) {
	status := StatusComplete
	var issues []string
	var controls []evaluatedControl
	record := func(control *evaluatedControl, floor Status, issue string) {
		if control != nil {
			controls = append(controls, *control)
		}
		if issue != "" {
			issues = append(issues, issue)
		}
		if floor == StatusInvalid {
			status = StatusInvalid
		} else if floor == StatusPartial && status != StatusInvalid {
			status = StatusPartial
		}
	}
	for _, option := range optionOrder {
		if option.spec.Value != nil {
			control, floor, issue := evaluateNativeValue(option.spec.ID, *option.spec.Value, option.value, map[string]any{
				"kind": "OPTION_VALUE", "argument_id": option.spec.ID, "spelling": option.spec.Spellings[0],
			})
			record(control, floor, issue)
		}
	}
	for _, assignment := range assignmentOrder {
		if assignment.spec.Value != nil {
			value := assignment.value
			control, floor, issue := evaluateNativeValue(assignment.spec.ID, *assignment.spec.Value, &value, map[string]any{
				"kind": "ASSIGNMENT_VALUE", "argument_id": assignment.spec.ID, "key": assignment.spec.Key,
			})
			record(control, floor, issue)
		}
	}
	if includePositional {
		for _, spec := range profile.profile.Syntax.Controls {
			if !activationActive(spec.ActiveWhen, activeOptions, activeAssignments, len(parsed.operands)) {
				continue
			}
			if spec.Source.Kind != "OPERAND" || spec.Source.Index == nil {
				record(nil, StatusPartial, "unsupported_control_source:"+spec.ID)
				continue
			}
			index := *spec.Source.Index
			var raw *string
			if index >= 0 && index < len(parsed.operands) {
				raw = stringPointer(parsed.operands[index])
			}
			required := spec.Required == nil || *spec.Required
			if raw == nil && required {
				record(nil, StatusInvalid, "missing_control:"+spec.ID)
				continue
			}
			if raw == nil {
				continue
			}
			consume := spec.Consume == nil || *spec.Consume
			if consume {
				parsed.consumedOperands[index] = struct{}{}
			}
			control, floor, issue := evaluateNativeValue(spec.ID, spec.Value, raw, map[string]any{
				"kind": "POSITIONAL", "argument_id": spec.ID, "operand_index": index,
			})
			record(control, floor, issue)
		}
	}
	sort.Slice(controls, func(left, right int) bool {
		return controls[left].fact["id"].(string) < controls[right].fact["id"].(string)
	})
	return controls, status, issues
}

func evaluateNativeValue(id string, spec valueSpec, raw *string, source map[string]any) (*evaluatedControl, Status, string) {
	source = cloneMap(source)
	if raw == nil {
		source["raw_value"] = nil
	} else {
		source["raw_value"] = *raw
	}
	parameter := spec.Parameter
	if parameter == "" {
		parameter = id
	}
	if spec.Disposition == "OPAQUE" {
		semanticType := spec.SemanticType
		if semanticType == "" {
			semanticType = "opaque.value.v1"
		}
		return &evaluatedControl{fact: map[string]any{
			"id": id, "type": semanticType, "status": "OPAQUE", "source": source,
		}, parameter: parameter, bindTo: spec.BindTo}, StatusComplete, ""
	}
	if spec.Disposition == "CONSERVATIVE" {
		semanticType := spec.SemanticType
		if semanticType == "" {
			semanticType = "unresolved.value.v1"
		}
		return &evaluatedControl{fact: map[string]any{
			"id": id, "type": semanticType, "status": "UNRESOLVED", "source": source,
		}, parameter: parameter, bindTo: spec.BindTo}, StatusPartial, "unresolved_control_value:" + id
	}
	if spec.Disposition == "RESOURCE" {
		if raw == nil || spec.Decoder == "" {
			return nil, StatusComplete, ""
		}
		_, decodeStatus, decodeIssue := decodeNativeValue(spec, *raw)
		if decodeStatus == StatusInvalid {
			return nil, StatusInvalid, "invalid_resource_value:" + id + ":" + decodeIssue
		}
		if decodeStatus != StatusComplete {
			return nil, StatusPartial, "partial_resource_value:" + id + ":" + decodeIssue
		}
		return nil, StatusComplete, ""
	}
	if spec.Disposition != "TYPED" || spec.Decoder == "" || spec.SemanticType == "" {
		return nil, StatusPartial, "invalid_value_contract:" + id
	}
	decodeRaw := raw
	if decodeRaw == nil && spec.Default != nil {
		decodeRaw = spec.Default
		source["defaulted"] = true
	}
	if decodeRaw == nil {
		return nil, StatusComplete, ""
	}
	value, decodeStatus, decodeIssue := decodeNativeValue(spec, *decodeRaw)
	if decodeStatus == StatusInvalid {
		return nil, StatusInvalid, "invalid_control_value:" + id + ":" + decodeIssue
	}
	if decodeStatus != StatusComplete {
		return &evaluatedControl{fact: map[string]any{
			"id": id, "type": spec.SemanticType, "status": "UNRESOLVED", "source": source,
		}, parameter: parameter, bindTo: spec.BindTo}, StatusPartial, "partial_control_value:" + id + ":" + decodeIssue
	}
	return &evaluatedControl{fact: map[string]any{
		"id": id, "type": spec.SemanticType, "status": "DECODED", "source": source, "value": value,
	}, parameter: parameter, bindTo: spec.BindTo}, StatusComplete, ""
}

func decodeNativeValue(spec valueSpec, raw string) (map[string]any, Status, string) {
	if len(raw) > 16_384 {
		return nil, StatusPartial, "decoder_input_limit"
	}
	switch spec.Decoder {
	case "closed_enum.v1":
		aliases, ok := spec.DecoderConfig["aliases"].(map[string]any)
		if !ok {
			return nil, StatusPartial, "invalid_decoder_config"
		}
		caseSensitive := true
		if configured, exists := spec.DecoderConfig["case_sensitive"]; exists {
			var valid bool
			caseSensitive, valid = configured.(bool)
			if !valid {
				return nil, StatusPartial, "invalid_decoder_config"
			}
		}
		candidate := raw
		if !caseSensitive {
			candidate = strings.ToLower(candidate)
		}
		for alias, canonical := range aliases {
			key := alias
			if !caseSensitive {
				key = strings.ToLower(key)
			}
			if candidate == key {
				value, valid := canonical.(string)
				if !valid {
					return nil, StatusPartial, "invalid_decoder_config"
				}
				return map[string]any{"kind": "ENUM", "canonical": value}, StatusComplete, ""
			}
		}
		return nil, StatusInvalid, "invalid_enum_value"
	default:
		return nil, StatusPartial, "unsupported_decoder"
	}
}

func (profile *nativeProfile) baseSemantics(mode string, modifiers stringSet, controls []evaluatedControl) map[string]any {
	controlFacts := make([]map[string]any, 0, len(controls))
	for _, control := range controls {
		controlFacts = append(controlFacts, control.fact)
	}
	return map[string]any{
		"mapping_id": profile.profile.MappingID,
		"mode":       mode,
		"modifiers":  modifiers.sorted(),
		"evidence": map[string]any{
			"kind":               "REVIEWED_REGISTRY_MAPPING",
			"mapping_id":         profile.profile.MappingID,
			"mapping_revision":   profile.profile.Revision,
			"profile":            profile.profile.Command.Profile,
			"coverage_status":    profile.profile.Coverage.Status,
			"evaluation_default": evaluationDefault(profile.profile.Coverage),
			"coverage_basis":     profile.profile.Coverage.Basis,
			"review_state":       profile.profile.Coverage.ReviewState,
		},
		"controls": controlFacts,
		"effects":  []any{},
		"flows":    []any{},
	}
}

func emptyNativeSemantics() map[string]any {
	return map[string]any{"evidence": nil, "controls": []any{}, "effects": []any{}, "flows": []any{}}
}

func nativeResult(status Status, issues []string, semantics map[string]any) Result {
	encoded, err := json.Marshal(semantics)
	if err != nil {
		return Result{Status: StatusError, Issues: []string{"native_semantics_encoding_failure"}}
	}
	return Result{Status: status, Issues: normalizeIssues(issues), Semantics: encoded}
}

func evaluationDefault(coverage profileCoverage) string {
	if coverage.EvaluationDefault != "" {
		return coverage.EvaluationDefault
	}
	return coverage.Status
}

func checkConstraints(constraints syntaxConstraints, options map[string]parsedOption, assignments map[string]parsedAssignment, operandCount int) []string {
	var issues []string
	if len(constraints.RequireAnyOptions) != 0 && !intersectsKeys(options, constraints.RequireAnyOptions) {
		issues = append(issues, "required_option_group_missing")
	}
	for _, group := range constraints.MutuallyExclusive {
		count := 0
		for _, id := range group {
			if _, exists := options[id]; exists {
				count++
			}
		}
		if count > 1 {
			issues = append(issues, "mutually_exclusive_options")
		}
	}
	for id, required := range constraints.OptionRequiresAll {
		if _, exists := options[id]; !exists {
			continue
		}
		for _, requiredID := range required {
			if _, exists := options[requiredID]; !exists {
				issues = append(issues, "option_requirement_missing:"+id)
				break
			}
		}
	}
	for _, count := range constraints.OperandCounts {
		if !activationActive(count.ActiveWhen, options, assignments, operandCount) {
			continue
		}
		if operandCount < count.Minimum || count.Maximum != nil && operandCount > *count.Maximum {
			issues = append(issues, "conditional_operand_count")
		}
	}
	return issues
}

func activationActive(activation activation, options map[string]parsedOption, assignments map[string]parsedAssignment, operandCount int) bool {
	for _, id := range activation.OptionPresent {
		if _, exists := options[id]; !exists {
			return false
		}
	}
	for _, id := range activation.OptionAbsent {
		if _, exists := options[id]; exists {
			return false
		}
	}
	for _, id := range activation.AssignmentPresent {
		if _, exists := assignments[id]; !exists {
			return false
		}
	}
	for _, id := range activation.AssignmentAbsent {
		if _, exists := assignments[id]; exists {
			return false
		}
	}
	return (activation.OperandCount.Minimum == nil || operandCount >= *activation.OperandCount.Minimum) &&
		(activation.OperandCount.Maximum == nil || operandCount <= *activation.OperandCount.Maximum)
}

func selectResourceValues(selector resourceSelector, parsed parsedInvocation, options map[string]parsedOption, assignments map[string]parsedAssignment) ([]*string, bool) {
	operands := parsed.operands
	values := func(items []string) []*string {
		result := make([]*string, 0, len(items))
		for _, item := range items {
			result = append(result, stringPointer(item))
		}
		return result
	}
	switch selector.Kind {
	case "ALL_OPERANDS":
		return values(operands), true
	case "UNCONSUMED_OPERANDS":
		var selected []string
		for index, operand := range operands {
			if _, consumed := parsed.consumedOperands[index]; !consumed {
				selected = append(selected, operand)
			}
		}
		return values(selected), true
	case "ALL_BUT_LAST_OPERAND":
		if len(operands) == 0 {
			return nil, true
		}
		return values(operands[:len(operands)-1]), true
	case "FIRST_OPERAND":
		if len(operands) == 0 {
			return nil, true
		}
		return values(operands[:1]), true
	case "LAST_OPERAND":
		if len(operands) == 0 {
			return nil, true
		}
		return values(operands[len(operands)-1:]), true
	case "OPERAND_INDEX":
		if selector.Index == nil {
			return nil, false
		}
		index := normalizedIndex(*selector.Index, len(operands))
		if index < 0 || index >= len(operands) {
			return nil, true
		}
		return values(operands[index : index+1]), true
	case "OPERANDS_FROM_INDEX", "OPERANDS_FROM_INDEX_OR_STDIN":
		if selector.Index == nil {
			return nil, false
		}
		index := normalizedSliceIndex(*selector.Index, len(operands))
		selected := values(operands[index:])
		if selector.Kind == "OPERANDS_FROM_INDEX_OR_STDIN" {
			if len(selected) == 0 {
				selected = values([]string{"stdin"})
			}
			selected = replaceDashWithStdin(selected)
		}
		return selected, true
	case "OPERANDS_TO_INDEX":
		if selector.Index == nil {
			return nil, false
		}
		index := normalizedIndex(*selector.Index, len(operands))
		if index < 0 {
			index = 0
		}
		if index > len(operands) {
			index = len(operands)
		}
		return values(operands[:index]), true
	case "ALL_OPERANDS_OR_LITERAL":
		if len(operands) != 0 {
			return values(operands), true
		}
		if selector.Literal == nil {
			return nil, false
		}
		return []*string{stringPointer(*selector.Literal)}, true
	case "ALL_OPERANDS_OR_STDIN", "UNCONSUMED_OPERANDS_OR_STDIN":
		var selected []string
		for index, operand := range operands {
			if selector.Kind == "UNCONSUMED_OPERANDS_OR_STDIN" {
				if _, consumed := parsed.consumedOperands[index]; consumed {
					continue
				}
			}
			selected = append(selected, operand)
		}
		if len(selected) == 0 {
			selected = []string{"stdin"}
		}
		return replaceDashWithStdin(values(selected)), true
	case "OPTION_VALUE":
		option, exists := options[selector.Option]
		if !exists || option.value == nil {
			return nil, true
		}
		return []*string{stringPointer(*option.value)}, true
	case "ASSIGNMENT_VALUE":
		assignment, exists := assignments[selector.Assignment]
		if !exists {
			return nil, true
		}
		return []*string{stringPointer(assignment.value)}, true
	case "STDIN_UNLESS_ASSIGNMENT":
		if _, exists := assignments[selector.Assignment]; exists {
			return nil, true
		}
		return []*string{stringPointer("stdin")}, true
	case "STDIN":
		return []*string{stringPointer("stdin")}, true
	case "STDOUT":
		return []*string{stringPointer("stdout")}, true
	case "LITERAL":
		if selector.Literal == nil {
			return nil, false
		}
		return []*string{stringPointer(*selector.Literal)}, true
	case "CONDITIONAL":
		for _, candidate := range selector.Cases {
			if activationActive(candidate.ActiveWhen, options, assignments, len(operands)) {
				return selectResourceValues(candidate.Selector, parsed, options, assignments)
			}
		}
		return nil, true
	case "BASENAME_JOIN":
		if selector.Base == nil || selector.Items == nil {
			return nil, false
		}
		bases, baseOK := selectResourceValues(*selector.Base, parsed, options, assignments)
		items, itemOK := selectResourceValues(*selector.Items, parsed, options, assignments)
		if !baseOK || !itemOK || len(bases) != 1 || bases[0] == nil {
			return []*string{nil}, baseOK && itemOK
		}
		joined := make([]*string, 0, len(items))
		for _, item := range items {
			if item == nil {
				joined = append(joined, nil)
			} else {
				joined = append(joined, stringPointer(path.Join(*bases[0], path.Base(*item))))
			}
		}
		return joined, true
	default:
		return nil, false
	}
}

func enrichNativeResource(spec resourceSpec, value *string, invocation NormalizedInvocation) (map[string]any, []string) {
	if value == nil {
		return unresolvedResource(spec), []string{"resource_resolution_unknown"}
	}
	context := invocation.Context
	fact := findWordFact(invocation.WordFacts, *value)
	rawValue, normalizedValue, resolvedValue := *value, *value, (*string)(nil)
	resolution := ResolutionExact
	expansions := []string{}
	if fact != nil {
		rawValue = fact.RawValue
		resolution = fact.Resolution
		if fact.NormalizedValue != nil {
			normalizedValue = *fact.NormalizedValue
		}
		if fact.ResolvedValue != nil {
			resolvedValue = stringPointer(path.Clean(*fact.ResolvedValue))
		}
		for _, expansion := range fact.Expansions {
			expansions = append(expansions, string(expansion))
		}
		sort.Strings(expansions)
	}
	isPath := isPathResource(spec.Kind, spec.Type, *value)
	if fact == nil && isPath {
		normalizedValue = path.Clean(*value)
	}
	if *value == "current-working-directory" {
		if context != nil && context.CWD != "" {
			resolvedValue = stringPointer(path.Clean(context.CWD))
			resolution = ResolutionContextual
		}
	} else if *value == "all-mounted-filesystems" {
		resolvedValue = nil
		resolution = ResolutionGenerated
	} else if fact == nil && isPath && strings.HasPrefix(*value, "/") {
		resolvedValue = stringPointer(normalizedValue)
	} else if fact == nil && isPath && context != nil && context.CWD != "" {
		resolvedValue = stringPointer(path.Join(context.CWD, normalizedValue))
	}
	var issues []string
	if resolution == ResolutionUnknown {
		issues = append(issues, "resource_resolution_unknown")
	}
	unsafeExpansion := contains(expansions, string(ExpansionCommandSubstitution))
	if unsafeExpansion {
		issues = append(issues, "unsafe_expansion_provenance")
	}
	location := "UNKNOWN"
	if *value == "all-mounted-filesystems" {
		location = "SYSTEM"
	} else if !unsafeExpansion && resolution != ResolutionUnknown && isPath {
		location = nativeLocation(resolvedValue, context)
	}
	resourceResolution := "STATIC"
	if resolution == ResolutionUnknown {
		resourceResolution = "UNRESOLVED"
	}
	return map[string]any{
		"kind":             spec.Kind,
		"type":             spec.Type,
		"role":             spec.Role,
		"id":               *value,
		"resolution":       resourceResolution,
		"raw_value":        rawValue,
		"normalized_value": normalizedValue,
		"resolved_value":   pointerValue(resolvedValue),
		"resolution_kind":  string(resolution),
		"location":         location,
		"expansions":       expansions,
	}, issues
}

func unresolvedResource(spec resourceSpec) map[string]any {
	return map[string]any{
		"kind": spec.Kind, "type": spec.Type, "role": spec.Role,
		"id": nil, "resolution": "UNRESOLVED", "raw_value": nil,
		"normalized_value": nil, "resolved_value": nil,
		"resolution_kind": "UNKNOWN", "location": "UNKNOWN", "expansions": []string{},
	}
}

func buildNativeEffects(
	profile compiledProfile,
	templates map[string]effectTemplate,
	resources map[string][]map[string]any,
	controls []evaluatedControl,
	mode string,
	conditions, globalModifiers stringSet,
	effectModifiers, effectConditions map[string]stringSet,
	scopeOverride, extentOverride string,
	effectScopeOverrides, effectExtentOverrides map[string]string,
	resourceArgumentsUncertain bool,
	status *Status,
	issues *[]string,
) []map[string]any {
	ids := make([]string, 0, len(templates))
	for id := range templates {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var effects []map[string]any
	for _, id := range ids {
		template := templates[id]
		predicate, resolved := nativePredicate(template.When, controls)
		if resolved && !predicate {
			continue
		}
		predicateConditions := makeStringSet()
		if !resolved {
			*status = StatusPartial
			*issues = append(*issues, "effect_predicate_unresolved:"+template.ID)
			predicateConditions.add("IF_CONTROL_PREDICATE_MATCHES")
		}
		parameters := boundParameters(controls, template.ID)
		selected := resources[template.ResourceRef]
		targetCount := len(selected)
		baseScope, upperBound := nativeBaseScope(profile.Semantics.ScopeStrategy, targetCount)
		directUpperBound := targetCount
		selectedScope := firstNonempty(effectScopeOverrides[template.ID], scopeOverride, template.Scope, baseScope)
		if selectedScope != baseScope {
			upperBound = nil
		}
		if resourceArgumentsUncertain {
			selectedScope, upperBound = "UNKNOWN", nil
		}
		selectedExtent := firstNonempty(effectExtentOverrides[template.ID], extentOverride, template.Extent)
		selectedModifiers := globalModifiers.copy()
		selectedModifiers.merge(effectModifiers[template.ID])
		if selectedExtent == "" {
			switch {
			case selectedScope == "ALL":
				selectedExtent = "GLOBAL"
			case selectedModifiers.has("RECURSIVE") || containsSubstringValue(template.Conditions, "DESCENDANT"):
				selectedExtent = "DESCENDANTS"
			case selectedScope == "UNBOUNDED" || selectedScope == "UNKNOWN":
				selectedExtent = "UNKNOWN"
			default:
				selectedExtent = "DIRECT"
			}
		}
		for _, resource := range selected {
			if len(effects) == maxNativeEffects {
				*status = StatusPartial
				*issues = append(*issues, "effect_limit")
				return effects
			}
			resourceScope, resourceExtent := selectedScope, selectedExtent
			resourceUpperBound := upperBound
			uncertain := resource["resolution_kind"] == "UNKNOWN" || containsAnyString(resource["expansions"], string(ExpansionCommandSubstitution))
			directKnown := !resourceArgumentsUncertain && !uncertain &&
				(resource["resolution_kind"] == "EXACT" || resource["resolution_kind"] == "CONTEXTUAL")
			if profile.Semantics.ScopeStrategy == "UNKNOWN" && resourceScope != "ONE" && resourceScope != "BOUNDED_MANY" {
				directKnown = false
			}
			if uncertain {
				resourceScope, resourceExtent, resourceUpperBound = "UNKNOWN", "UNKNOWN", nil
			} else if resourceExtent == "GLOBAL" {
				resourceScope, resourceUpperBound = "ALL", nil
			} else if resourceExtent == "DESCENDANTS" && resource["location"] == "ROOT" {
				resourceExtent, resourceScope, resourceUpperBound = "GLOBAL", "ALL", nil
			} else if resourceExtent == "DESCENDANTS" || resourceExtent == "GENERATED" ||
				!directKnown && resourceScope != "ALL" && resourceScope != "UNKNOWN" {
				resourceScope, resourceUpperBound = "UNBOUNDED", nil
			}
			directCardinality := map[string]any{"kind": "UNKNOWN"}
			selectionCardinality := map[string]any{"kind": "UNKNOWN"}
			if directKnown {
				directCardinality = map[string]any{"kind": "EXACT", "value": 1}
				selectionCardinality = map[string]any{"kind": "EXACT", "value": targetCount}
			}
			scope := map[string]any{
				"kind": resourceScope, "direct_cardinality": directCardinality,
				"selection_cardinality": selectionCardinality, "extent": resourceExtent,
			}
			if resourceUpperBound != nil {
				scope["upper_bound"] = *resourceUpperBound
			}
			if directKnown && (resourceScope == "UNBOUNDED" || resourceScope == "ALL") {
				scope["direct_upper_bound"] = directUpperBound
			}
			effectConditionSet := makeStringSet(template.Conditions...)
			effectConditionSet.merge(conditions)
			effectConditionSet.merge(effectConditions[template.ID])
			effectConditionSet.merge(predicateConditions)
			effects = append(effects, map[string]any{
				"effect_id": len(effects) + 1, "operation": template.Operation,
				"effect_buckets": sortedCopy(template.EffectBuckets), "mode": mode,
				"resource": resource, "scope": scope, "conditions": effectConditionSet.sorted(),
				"parameters": parameters, "mapping_id": profile.MappingID,
			})
		}
	}
	if effects == nil {
		return []map[string]any{}
	}
	return effects
}

func nativePredicate(predicate *effectPredicate, controls []evaluatedControl) (bool, bool) {
	if predicate == nil {
		return true, true
	}
	for _, control := range controls {
		if control.fact["id"] != predicate.Control {
			continue
		}
		value, ok := control.fact["value"].(map[string]any)
		if control.fact["status"] != "DECODED" || !ok {
			return false, false
		}
		field, exists := value[predicate.Field]
		if !exists {
			return false, false
		}
		matched := false
		for _, candidate := range predicate.Values {
			if reflect.DeepEqual(field, candidate) {
				matched = true
				break
			}
		}
		if predicate.Negate {
			matched = !matched
		}
		return matched, true
	}
	return predicate.MatchIfMissing, true
}

func boundParameters(controls []evaluatedControl, effectID string) []map[string]any {
	var parameters []map[string]any
	for _, control := range controls {
		if !contains(control.bindTo, "*") && !contains(control.bindTo, effectID) {
			continue
		}
		parameter := map[string]any{
			"name": control.parameter, "type": control.fact["type"],
			"status": control.fact["status"], "source": control.fact["source"],
		}
		if value, exists := control.fact["value"]; exists {
			parameter["value"] = value
		}
		parameters = append(parameters, parameter)
	}
	sort.Slice(parameters, func(left, right int) bool {
		return parameters[left]["name"].(string) < parameters[right]["name"].(string)
	})
	if parameters == nil {
		return []map[string]any{}
	}
	return parameters
}

func nativeBaseScope(strategy string, count int) (string, *int) {
	switch strategy {
	case "NONE":
		return "ONE", nil
	case "ONE":
		return "ONE", intPointer(1)
	case "UNKNOWN":
		return "UNKNOWN", nil
	default:
		if count == 0 {
			return "ONE", intPointer(0)
		}
		if count == 1 {
			return "ONE", intPointer(1)
		}
		return "BOUNDED_MANY", intPointer(count)
	}
}

func buildNativeFlows(profile compiledProfile, resources map[string][]map[string]any) ([]map[string]any, string) {
	var flows []map[string]any
	for _, template := range profile.Semantics.Flows {
		sources, destinations := resources[template.From], resources[template.To]
		if template.Pairing == "ZIP" && len(sources) != len(destinations) {
			return []map[string]any{}, "flow_pairing_mismatch"
		}
		for sourceIndex, source := range sources {
			for destinationIndex, destination := range destinations {
				if template.Pairing == "ZIP" && sourceIndex != destinationIndex {
					continue
				}
				if len(flows) == maxNativeFlows {
					return []map[string]any{}, "flow_limit"
				}
				flows = append(flows, map[string]any{
					"flow_id": len(flows) + 1, "kind": template.Kind,
					"from": source, "to": destination,
					"conditions": sortedCopy(template.Conditions), "mapping_id": profile.MappingID,
				})
			}
		}
	}
	if flows == nil {
		return []map[string]any{}, ""
	}
	return flows, ""
}

type stringSet map[string]struct{}

func makeStringSet(values ...string) stringSet {
	set := make(stringSet)
	set.add(values...)
	return set
}

func (set stringSet) add(values ...string) {
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
}

func (set stringSet) has(value string) bool {
	_, exists := set[value]
	return exists
}

func (set stringSet) merge(other stringSet) {
	for value := range other {
		set[value] = struct{}{}
	}
}

func (set stringSet) copy() stringSet {
	copy := makeStringSet()
	copy.merge(set)
	return copy
}

func (set stringSet) sorted() []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func ensureSet(sets map[string]stringSet, key string) stringSet {
	if sets[key] == nil {
		sets[key] = makeStringSet()
	}
	return sets[key]
}

func findWordFact(facts []WordFact, value string) *WordFact {
	for index := range facts {
		if facts[index].Value == value {
			return &facts[index]
		}
	}
	return nil
}

func isPathResource(kind, resourceType, value string) bool {
	if kind != "HOST_FILESYSTEM_DEVICE" || contains([]string{"stdin", "stdout", "all-mounted-filesystems"}, value) {
		return false
	}
	if strings.HasPrefix(resourceType, "stream.") ||
		contains([]string{"filesystem.buffers", "filesystem.user_home_and_mail"}, resourceType) {
		return false
	}
	return strings.HasPrefix(resourceType, "filesystem.") || strings.HasPrefix(value, "/") || strings.HasPrefix(value, ".")
}

func nativeLocation(resolved *string, context *InvocationContext) string {
	if resolved == nil || !strings.HasPrefix(*resolved, "/") {
		return "UNKNOWN"
	}
	if *resolved == "/" {
		return "ROOT"
	}
	if context != nil {
		for _, root := range context.WorkspaceRoots {
			if pathContains(root, *resolved) {
				return "WORKSPACE"
			}
		}
		if context.ActiveHome != "" && pathContains(context.ActiveHome, *resolved) {
			return "HOME"
		}
		for _, root := range context.TemporaryRoots {
			if pathContains(root, *resolved) {
				return "TEMP"
			}
		}
	}
	for _, root := range []string{"/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var"} {
		if pathContains(root, *resolved) {
			return "SYSTEM"
		}
	}
	return "OTHER"
}

func pathContains(root, value string) bool {
	root, value = path.Clean(root), path.Clean(value)
	return value == root || root == "/" && strings.HasPrefix(value, "/") ||
		root != "/" && strings.HasPrefix(value, root+"/")
}

func intersects(values []string, candidates ...string) bool {
	for _, candidate := range candidates {
		if contains(values, candidate) {
			return true
		}
	}
	return false
}

func intersectsKeys[T any](values map[string]T, candidates []string) bool {
	for _, candidate := range candidates {
		if _, exists := values[candidate]; exists {
			return true
		}
	}
	return false
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func containsAny(values []string, candidates ...string) bool {
	return intersects(values, candidates...)
}

func containsSubstringValue(values []string, fragment string) bool {
	for _, value := range values {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func containsAnyString(value any, candidate string) bool {
	values, ok := value.([]string)
	return ok && contains(values, candidate)
}

func sortedCopy(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	if result == nil {
		return []string{}
	}
	return result
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func removeString(values []string, removed string) []string {
	for index, value := range values {
		if value == removed {
			return append(values[:index], values[index+1:]...)
		}
	}
	return values
}

func replaceDashWithStdin(values []*string) []*string {
	for index, value := range values {
		if value != nil && *value == "-" {
			values[index] = stringPointer("stdin")
		}
	}
	return values
}

func normalizedIndex(index, length int) int {
	if index < 0 {
		return length + index
	}
	return index
}

func normalizedSliceIndex(index, length int) int {
	index = normalizedIndex(index, length)
	if index < 0 {
		return 0
	}
	if index > length {
		return length
	}
	return index
}

func stringPointer(value string) *string { return &value }
func intPointer(value int) *int          { return &value }

func pointerValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func cloneMap(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
