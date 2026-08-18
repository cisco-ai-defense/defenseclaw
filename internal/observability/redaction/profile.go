// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// ProfileName is a stable route-selectable projection identity.
type ProfileName string

const (
	ProfileNone      ProfileName = "none"
	ProfileSensitive ProfileName = "sensitive"
	ProfileContent   ProfileName = "content"
	ProfileStrict    ProfileName = "strict"
	ProfileLegacyV7  ProfileName = "legacy-v7"
)

// TransformationMode is one field-class projection operation.
type TransformationMode string

const (
	ModePreserve TransformationMode = "preserve"
	ModeDetect   TransformationMode = "detect"
	ModeWhole    TransformationMode = "whole"
	ModeHash     TransformationMode = "hash"
	ModeRemove   TransformationMode = "remove"
)

const fieldClassCount = 8

// Profile is immutable: its resolved modes and detector groups are fixed-size
// value data and its accessors return copies.
type Profile struct {
	name        ProfileName
	base        ProfileName
	modes       [fieldClassCount]TransformationMode
	groups      [3]bool
	fingerprint [32]byte
}

// Name returns the route-selectable profile name.
func (profile Profile) Name() ProfileName { return profile.name }

// Base returns the built-in composition base. Built-ins return their own name.
func (profile Profile) Base() ProfileName { return profile.base }

// Mode returns the resolved mode for one canonical field class.
func (profile Profile) Mode(class observability.FieldClass) (TransformationMode, bool) {
	index, ok := fieldClassIndex(class)
	if !ok {
		return "", false
	}
	return profile.modes[index], true
}

// DetectorGroups returns the effective groups in canonical catalog order.
func (profile Profile) DetectorGroups() []DetectorGroup {
	ordered := DetectorGroups()
	result := make([]DetectorGroup, 0, len(ordered))
	for index, group := range ordered {
		if profile.groups[index] {
			result = append(result, group)
		}
	}
	return result
}

// IsRedacting reports whether this profile is allowed to transform payloads.
func (profile Profile) IsRedacting() bool { return profile.name != ProfileNone }

// BuiltInProfile resolves one immutable built-in profile.
func BuiltInProfile(name ProfileName) (Profile, bool) {
	profile, ok := builtInProfiles()[name]
	return profile, ok
}

// BuiltInProfiles returns independent immutable values in stable order.
func BuiltInProfiles() []Profile {
	definitions := builtInProfiles()
	return []Profile{
		definitions[ProfileNone],
		definitions[ProfileSensitive],
		definitions[ProfileContent],
		definitions[ProfileStrict],
		definitions[ProfileLegacyV7],
	}
}

// NewCustomProfile composes an immutable single-level profile. A nil group
// slice inherits the base selection; a present selection must be nonempty and
// replaces the complete effective selection. Overrides replace base cells.
func NewCustomProfile(
	name ProfileName,
	base ProfileName,
	detectorGroups []DetectorGroup,
	overrides map[observability.FieldClass]TransformationMode,
) (Profile, error) {
	if err := validateProfileName(name); err != nil {
		return Profile{}, err
	}
	if _, reserved := builtInProfiles()[name]; reserved {
		return Profile{}, fmt.Errorf("custom redaction profile name is reserved")
	}
	if base != ProfileSensitive && base != ProfileContent && base != ProfileStrict {
		return Profile{}, fmt.Errorf("custom redaction profile must extend sensitive, content, or strict")
	}
	profile, _ := BuiltInProfile(base)
	profile.name = name
	profile.base = base
	if detectorGroups != nil {
		if len(detectorGroups) == 0 {
			return Profile{}, fmt.Errorf("custom redaction profile detector groups must not be empty")
		}
		profile.groups = [3]bool{}
		for _, group := range detectorGroups {
			index, ok := detectorGroupIndex(group)
			if !ok {
				return Profile{}, fmt.Errorf("custom redaction profile contains an unknown detector group")
			}
			if profile.groups[index] {
				return Profile{}, fmt.Errorf("custom redaction profile contains a duplicate detector group")
			}
			profile.groups[index] = true
		}
	}
	for class, mode := range overrides {
		index, ok := fieldClassIndex(class)
		if !ok {
			return Profile{}, fmt.Errorf("custom redaction profile contains an unknown field class")
		}
		if !isTransformationMode(mode) {
			return Profile{}, fmt.Errorf("custom redaction profile contains an unknown transformation mode")
		}
		profile.modes[index] = mode
	}
	if err := validateResolvedProfile(profile, true); err != nil {
		return Profile{}, err
	}
	profile.fingerprint = profileFingerprint(profile)
	return profile, nil
}

// ProfileCatalog owns the immutable built-in and custom profile namespace.
type ProfileCatalog struct {
	profiles map[ProfileName]Profile
}

// NewProfileCatalog constructs a value-safe catalog. Every supplied profile
// must have been returned by NewCustomProfile and names must be unique.
func NewProfileCatalog(custom []Profile) (ProfileCatalog, error) {
	profiles := builtInProfiles()
	for _, profile := range custom {
		if profile.name == "" || profile.fingerprint != profileFingerprint(profile) {
			return ProfileCatalog{}, fmt.Errorf("redaction profile is not a valid immutable profile")
		}
		if _, exists := profiles[profile.name]; exists {
			return ProfileCatalog{}, fmt.Errorf("redaction profile name is duplicated")
		}
		if err := validateResolvedProfile(profile, true); err != nil {
			return ProfileCatalog{}, err
		}
		profiles[profile.name] = profile
	}
	return ProfileCatalog{profiles: profiles}, nil
}

// Resolve returns an immutable profile value.
func (catalog ProfileCatalog) Resolve(name ProfileName) (Profile, bool) {
	profile, ok := catalog.profiles[name]
	return profile, ok
}

// Names returns stable lexical custom-and-built-in catalog order.
func (catalog ProfileCatalog) Names() []ProfileName {
	names := make([]ProfileName, 0, len(catalog.profiles))
	for name := range catalog.profiles {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	return names
}

func builtInProfiles() map[ProfileName]Profile {
	none := resolvedBuiltIn(ProfileNone, [fieldClassCount]TransformationMode{
		ModePreserve, ModePreserve, ModePreserve, ModePreserve,
		ModePreserve, ModePreserve, ModePreserve, ModePreserve,
	}, false)
	sensitive := resolvedBuiltIn(ProfileSensitive, [fieldClassCount]TransformationMode{
		ModePreserve, ModePreserve, ModeDetect, ModeDetect,
		ModeDetect, ModeDetect, ModeHash, ModeRemove,
	}, true)
	content := resolvedBuiltIn(ProfileContent, [fieldClassCount]TransformationMode{
		ModePreserve, ModePreserve, ModeWhole, ModeWhole,
		ModeWhole, ModeWhole, ModeHash, ModeRemove,
	}, true)
	strict := resolvedBuiltIn(ProfileStrict, [fieldClassCount]TransformationMode{
		ModePreserve, ModePreserve, ModeRemove, ModeRemove,
		ModeRemove, ModeRemove, ModeRemove, ModeRemove,
	}, true)
	legacyV7 := resolvedBuiltIn(ProfileLegacyV7, [fieldClassCount]TransformationMode{
		ModePreserve, ModeWhole, ModeWhole, ModeWhole,
		ModeWhole, ModeWhole, ModeWhole, ModeWhole,
	}, false)
	return map[ProfileName]Profile{
		ProfileNone: none, ProfileSensitive: sensitive,
		ProfileContent: content, ProfileStrict: strict, ProfileLegacyV7: legacyV7,
	}
}

func resolvedBuiltIn(
	name ProfileName,
	modes [fieldClassCount]TransformationMode,
	allGroups bool,
) Profile {
	profile := Profile{name: name, base: name, modes: modes}
	if allGroups {
		profile.groups = [3]bool{true, true, true}
	}
	profile.fingerprint = profileFingerprint(profile)
	return profile
}

func validateProfileName(name ProfileName) error {
	if !observability.IsStableToken(string(name)) {
		return fmt.Errorf("redaction profile name is not a stable token")
	}
	return nil
}

func validateResolvedProfile(profile Profile, custom bool) error {
	if err := validateProfileName(profile.name); err != nil {
		return err
	}
	groups := profile.DetectorGroups()
	for index, class := range observability.FieldClasses() {
		mode := profile.modes[index]
		if !isTransformationMode(mode) {
			return fmt.Errorf("redaction profile has an unknown transformation mode")
		}
		if !custom {
			continue
		}
		if (class == observability.FieldClassMetadata || class == observability.FieldClassIdentifier) && mode != ModePreserve {
			return fmt.Errorf("custom redaction profile must preserve metadata and identifier classes")
		}
		if mode == ModePreserve && class != observability.FieldClassMetadata && class != observability.FieldClassIdentifier {
			return fmt.Errorf("custom redaction profile cannot preserve a dynamic field class")
		}
		if class == observability.FieldClassCredential && mode != ModeRemove && mode != ModeWhole {
			return fmt.Errorf("custom redaction profile credential mode must be remove or whole")
		}
		if mode == ModeDetect && len(groups) == 0 {
			return fmt.Errorf("custom redaction profile detect mode requires a detector group")
		}
	}
	return nil
}

func isTransformationMode(mode TransformationMode) bool {
	switch mode {
	case ModePreserve, ModeDetect, ModeWhole, ModeHash, ModeRemove:
		return true
	default:
		return false
	}
}

func fieldClassIndex(class observability.FieldClass) (int, bool) {
	for index, candidate := range observability.FieldClasses() {
		if class == candidate {
			return index, true
		}
	}
	return 0, false
}

func detectorGroupIndex(group DetectorGroup) (int, bool) {
	for index, candidate := range DetectorGroups() {
		if group == candidate {
			return index, true
		}
	}
	return 0, false
}

func profileFingerprint(profile Profile) [32]byte {
	var builder strings.Builder
	builder.WriteString(string(profile.name))
	builder.WriteByte(0)
	builder.WriteString(string(profile.base))
	for _, mode := range profile.modes {
		builder.WriteByte(0)
		builder.WriteString(string(mode))
	}
	for _, enabled := range profile.groups {
		if enabled {
			builder.WriteByte(1)
		} else {
			builder.WriteByte(0)
		}
	}
	return sha256.Sum256([]byte(builder.String()))
}
