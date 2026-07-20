// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxGGUFMetadataPrefixBytes int64 = 256 << 10
	maxGGUFMetadataPairs             = 4096
	maxGGUFMetadataStringBytes       = 16 << 10
	maxGGUFMetadataArrayItems        = 4096
	maxModelSidecarBytes       int64 = 64 << 10
)

const (
	ggufTypeUint8 uint32 = iota
	ggufTypeInt8
	ggufTypeUint16
	ggufTypeInt16
	ggufTypeUint32
	ggufTypeInt32
	ggufTypeFloat32
	ggufTypeBool
	ggufTypeString
	ggufTypeArray
	ggufTypeUint64
	ggufTypeInt64
	ggufTypeFloat64
)

var ggufBaseModelKeyPattern = regexp.MustCompile(`^general\.base_model\.([0-9]+)\.(name|author|organization|repo_url)$`)

type ggufMetadataValue struct {
	text   string
	number uint64
	kind   uint32
}

// modelArtifactProvenanceHints reads only bounded metadata surfaces. GGUF
// containers expose their provenance in a prefix key/value header; other
// formats use small, adjacent JSON sidecars. Any malformed or oversized
// metadata fails to unknown and never suppresses the underlying model signal.
func modelArtifactProvenanceHints(path, format string) modelProvenanceHints {
	var hints modelProvenanceHints
	if strings.EqualFold(format, "gguf") {
		if parsed, err := readGGUFProvenanceHints(path); err == nil {
			hints = mergeModelProvenanceHints(hints, parsed)
		}
	}
	if parsed, ok := readModelConfigProvenanceHints(filepath.Dir(path)); ok {
		hints = mergeModelProvenanceHints(hints, parsed)
	}
	return hints
}

func readGGUFProvenanceHints(path string) (modelProvenanceHints, error) {
	raw, err := readRegularFilePrefix(path, maxGGUFMetadataPrefixBytes)
	if err != nil {
		return modelProvenanceHints{}, err
	}
	metadata, err := parseGGUFMetadata(raw)
	if err != nil {
		return modelProvenanceHints{}, err
	}
	hints := modelProvenanceHints{Source: "gguf_metadata"}
	appendReference := func(key string) {
		if value := metadata[key].text; value != "" {
			hints.References = append(hints.References, value)
		}
	}
	// Source/base records precede the converted artifact's own identity so a
	// renamed quantized file resolves to its original weights.
	appendReference("general.source.repo_url")
	baseByIndex := make(map[int]map[string]string)
	for key, value := range metadata {
		match := ggufBaseModelKeyPattern.FindStringSubmatch(key)
		if len(match) != 3 || value.text == "" {
			continue
		}
		index, parseErr := strconv.Atoi(match[1])
		if parseErr != nil || index < 0 || index >= maxModelBaseModels {
			continue
		}
		if baseByIndex[index] == nil {
			baseByIndex[index] = make(map[string]string)
		}
		baseByIndex[index][match[2]] = value.text
	}
	for index := 0; index < maxModelBaseModels; index++ {
		base := baseByIndex[index]
		if base == nil {
			continue
		}
		identity := base["repo_url"]
		if identity == "" {
			identity = base["name"]
		}
		if identity != "" {
			hints.BaseModels = append(hints.BaseModels, identity)
			hints.References = append(hints.References, identity)
		}
		if repoID, ok := explicitHuggingFaceRepoID(base["repo_url"]); ok {
			hints.HuggingFaceRepoIDs = append(hints.HuggingFaceRepoIDs, repoID)
		}
		if org := firstNonEmpty(base["organization"], base["author"]); org != "" {
			hints.BaseOrganizations = append(hints.BaseOrganizations, org)
		}
	}
	appendReference("general.repo_url")
	for _, key := range []string{"general.source.repo_url", "general.repo_url"} {
		if repoID, ok := explicitHuggingFaceRepoID(metadata[key].text); ok {
			hints.HuggingFaceRepoIDs = append(hints.HuggingFaceRepoIDs, repoID)
		}
	}
	appendReference("general.name")
	appendReference("general.basename")
	for _, key := range []string{"general.organization", "general.author"} {
		if value := metadata[key].text; value != "" {
			hints.Organizations = append(hints.Organizations, value)
		}
	}
	if fileType, ok := ggufFileTypeName(metadata["general.file_type"]); ok {
		hints.Quantization = fileType
		value := !isUnquantizedEncoding(fileType)
		hints.Quantized = &value
	} else if version := metadata["general.quantization_version"]; version.kind == ggufTypeUint32 || version.kind == ggufTypeUint64 {
		hints.Quantization = fmt.Sprintf("GGUF-V%d", version.number)
		hints.Quantized = modelBool(true)
	} else if metadata["general.quantized_by"].text != "" {
		hints.Quantized = modelBool(true)
	}
	return hints, nil
}

func parseGGUFMetadata(raw []byte) (map[string]ggufMetadataValue, error) {
	reader := bytes.NewReader(raw)
	magic := make([]byte, 4)
	if _, err := reader.Read(magic); err != nil || string(magic) != "GGUF" {
		return nil, errors.New("invalid GGUF magic")
	}
	var version uint32
	if err := binary.Read(reader, binary.LittleEndian, &version); err != nil || (version != 2 && version != 3) {
		return nil, fmt.Errorf("unsupported GGUF version %d", version)
	}
	var tensorCount, pairCount uint64
	if err := binary.Read(reader, binary.LittleEndian, &tensorCount); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &pairCount); err != nil {
		return nil, err
	}
	_ = tensorCount // tensor metadata/data is intentionally never parsed
	if pairCount > maxGGUFMetadataPairs {
		return nil, errors.New("GGUF metadata pair count exceeds limit")
	}
	out := make(map[string]ggufMetadataValue)
	for i := uint64(0); i < pairCount; i++ {
		key, err := readGGUFString(reader)
		if err != nil {
			return nil, err
		}
		var valueType uint32
		if err := binary.Read(reader, binary.LittleEndian, &valueType); err != nil {
			return nil, err
		}
		keep := isRelevantGGUFMetadataKey(key)
		value, err := readGGUFValue(reader, valueType, keep, 0)
		if err != nil {
			return nil, err
		}
		if keep {
			out[key] = value
		}
	}
	return out, nil
}

func isRelevantGGUFMetadataKey(key string) bool {
	switch key {
	case "general.name", "general.author", "general.organization", "general.basename",
		"general.repo_url", "general.source.repo_url", "general.quantized_by",
		"general.quantization_version", "general.file_type", "general.base_model.count":
		return true
	default:
		return ggufBaseModelKeyPattern.MatchString(key)
	}
}

func readGGUFString(reader *bytes.Reader) (string, error) {
	var length uint64
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return "", err
	}
	if length > maxGGUFMetadataStringBytes || length > uint64(reader.Len()) {
		return "", errors.New("GGUF metadata string exceeds limit")
	}
	raw := make([]byte, int(length))
	if _, err := reader.Read(raw); err != nil {
		return "", err
	}
	return boundedLocalModelField(string(raw), maxGGUFMetadataStringBytes), nil
}

func readGGUFValue(reader *bytes.Reader, valueType uint32, keep bool, depth int) (ggufMetadataValue, error) {
	if depth > 2 {
		return ggufMetadataValue{}, errors.New("GGUF metadata nesting exceeds limit")
	}
	value := ggufMetadataValue{kind: valueType}
	switch valueType {
	case ggufTypeUint8, ggufTypeInt8, ggufTypeBool:
		var raw uint8
		if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
			return value, err
		}
		value.number = uint64(raw)
	case ggufTypeUint16, ggufTypeInt16:
		var raw uint16
		if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
			return value, err
		}
		value.number = uint64(raw)
	case ggufTypeUint32, ggufTypeInt32, ggufTypeFloat32:
		var raw uint32
		if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
			return value, err
		}
		value.number = uint64(raw)
	case ggufTypeUint64, ggufTypeInt64, ggufTypeFloat64:
		var raw uint64
		if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
			return value, err
		}
		value.number = raw
	case ggufTypeString:
		if keep {
			text, err := readGGUFString(reader)
			if err != nil {
				return value, err
			}
			value.text = text
		} else if err := skipGGUFString(reader); err != nil {
			return value, err
		}
	case ggufTypeArray:
		var elementType uint32
		var count uint64
		if err := binary.Read(reader, binary.LittleEndian, &elementType); err != nil {
			return value, err
		}
		if err := binary.Read(reader, binary.LittleEndian, &count); err != nil {
			return value, err
		}
		if count > maxGGUFMetadataArrayItems {
			return value, errors.New("GGUF metadata array exceeds limit")
		}
		for i := uint64(0); i < count; i++ {
			if _, err := readGGUFValue(reader, elementType, false, depth+1); err != nil {
				return value, err
			}
		}
	default:
		return value, fmt.Errorf("unsupported GGUF metadata type %d", valueType)
	}
	return value, nil
}

func skipGGUFString(reader *bytes.Reader) error {
	var length uint64
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return err
	}
	if length > uint64(reader.Len()) {
		return errors.New("GGUF metadata string exceeds bounded prefix")
	}
	_, err := reader.Seek(int64(length), io.SeekCurrent)
	return err
}

func ggufFileTypeName(value ggufMetadataValue) (string, bool) {
	if value.kind != ggufTypeUint32 && value.kind != ggufTypeUint64 {
		return "", false
	}
	names := map[uint64]string{
		0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 4: "Q4_1_SOME_F16",
		5: "Q4_2", 6: "Q4_3", 7: "Q8_0", 8: "Q5_0", 9: "Q5_1",
		10: "Q2_K", 11: "Q3_K_S", 12: "Q3_K_M", 13: "Q3_K_L",
		14: "Q4_K_S", 15: "Q4_K_M", 16: "Q5_K_S", 17: "Q5_K_M", 18: "Q6_K",
	}
	name, ok := names[value.number]
	return name, ok
}

func readModelConfigProvenanceHints(dir string) (modelProvenanceHints, bool) {
	var combined modelProvenanceHints
	parsedAny := false
	for _, name := range []string{"adapter_config.json", "config.json", "quantize_config.json", "quant_config.json"} {
		raw, err := readBoundedRegularFile(filepath.Join(dir, name), maxModelSidecarBytes)
		if err != nil {
			continue
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			continue
		}
		hints := modelProvenanceHints{Source: "model_config"}
		if base := safeMetadataModelReference(stringFromAny(document["base_model_name_or_path"])); base != "" {
			hints.BaseModels = append(hints.BaseModels, base)
			hints.References = append(hints.References, base)
			if repoID, ok := explicitHuggingFaceRepoID(base); ok {
				hints.HuggingFaceRepoIDs = append(hints.HuggingFaceRepoIDs, repoID)
			}
		}
		if source := safeMetadataModelReference(stringFromAny(document["_name_or_path"])); source != "" {
			hints.References = append(hints.References, source)
			if repoID, ok := explicitHuggingFaceRepoID(source); ok {
				hints.HuggingFaceRepoIDs = append(hints.HuggingFaceRepoIDs, repoID)
			}
		}
		quant := quantizationFromConfig(document)
		if quant != "" {
			hints.Quantization = quant
			hints.Quantized = modelBool(!isUnquantizedEncoding(quant))
		}
		if len(hints.References) > 0 || hints.Quantized != nil {
			combined = mergeModelProvenanceHints(combined, hints)
			parsedAny = true
		}
	}
	return combined, parsedAny
}

func quantizationFromConfig(document map[string]any) string {
	containers := []map[string]any{document}
	for _, key := range []string{"quantization_config", "quant_config"} {
		if nested, ok := document[key].(map[string]any); ok {
			containers = append([]map[string]any{nested}, containers...)
		}
	}
	for _, container := range containers {
		method := stringFromAny(container["quant_method"])
		if method == "" {
			method = stringFromAny(container["method"])
		}
		bits := positiveConfigBits(container["bits"])
		if method != "" && bits > 0 {
			return fmt.Sprintf("%s-%dBIT", method, bits)
		}
		if method != "" {
			return method
		}
		if bits > 0 {
			return fmt.Sprintf("%dBIT", bits)
		}
	}
	return ""
}

func positiveConfigBits(value any) int {
	switch number := value.(type) {
	case float64:
		if number >= 1 && number <= 64 && math.Trunc(number) == number {
			return int(number)
		}
	case json.Number:
		if parsed, err := strconv.Atoi(number.String()); err == nil && parsed >= 1 && parsed <= 64 {
			return parsed
		}
	}
	return 0
}

func stringFromAny(value any) string {
	text, _ := value.(string)
	return boundedLocalModelField(text, maxLocalModelIDBytes)
}

func safeMetadataModelReference(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || filepath.IsAbs(value) || strings.HasPrefix(value, ".") || strings.Contains(value, "\\") {
		return ""
	}
	if strings.Contains(value, "..") {
		return ""
	}
	if safe, ok := safeLocalModelID(value); ok {
		return safe
	}
	return ""
}

func mergeModelProvenanceHints(left, right modelProvenanceHints) modelProvenanceHints {
	left.References = uniqueBoundedModelReferences(append(left.References, right.References...), maxModelBaseModels+4)
	left.BaseModels = uniqueBoundedModelReferences(append(left.BaseModels, right.BaseModels...), maxModelBaseModels)
	left.Organizations = uniqueBoundedModelReferences(append(left.Organizations, right.Organizations...), maxModelBaseModels)
	left.BaseOrganizations = uniqueBoundedModelReferences(append(left.BaseOrganizations, right.BaseOrganizations...), maxModelBaseModels)
	left.HuggingFaceRepoIDs = uniqueCredibleHuggingFaceRepoIDs(append(left.HuggingFaceRepoIDs, right.HuggingFaceRepoIDs...))
	if left.Quantization == "" {
		left.Quantization = right.Quantization
	}
	if left.Quantized == nil && right.Quantized != nil {
		left.Quantized = modelBool(*right.Quantized)
	}
	if left.Distilled == nil && right.Distilled != nil {
		left.Distilled = modelBool(*right.Distilled)
	}
	if left.Source == "" {
		left.Source = right.Source
	} else if right.Source != "" && left.Source != right.Source {
		left.Source = "mixed"
	}
	return left
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
