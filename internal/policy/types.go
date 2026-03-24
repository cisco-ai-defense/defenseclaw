package policy

// AdmissionInput is the structured input passed to the OPA admission policy.
type AdmissionInput struct {
	TargetType string          `json:"target_type"`
	TargetName string          `json:"target_name"`
	Path       string          `json:"path"`
	BlockList  []ListEntry     `json:"block_list"`
	AllowList  []ListEntry     `json:"allow_list"`
	ScanResult *ScanResultInput `json:"scan_result,omitempty"`
}

// ListEntry represents one entry in the block or allow list.
type ListEntry struct {
	TargetType string `json:"target_type"`
	TargetName string `json:"target_name"`
	Reason     string `json:"reason"`
}

// ScanResultInput is the scan result subset needed by OPA.
type ScanResultInput struct {
	MaxSeverity   string `json:"max_severity"`
	TotalFindings int    `json:"total_findings"`
}

// AdmissionOutput is the structured output from the OPA admission policy.
type AdmissionOutput struct {
	Verdict    string `json:"verdict"`
	Reason     string `json:"reason"`
	FileAction string `json:"file_action"`
}
