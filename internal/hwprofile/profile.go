package hwprofile

// SystemProfile contains the detected hardware capabilities of the host.
// Computed once at sidecar startup and cached. Exposed via /api/v1/profile/hardware.
type SystemProfile struct {
	CPUName        string    `json:"cpu_name"`
	CPUCores       int       `json:"cpu_cores"`
	TotalRAMGB     float64   `json:"total_ram_gb"`
	AvailableRAMGB float64   `json:"available_ram_gb"`
	HasGPU         bool      `json:"has_gpu"`
	GPUs           []GpuInfo `json:"gpus"`
	TotalGPUVRAMGB float64   `json:"total_gpu_vram_gb"`
	Platform       string    `json:"platform"`
	Arch           string    `json:"arch"`
	UnifiedMemory  bool      `json:"unified_memory"`
	HardwareTier   string    `json:"hardware_tier"`
	MaxModelFP16GB float64   `json:"max_model_fp16_gb"`
	MaxModelINT4GB float64   `json:"max_model_int4_gb"`
}

// GpuInfo describes a single GPU or accelerator.
type GpuInfo struct {
	Name          string  `json:"name"`
	VRAMTotalGB   float64 `json:"vram_total_gb"`
	UnifiedMemory bool    `json:"unified_memory"`
	Backend       string  `json:"backend"` // cuda, metal, rocm, vulkan, cpu
}
