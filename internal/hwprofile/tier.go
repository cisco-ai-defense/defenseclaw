package hwprofile

// classifyTier determines the hardware tier and maximum model sizes.
func classifyTier(p *SystemProfile) {
	var effective float64
	if p.UnifiedMemory {
		effective = p.TotalRAMGB
	} else if p.TotalGPUVRAMGB > 0 {
		effective = p.TotalGPUVRAMGB
	} else {
		effective = p.TotalRAMGB * 0.7
	}

	switch {
	case effective <= 4:
		p.HardwareTier = "edge"
	case effective <= 16:
		p.HardwareTier = "laptop"
	case effective <= 48:
		p.HardwareTier = "desktop"
	case effective <= 160:
		p.HardwareTier = "workstation"
	default:
		p.HardwareTier = "server"
	}

	// Max model sizes: 75% of effective memory usable for model weights
	usable := effective * 0.75
	p.MaxModelFP16GB = usable / 2.0 // FP16 = 2 bytes/param → 1B params = 2GB
	p.MaxModelINT4GB = usable / 0.6 // INT4 ≈ 0.6 bytes/param → 1B params = 0.6GB
}
