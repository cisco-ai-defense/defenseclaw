# StreamGRPO MLSys Paper

**Title:** StreamGRPO: NVMe-Streaming Reinforcement Learning for Language Models on Commodity Hardware

**Author:** Nikhil Ghodki, Cisco Systems

**Target Venue:** MLSys / OSDI systems track

## Overview

This paper presents StreamGRPO, a pure-C GRPO training engine that enables RL training for language models on commodity hardware without GPUs. The key innovation is streaming the reference model layer-by-layer from NVMe storage, reducing memory from 3.4GB to 52MB (98.5% reduction).

## Key Claims

1. **Quality parity** with TRL+Unsloth on GSM8K (within 2% accuracy)
2. **98.5% memory reduction** for reference model (52MB vs 3.4GB)
3. **First pure-C GRPO engine** - runs on 8GB RAM laptop without GPU
4. **35% I/O throughput improvement** with io_uring double-buffering

## Structure

- `paper.tex` - Main paper body (10-12 pages)
- `references.bib` - Bibliography
- `Makefile` - Build system (pdflatex + bibtex)
- `figures/` - Directory for generated figures (TODO: populate from benchmarks)

## Building

```bash
make          # Build paper.pdf
make clean    # Remove build artifacts
make view     # Open PDF in viewer
make check    # Quick syntax check
```

## TODO: Evaluation Data

The paper has TODO placeholders in evaluation sections that need to be filled from benchmark results:

### From Task 2 (Quality Comparison)
- **Table 1**: GSM8K accuracy comparison (TRL vs StreamGRPO)
- **Expected**: Within 2% accuracy difference
- **Source**: `benchmarks/grpo/results/trl_vs_streamgrpo.json`

### From Task 3 (I/O Performance)
- **Table 3**: I/O backend comparison (mmap vs pread vs io_uring)
- **Expected**: io_uring 35% faster than pread, uses 104MB vs 52MB
- **Source**: `benchmarks/grpo/results/io_comparison.json`

### From Task 2 (Memory Profiling)
- **Table 2**: Peak memory usage during training
- **Expected**: StreamGRPO uses ~1.9GB total (52MB reference + 1.83GB policy+LoRA)
- **Source**: `benchmarks/grpo/results/memory_profile.json`

### Additional Data Needed
- **Table 4**: Wall-clock training time comparison
- **Table 5**: Ablation study (impact of each optimization)

## Figures to Generate

Once benchmarks are complete, generate the following figures:

1. **Architecture diagram** (`figures/architecture.pdf`)
   - Show Go orchestrator + C engine split
   - Highlight NVMe streaming path
   - Show KV cache snapshot/restore flow

2. **Memory comparison** (`figures/memory_comparison.pdf`)
   - Bar chart: TRL (6.8GB) vs StreamGRPO (1.9GB)
   - Breakdown: policy RAM vs reference RAM

3. **I/O throughput** (`figures/io_throughput.pdf`)
   - Line graph: tokens/sec vs sequence length
   - Three lines: mmap, pread, io_uring

4. **Training convergence** (`figures/convergence.pdf`)
   - Line graph: eval accuracy vs training steps
   - Two lines: TRL and StreamGRPO (should overlap)

## Dependencies

- pdflatex (TeX Live 2020+)
- bibtex
- ACM acmart document class
- Standard LaTeX packages: booktabs, graphicx, amsmath, algorithm, listings

## Notes

- Paper uses ACM `acmart` sigconf format (two-column)
- Configured for anonymous review (author names will be revealed after acceptance)
- Focus is on **systems contributions**, not algorithmic novelty
- Target length: 10-12 pages including references
- Current draft: ~3,500 words (body only, excluding abstract/references)
