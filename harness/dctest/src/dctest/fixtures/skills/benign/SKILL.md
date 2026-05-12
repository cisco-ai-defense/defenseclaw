---
name: benign-echo
description: A trivially safe skill used by dctest to assert no-finding behavior.
version: 0.1.0
---

# benign-echo

This skill echoes a static greeting. It does not read files, network, or env
vars. It exists so that dctest can assert that the scanner's "no findings"
path actually works: a clean scan of this skill MUST return zero high- or
critical-severity findings.
