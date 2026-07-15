# Security model

run receives a read-only repository mount and private writable scratch. run_write and apply_patch receive a writable registered workspace while .git, credentials, sockets, policy, and configuration paths remain protected. Workers have private networking and cannot use host loopback, host Unix sockets, credentials, container sockets, ptrace, mounts, BPF, or privileged namespace creation.

AXIS provenance is pinned to commit e32f69b3c411f25975940cbcfd1101a3682783c9. The build uses a reviewed Cargo.lock; it does not claim signed, offline, or byte-for-byte reproducible artifacts.
