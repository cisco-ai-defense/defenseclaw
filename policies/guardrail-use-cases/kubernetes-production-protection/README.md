# Kubernetes production protection

This opt-in guardrail profile extends the embedded balanced defaults and blocks
an exact named Secret content read, statically proven namespace deletion, and
closed forms of bulk workload deletion through `kubectl` or `oc`. Assign it only
to connectors whose Kubernetes context can reach production; cluster and
namespace names are not treated as production evidence.

The v1 block claim covers a direct authenticated read of one literal named
Secret's content, deletion of a named namespace, and `delete --all` for the
closed resource set in the semantic owner. Secret metadata/listing, dynamic or
batch Secret selection, single-resource deletion, manifest-driven deletion,
help, dry runs, quoted examples, dynamic operands, and unsupported option
grammars do not block.
