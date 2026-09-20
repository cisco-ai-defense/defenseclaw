# Cloud production protection

This opt-in guardrail profile extends the embedded balanced defaults and blocks
statically proven destructive AWS, Google Cloud, and Azure CLI actions. Apply it
only to connectors whose cloud credentials or execution context can reach
production. DefenseClaw deliberately does not infer production from a resource
name such as `prod`; the connector's assigned rule pack is the trust boundary.

The rules are semantic-only. They require complete executable `ActionFacts` and
a same-rule code-owned proof. Quoted examples, help text, incomplete shell
syntax, dynamic expansion, and unsupported CLI forms cannot authorize a block.

Covered v1 operations include recursive object deletion, object-batch deletion,
bucket or storage-account deletion, managed database deletion, project/resource
group deletion, compute-instance termination, cluster deletion, and stack
deletion. It also blocks the closed, literal AWS CloudTrail stop/delete and GCP
Cloud Audit Activity log-deletion grammars owned by ActionFacts. Unrecognized
provider operations remain outside the blocking claim.
