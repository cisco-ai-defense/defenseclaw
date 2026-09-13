# Cloud-share same-operation control fixture

This directory contains a three-row, normalized test fixture for
`benchmark_normalize_cloud_share_controls.py`. It preserves the bounded AWS
request/result shapes needed by the parser while excluding credentials,
principal details, source addresses, user agents, TLS metadata, and plaintext
error messages. It is not the benchmark corpus and must not be used as an FPR
denominator.

The complete download-only normalization uses these pinned public sources:

- Elastic AWS CloudTrail fixtures at revision
  `f79b2e9c59de04d980d0bb087421f2c2b1a9cd8d` (Elastic-2.0):
  <https://github.com/elastic/integrations/tree/f79b2e9c59de04d980d0bb087421f2c2b1a9cd8d/packages/aws/data_stream/cloudtrail/_dev/test/pipeline>
- CybersecJSONSchemaBench CloudTrail v6 at revision
  `f90172fc32a3900e97f63bd30538abcc9565f238` (`other`; see the dataset card
  for its flAWS and synthetic-chain provenance):
  <https://huggingface.co/datasets/achinta3/cybersec-jsonschemabench-cloudtrail-v6/tree/f90172fc32a3900e97f63bd30538abcc9565f238>
- TrailDiscover at revision
  `f96cbdb0591f78d16b1948e84c211becce6258e6` (CC-BY-4.0):
  <https://github.com/adanalvarez/TrailDiscover/tree/f96cbdb0591f78d16b1948e84c211becce6258e6>

The complete corpus contains eight scoreable negative controls: three
successful permission removals and five argument-complete failed operations.
Two additional failed operations have no request parameters and are retained
only as parser controls with `applicability=out_of_scope`. Eight observations
are too few for a production false-positive-rate claim.

Labels are deterministic projections of source arguments and outcomes. No LLM
labels are used.
