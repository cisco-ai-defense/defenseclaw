# Agent Substrate on EKS: example files

Used by the [EKS guide](../../../../docs-site/content/docs/substrate/eks.mdx) (published as `/docs/substrate/eks`). They were run on a
real EKS cluster with Agent Substrate v1.0.0 and both sandbox classes. They are examples, not a supported installer: upstream has no
EKS profile yet.

| File | What it is |
|---|---|
| `eks-overlay.patch` | A patch for the Substrate v1.0.0 tag. It changes the kind overlay (`manifests/ate-install/kind`) to use S3 with the node role instead of the test object store, and to use the EKS image credential provider so actors can run ECR images. The region lines in the context are `us-east-1`; edit them to your region before applying |
| `substrate-install.yaml` | The `SubstrateInstall` file for `ate-setup`. Replace `BUCKET` |
| `stage-assets.sh` | Uploads the microVM assets to the bucket and applies the microVM sandbox config |

## Use

```sh
git clone --depth 1 --branch v1.0.0 https://github.com/agent-substrate/substrate.git && cd substrate
git apply /path/to/eks-overlay.patch              # after setting your region in the patch
sed -i 's/BUCKET/my-snapshots/' /path/to/substrate-install.yaml
ate-setup --kind --context MY_EKS_CONTEXT --config /path/to/substrate-install.yaml deploy ate-system --sandbox-classes gvisor
```

For microVM nodes, then run `ate-setup ... deploy sandboxconfig --sandbox-classes gvisor,microvm` (expect it to fail at the last step),
and `BUCKET=my-snapshots SUBSTRATE_DIR=$PWD ./stage-assets.sh`.

Build `ate-setup` from the same tag as the manifests; upstream publishes no binary. To set a unique actor-token issuer, add
`--actor-jwt-issuer https://UNIQUE-HOST` to `ate-setup ... deploy apiserver`.
