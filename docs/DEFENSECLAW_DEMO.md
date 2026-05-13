# DefenseClaw Demo Package

This is the shareable run-of-show for the full DefenseClaw demo package. It is
written for mixed audiences: some people may know Kubernetes but not Galileo,
some may know Splunk but not agent runtime controls, and some may be new to all
of it.

Use this document as the top-level handoff. The linked docs contain the deeper
implementation details.

## One-Sentence Story

DefenseClaw governs AI agents at runtime: it inspects prompts, completions, and
tool calls before unsafe behavior becomes an operational incident, then records
the evidence in Splunk, Agent Control, and Galileo.

## What The Demo Proves

| Claim | How the demo proves it |
| --- | --- |
| Agents need runtime governance, not just offline scanning. | A live tool request asks for a destructive Kubernetes action, and DefenseClaw evaluates it before execution. |
| Policy decisions should be visible and explainable. | Agent Control shows which control matched and why. |
| Security teams need durable operational evidence. | Splunk shows audit rows, verdicts, and dashboard pivots for the same event. |
| Governance scenarios should be repeatable. | Galileo stores prompt, dataset, and experiment evidence for the same scenarios. |
| Executives need a summarized view, not raw telemetry. | The optional Cisco Cloud Control tokenomics BFF packages token and governance signals without exposing credentials. |

## Who Should Use Which Script

| Audience | Best script | Goal |
| --- | --- | --- |
| Executives or leaders | 5-minute | Understand the value and source-of-truth split. |
| Customer / partner field team | 25-minute | See the full story with one live control path. |
| Security, platform, SRE, architects | 45-minute | Understand architecture, controls, evidence, and fallback behavior. |
| Hands-on technical team | 60-minute | Walk through commands, data paths, datasets, and troubleshooting. |

## Technology Primer

Use this section before the timed scripts when the audience is new to the
underlying tools.

| Term | Plain-English meaning | Role in this demo |
| --- | --- | --- |
| Agent | Software that can reason, call tools, and act on a user's behalf. | The agent is the thing DefenseClaw protects and observes. |
| Tool call | An action the agent wants to execute, such as running shell or `kubectl`. | The main demo blocks or flags a dangerous tool call before it runs. |
| OpenClaw | Agent runtime / gateway used in the lab. | It is where agent activity originates. |
| DefenseClaw | Governance sidecar and policy layer for agent runtimes. | It inspects prompts, responses, and tools, then records audit evidence. |
| Kubernetes / K8 | Platform for running containerized services. | The demo stack runs in an EKS cluster. |
| EKS | AWS-managed Kubernetes. | The live lab cluster is `isovalent-demo`. |
| Namespace | A Kubernetes grouping boundary. | Runtime services run in `defenesclaw`; optional Cisco Cloud Control demo runs in `defenseclaw`. |
| Agent Control | Runtime policy service for agent actions. | It evaluates whether a prompt, response, or tool step is safe. |
| Splunk Local | Local Splunk Enterprise app packaged for demo investigation. | It shows operational evidence: audit events, verdicts, dashboards, and search pivots. |
| Splunk HEC | HTTP Event Collector, a Splunk event ingestion endpoint. | DefenseClaw sends audit evidence into Splunk through HEC. |
| OTel / OpenTelemetry | Vendor-neutral telemetry format for metrics, logs, and traces. | DefenseClaw and OpenClaw emit runtime signals through OTel paths. |
| Galileo | AI evaluation and observability SaaS. | It stores prompt, dataset, and experiment evidence for Agent Watch review. |
| Dataset | A structured set of test cases. | The six Galileo datasets represent the governance scenarios. |
| Experiment | A run of a prompt/function against a dataset with metrics. | Completed Galileo experiments prove the scenarios are repeatable. |
| Cisco Cloud Control tokenomics | Optional executive API/BFF surface for token usage and governance summaries. | It packages O11y and Galileo signals for a Cisco Cloud Control-style executive app. |
| Observe mode | Log and report would-block decisions without stopping the agent. | The live demo uses `would_block=true` as evidence. |
| Action mode | Enforce blocking decisions. | Discuss as production enforcement mode after policy tuning. |

## Mental Model

The demo has four evidence layers:

```text
Agent request
  -> OpenClaw runtime
  -> DefenseClaw inspection
  -> Agent Control policy decision
  -> Evidence fan-out
       -> Splunk for operational investigation
       -> Galileo for repeatable eval / Agent Watch review
       -> Optional Cisco Cloud Control BFF for executive packaging
```

When explaining this to new audiences, keep the split simple:

| Question | Best surface |
| --- | --- |
| What did the agent try to do live? | DefenseClaw and OpenClaw |
| Which policy matched? | Agent Control |
| Where is the operational evidence? | Splunk |
| Can we repeat and review this scenario later? | Galileo |
| Can leadership see a summarized rollup? | Cisco Cloud Control tokenomics |

## Demo Surfaces

| Surface | Role in the demo | Primary doc |
| --- | --- | --- |
| DefenseClaw/OpenClaw K8 lab | Live runtime, prompt/tool inspection, audit emission | [K8 demo deployment](../deploy/k8s/defenseclaw/README.md) |
| Agent Control | Active runtime policy and matched control decisions | [K8 demo deployment](../deploy/k8s/defenseclaw/README.md#live-agent-control-and-splunk-flow) |
| Splunk Local | Operational evidence, audit rows, verdicts, and dashboards | [Splunk app](SPLUNK_APP.md) |
| Galileo Agent Watch | Prompt, datasets, Playground recipe, and completed experiments | [Galileo datasets](GALILEO_DEFENSECLAW_DATASETS.md) |
| Cisco Cloud Control tokenomics | Optional executive tokenomics BFF and governance rollup | [Cisco Cloud Control tokenomics](C3_AGENT_TOKENOMICS_GALILEO.md) |

## Environment Facts

| Item | Value |
| --- | --- |
| AWS account | `637423309390` |
| EKS cluster | `isovalent-demo` |
| Runtime namespace | `defenesclaw` |
| Optional Cisco Cloud Control namespace | `defenseclaw` |
| Galileo project | `clus-demo` |
| Galileo project ID | `0ba7b20d-8262-44c4-b230-547a0cd74b2b` |
| Galileo log stream ID | `82b893bd-fa1f-411e-81e8-e12ca66692ad` |
| Splunk local index | `defenseclaw_local` |
| Main live scenario | `defenseclaw-dangerous-tool-pre-tool` |

The namespace spelling `defenesclaw` is intentional; it matches the running lab
services and DNS names.

Some live resource names, file paths, Python modules, and demo endpoints still
use `c3` as a shorthand, for example `c3-agent-tokenomics-demo` and
`/v1/c3/agent-tokenomics/summary`. In the demo narrative, read `c3` as
Cisco Cloud Control.

Run `duo-sso` before using AWS, EKS, or in-cluster resources.

## Pre-Demo Checklist

Run these before the meeting. Do not run them for the first time live.

```bash
duo-sso
aws eks update-kubeconfig --region us-east-1 --name isovalent-demo
kubectl config current-context
kubectl -n defenesclaw get deploy defenseclaw openclaw agent-control splunk-local
kubectl -n defenseclaw get deploy c3-agent-tokenomics-demo
```

What good looks like:

| Check | Expected |
| --- | --- |
| `kubectl config current-context` | Context contains `isovalent-demo`. |
| `defenseclaw`, `openclaw`, `agent-control`, `splunk-local` | Deployments exist in `defenesclaw`. |
| `c3-agent-tokenomics-demo` | Exists in `defenseclaw` if using the optional Cisco Cloud Control segment. |

Verify Galileo dry-run planners:

```bash
python3 scripts/run_galileo_playground_experiment.py --all
python3 scripts/run_galileo_runtime_evidence_experiment.py --all
```

Open service entry points:

```bash
kubectl -n defenesclaw get svc defenseclaw-ui agent-control-ui splunk-local-ui
kubectl -n defenseclaw get svc c3-agent-tokenomics-demo
```

Credential-safe Galileo check:

```bash
kubectl -n defenesclaw get secret defenseclaw-secrets \
  -o jsonpath='{.metadata.name}:{.data.GALILEO_API_KEY}' \
  | awk -F: '{ if (length($2) > 0) print $1 ":GALILEO_API_KEY=set"; else print $1 ":GALILEO_API_KEY=missing" }'
```

Do not print API keys, Splunk HEC tokens, O11y tokens, or Agent Control API
keys in a demo.

## Primary Scenario

The anchor scenario is intentionally concrete:

```text
The agent is asked to run:
kubectl delete pods --all -n defenesclaw
```

That request is useful because everyone can understand why it is risky:

- it targets the live runtime namespace
- it is destructive
- it should require approval or a safer rollout plan
- it maps cleanly to an Agent Control policy
- it generates clear evidence in Splunk and Galileo

Expected demo outcome:

| Surface | Expected outcome |
| --- | --- |
| DefenseClaw API | Response includes `would_block=true` and `raw_action=block` in observe mode. |
| Agent Control | Matched control is `deny-dangerous-shell-pre-tool`. |
| Splunk | Search finds the audit / verdict evidence for the same decision. |
| Galileo | Dataset `defenseclaw-dangerous-tool-pre-tool` has completed runtime-evidence experiment. |

## Live Tool-Call Bridge

Use this command in the 25, 45, and 60 minute versions.

```bash
kubectl -n defenesclaw port-forward svc/defenseclaw 18970:18970
```

In another terminal:

```bash
curl -sS http://127.0.0.1:18970/api/v1/inspect/tool \
  -H 'Content-Type: application/json' \
  -d '{"tool":"shell","args":{"command":"kubectl delete pods --all -n defenesclaw"}}' | jq
```

Speaker note:

```text
We are not deleting pods here. We are asking DefenseClaw to inspect the tool
request the same way an agent hook would before execution. In observe mode,
DefenseClaw records that this would have been blocked.
```

Key fields to point out:

| Field | Meaning |
| --- | --- |
| `action` | What the hook should do in the current mode. |
| `raw_action` | The underlying policy recommendation before observe-mode downgrade. |
| `would_block` | Evidence that observe mode would have blocked in action mode. |
| `agent_control.control_name` | Which Agent Control policy matched. |
| `agent_control.action` | Agent Control's recommended action. |

## Splunk Pivot

Use this search after the live tool-call bridge.

```spl
index=defenseclaw_local source=defenseclaw
("deny-dangerous-shell-pre-tool" OR would_block=true OR raw_action=block)
| table _time sourcetype action severity target details raw_action would_block
| sort - _time
```

Speaker note:

```text
Splunk is the operational record. This is where security or operations teams
can investigate what happened, when it happened, which decision was made, and
which run/session identifiers connect the event to other runtime evidence.
```

Useful dashboards to open:

| Dashboard | What to show |
| --- | --- |
| Executive Agent Watch Overview | High-level agent sessions, deny/block signals, and investigation candidates. |
| Policy Decisions | Allow, block, deny, confirm, policies, and targets. |
| Findings And HITL | Findings by severity and human-review signals. |
| Search And Drilldown | Raw SPL pivot by run, session, or policy evidence. |

## Galileo Review Path

Galileo is the repeatable evidence layer. Do this after the live Splunk and
Agent Control flow.

1. Open project `clus-demo`.
2. Show prompt `defenseclaw-runtime-governance`.
3. Point out selected version `2`.
4. Show the prompt variables: `user_prompt`, `cluster_context`, `agent_name`, `guardrail_mode`.
5. Show the six datasets.
6. Open completed runtime-evidence experiments.
7. Use `defenseclaw-dangerous-tool-pre-tool` as the bridge back to the live demo.

Speaker note:

```text
Splunk proves what happened operationally. Galileo proves that the same
governance behavior is repeatable across a named dataset, prompt, and
experiment history.
```

Reliable runtime-evidence dry run:

```bash
python3 scripts/run_galileo_runtime_evidence_experiment.py --all
```

Live execution when credentials are available:

```bash
GALILEO_API_KEY="$(kubectl -n defenesclaw get secret defenseclaw-secrets -o jsonpath='{.data.GALILEO_API_KEY}' | base64 --decode)" \
python3 scripts/run_galileo_runtime_evidence_experiment.py --all --execute
```

Optional model-backed Playground dry run:

```bash
python3 scripts/run_galileo_playground_experiment.py --all
```

Use the model-backed path only when Galileo's configured model provider has
quota. On May 10, 2026, the configured provider returned `insufficient_quota`,
so the deterministic runtime-evidence path is the reliable live-demo path.

## Cisco Cloud Control Tokenomics Path

Cisco Cloud Control tokenomics is optional. Use it only if the audience cares
about executive packaging or agent cost / usage views.

Plain-English framing:

```text
Splunk Observability is the source of truth for token and model usage.
Galileo is the source of truth for runtime governance evidence.
Cisco Cloud Control is the management-plane experience that can consume a
server-side summary of those signals without sending O11y or Galileo
credentials to the browser.
```

Official Cisco context:

- [Cisco Cloud Control](https://cloud.cisco.com/) is presented as the future of
  unified management for Cisco products and beyond.
- [Cisco Security Cloud Control](https://www.cisco.com/c/en/us/products/collateral/security/security-cloud-control/security-cloud-control-faq.html)
  centralizes management, visibility, and automation across Cisco security
  products, including Cisco AI Defense.
- The [Security Cloud Control API](https://developer.cisco.com/docs/security-cloud-control/)
  exposes organization, user, role, network-object, and product-integration
  management through REST APIs.
- [Cisco AI Defense](https://www.cisco.com/site/us/en/products/security/ai-defense/index.html)
  focuses on AI asset discovery, risk assessment, runtime guardrails, and
  real-time mitigation of prompt injection, harmful responses, and data leakage.

How this demo fits: the current repo does not call Cisco Cloud Control APIs
directly. It provides the BFF payload shape that a Cisco Cloud Control-native
experience could consume: token usage from Splunk Observability plus runtime
governance evidence from Galileo and Agent Control.

Local fixture-backed command:

```bash
PYTHONPATH=cli python -m defenseclaw.main c3-tokenomics generate \
  --include-galileo \
  --output artifacts/c3_agent_tokenomics_with_galileo.json
```

Mock BFF command:

```bash
PYTHONPATH=cli python -m defenseclaw.c3_agent_tokenomics.mock_api --port 8787
curl 'http://127.0.0.1:8787/v1/c3/agent-tokenomics/summary?include_galileo=true'
```

What to emphasize:

| Point | Why it matters |
| --- | --- |
| Cisco Cloud Control is optional in this package. | The primary Agent Watch path is Galileo, Agent Control, and Splunk. |
| Credentials stay server-side. | Browsers and executive apps should not receive O11y or Galileo keys. |
| Cost is not billing-authoritative. | Token counts are the demo source of truth; dollars are directional. |

## 5-Minute Executive Script

Use this when the audience needs the story, not the mechanics.

| Time | Action | Speaker notes |
| --- | --- | --- |
| 0:00-0:45 | Start with the problem. | AI agents can call tools and affect production-like systems. Governance has to happen at runtime, not just during code review. |
| 0:45-1:30 | Show Splunk Local Agent Watch overview. | This is the operational view: sessions, risky activity, block/deny signals, and investigation pivots. |
| 1:30-2:15 | Describe the dangerous K8 tool request. | The agent asks for `kubectl delete pods --all -n defenesclaw`. That is understandable, risky, and should not run without controls. |
| 2:15-3:00 | Show Agent Control matched policy. | The control is explicit: `deny-dangerous-shell-pre-tool`. This makes policy explainable. |
| 3:00-4:15 | Show Galileo dataset / experiment. | The same scenario exists as repeatable Agent Watch evidence, not just a one-time live event. |
| 4:15-5:00 | Optional Cisco Cloud Control rollup. | Executives can consume a summarized view while Splunk and Galileo remain the source systems. |

Close:

```text
DefenseClaw is the runtime governance and evidence layer. Agent Control decides,
Splunk investigates, Galileo validates repeatability, and Cisco Cloud Control
can summarize.
```

Avoid in the 5-minute version:

- live shell commands
- API payload details
- model quota discussion
- Kubernetes deployment details

## 25-Minute Standard Script

Use this for a customer or partner field demo.

| Time | Action | Speaker notes |
| --- | --- | --- |
| 0:00-2:00 | Explain the problem and surfaces. | Agent runtime, runtime policy, operational evidence, repeatable eval evidence, optional executive rollup. |
| 2:00-4:00 | Explain the lab environment. | The live runtime is in Kubernetes namespace `defenesclaw`; optional Cisco Cloud Control BFF is in namespace `defenseclaw`. |
| 4:00-7:00 | Show Splunk Local overview. | Start from the dashboard because it is familiar to operations and security teams. |
| 7:00-11:00 | Run or replay the live `/api/v1/inspect/tool` bridge. | Show `would_block=true`, `raw_action=block`, and Agent Control fields. |
| 11:00-14:00 | Open Agent Control. | Show that the matched control is a named policy, not an opaque model answer. |
| 14:00-19:00 | Open Galileo Agent Watch assets. | Show project `clus-demo`, prompt `defenseclaw-runtime-governance`, and six datasets. |
| 19:00-22:00 | Review completed runtime-evidence experiment. | Anchor on `defenseclaw-dangerous-tool-pre-tool`. |
| 22:00-24:00 | Optional Cisco Cloud Control tokenomics summary. | Position it as executive packaging, not the primary evidence source. |
| 24:00-25:00 | Recap ownership split. | Agent Control decides, Splunk investigates, Galileo validates, Cisco Cloud Control summarizes. |

Required commands:

```bash
kubectl -n defenesclaw port-forward svc/defenseclaw 18970:18970
curl -sS http://127.0.0.1:18970/api/v1/inspect/tool \
  -H 'Content-Type: application/json' \
  -d '{"tool":"shell","args":{"command":"kubectl delete pods --all -n defenesclaw"}}' | jq
```

Fallback if the live API call fails:

| Failure | Fallback |
| --- | --- |
| Port-forward fails | Use the existing Splunk search and Galileo experiment as pre-recorded evidence. |
| Agent Control is unavailable | Explain `fail_mode=open` and show the expected deterministic Galileo experiment. |
| Splunk UI is slow | Use the SPL query text and saved dashboards from [Splunk app](SPLUNK_APP.md). |
| Galileo model quota unavailable | Use completed runtime-evidence experiments, not Playground execution. |

## 45-Minute Technical Script

Use this when the audience wants architecture, controls, and repeatability.

| Time | Action | Speaker notes |
| --- | --- | --- |
| 0:00-4:00 | Threat model. | Agents can receive malicious prompts, reveal sensitive outputs, and call dangerous tools. |
| 4:00-8:00 | Architecture walkthrough. | OpenClaw produces activity; DefenseClaw inspects; Agent Control evaluates; Splunk and Galileo receive evidence. |
| 8:00-12:00 | Validate the live cluster. | Show deployments and services in `defenesclaw`. |
| 12:00-18:00 | Dangerous tool live flow. | Run the API bridge, show observe-mode fields, then show Splunk and Agent Control. |
| 18:00-23:00 | Prompt injection scenario. | Use `defenseclaw-prompt-injection-pre-llm`; explain pre-LLM inspection. |
| 23:00-28:00 | PII steering scenario. | Use `defenseclaw-pii-post-llm`; explain post-LLM steering/redaction. |
| 28:00-33:00 | Ambiguous admin intent. | Explain approval-seeking behavior and human review patterns. |
| 33:00-39:00 | Galileo experiment handling. | Compare Playground/model-backed path with deterministic runtime-evidence path. |
| 39:00-43:00 | Cisco Cloud Control tokenomics BFF. | Explain O11y token source, Galileo governance enrichment, server-side credential boundary. |
| 43:00-45:00 | Failure modes. | Observe versus action mode, quota fallback, fail-open behavior, credential boundaries. |

Technical details worth explaining:

| Detail | Explanation |
| --- | --- |
| `would_block=true` | Observe mode did not stop the action, but the underlying policy would block in action mode. |
| `raw_action=block` | The raw policy verdict before observe-mode downgrade. |
| `tool/pre/deny` | The policy runs before the tool executes and recommends denial. |
| `llm/pre/observe` | Prompt injection is detected before an LLM call. |
| `llm/post/steer` | Sensitive output can be steered or redacted after generation. |
| Deterministic runtime-evidence runner | Creates repeatable Galileo evidence without external LLM quota. |

## 60-Minute Workshop Script

Use this for a hands-on or deeply technical session.

| Time | Action | Speaker notes |
| --- | --- | --- |
| 0:00-5:00 | Set goals and vocabulary. | Use the Technology Primer. Make sure everyone understands agent, tool call, policy, evidence, dataset, experiment. |
| 5:00-12:00 | Validate deployment. | Show EKS context, namespaces, deployments, services, and credential-safe checks. |
| 12:00-20:00 | Walk through the live dangerous tool flow. | Inspect request, DefenseClaw verdict, Agent Control match, Splunk evidence. |
| 20:00-28:00 | Splunk investigation. | Open Agent Watch overview, Policy Decisions, Findings/HITL, Search and Drilldown. |
| 28:00-36:00 | Galileo object model. | Explain project, prompt, variables, datasets, metrics, experiments. |
| 36:00-44:00 | Run deterministic Galileo dry-run and discuss execute path. | Use `scripts/run_galileo_runtime_evidence_experiment.py --all`. |
| 44:00-50:00 | Cover all six governance datasets. | Safe ops, prompt injection, dangerous tool, PII, ambiguous admin, grounded cluster review. |
| 50:00-55:00 | Optional Cisco Cloud Control tokenomics packaging. | Server-side BFF, O11y tokens, Galileo governance cards, no browser-side credentials. |
| 55:00-60:00 | Operational close. | Who owns each surface, what to monitor, what changes in action mode. |

Workshop exercise options:

| Exercise | Command or surface | Learning goal |
| --- | --- | --- |
| Validate cluster health | `kubectl -n defenesclaw get deploy,svc` | Understand where the lab runs. |
| Inspect a dangerous tool request | `/api/v1/inspect/tool` curl command | Understand pre-tool policy enforcement. |
| Search for evidence | Splunk SPL pivot | Understand operational audit evidence. |
| Review repeatability | Galileo runtime-evidence experiment | Understand dataset-backed governance proof. |
| Compare surfaces | Splunk vs Galileo vs Cisco Cloud Control | Understand source-of-truth boundaries. |

## Scenario Map

| Scenario | Dataset | Best surface | Control or evidence |
| --- | --- | --- | --- |
| Safe read-only K8 operations | `defenseclaw-safe-ops` | Splunk and Galileo | Expected allow. |
| Prompt injection before LLM | `defenseclaw-prompt-injection-pre-llm` | Galileo and Splunk verdicts | `observe-prompt-injection-pre-llm`. |
| Dangerous shell before tool | `defenseclaw-dangerous-tool-pre-tool` | Agent Control, Splunk, Galileo | `deny-dangerous-shell-pre-tool`. |
| PII or secret output | `defenseclaw-pii-post-llm` | Galileo and Splunk verdicts | `steer-pii-post-llm`. |
| Ambiguous admin request | `defenseclaw-ambiguous-admin-intent` | Galileo and HITL evidence | Approval-seeking behavior. |
| Grounded cluster review | `defenseclaw-grounded-cluster-review` | Galileo | `isovalent-demo`, namespace `defenesclaw`. |

## Explaining The Six Galileo Datasets

| Dataset | Plain-English explanation |
| --- | --- |
| `defenseclaw-safe-ops` | Normal read-only Kubernetes work. The agent should be allowed to inspect health or status. |
| `defenseclaw-prompt-injection-pre-llm` | User or document tries to override safety instructions before the model call. |
| `defenseclaw-dangerous-tool-pre-tool` | Agent wants to run shell or Kubernetes actions that could break the environment or expose secrets. |
| `defenseclaw-pii-post-llm` | The final answer may contain sensitive data and should be redacted or steered. |
| `defenseclaw-ambiguous-admin-intent` | The request might be legitimate, but it is risky enough to require approval and rollback context. |
| `defenseclaw-grounded-cluster-review` | The answer must stay grounded in real cluster facts and ignore unrelated Cisco Cloud Control resources. |

## Common Questions

| Question | Answer |
| --- | --- |
| Is DefenseClaw replacing Splunk? | No. DefenseClaw emits governance evidence; Splunk is the operational investigation surface. |
| Is Galileo replacing Agent Control? | No. Agent Control is the active runtime policy service; Galileo stores repeatable prompt/dataset/experiment evidence. |
| Why are there two namespaces? | `defenesclaw` contains the live DefenseClaw/OpenClaw runtime. `defenseclaw` contains the optional Cisco Cloud Control tokenomics demo. |
| Why is the namespace misspelled? | The live lab services and DNS names use `defenesclaw`, so the docs preserve that spelling. |
| Why use observe mode? | It lets teams tune policy and collect would-block evidence without disrupting the running demo. |
| What changes in action mode? | The same raw policy decision can block the tool or request instead of just logging `would_block=true`. |
| Why does Galileo have a deterministic runner? | It keeps the demo reliable when the model-backed Playground provider has no quota. |
| Does Cisco Cloud Control get direct API keys? | No. A Cisco Cloud Control browser experience should only call the server-side BFF. |

## Presenter Tips

- Start with the problem: agents can act, so governance must happen before tools execute.
- Avoid opening with architecture diagrams for non-technical audiences.
- Use the dangerous K8 action because it is easy to understand.
- Say "operational evidence" for Splunk and "repeatable experiment evidence" for Galileo.
- Do not describe Cisco Cloud Control as the source of truth; describe it as optional executive packaging.
- Avoid printing secrets or raw tokens in terminals.
- If a live step fails, pivot to completed Splunk/Galileo evidence and explain the reliability fallback.

## Share These Docs

Use this doc as the top-level handoff. Attach these supporting docs only when
the audience needs implementation detail:

- [K8 demo deployment](../deploy/k8s/defenseclaw/README.md)
- [Galileo datasets and experiments](GALILEO_DEFENSECLAW_DATASETS.md)
- [Splunk app dashboards](SPLUNK_APP.md)
- [Cisco Cloud Control tokenomics and Galileo runtime governance](C3_AGENT_TOKENOMICS_GALILEO.md)
