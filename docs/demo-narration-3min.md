# MyAgent — 3:20 Demo Script

> Slide cues + live demo + voiceover. Focus: user experience, security, enterprise value.
> Don't dwell on internal tech (LiteLLM, Hermes, SR) — talk about what they DO, not what they ARE.

---

## Recording Setup

**Screen capture**: QuickTime → New Screen Recording (Retina, 60fps)
**Audio**: Record voiceover separately for clean audio
**Tip**: Pre-run setup once so everything is cached, then uninstall and re-record at 2x speed.

---

## [0:00–0:15] SLIDE 1: Title

**[Show: Slide 1 — "MyAgent" title]**

> "Today I want to show you MyAgent — a new way to bring AI to every employee's desktop, with enterprise security built in from day one.
>
> One command installs everything. The agent runs in a complete sandbox with zero access to the system. And the user gets a native macOS experience — right from the menu bar."

---

## [0:15–0:22] SLIDE 2: The Challenge

**[Show: Slide 2 — 5 bullet points]**

> "Today, our AI agent runs on Kubernetes — significant infrastructure and operational cost to maintain and manage each agent instance at scale. And to use it, employees have to navigate to a specific website or open a Webex channel. It's not where they work — it's another tab, another context switch.
>
> What if the agent lived on the user's own machine? No infrastructure. No Kubernetes. No cloud hosting cost. And available instantly from a hotkey — not a browser tab."

---

## [0:22–0:50] LIVE DEMO: One-Command Install

**[Switch to: Terminal]**

```
defenseclaw setup it-governed --yes
```

**[Speed up to 2x — show credentials flowing, installs happening]**

> "One command. It prompts for your enterprise credentials — Circuit API for the LLM, Atlassian for Jira, Microsoft Graph for Outlook. Each validated and stored securely.
>
> Then it installs the agent in a fully sandboxed mode. A hardened Docker container — no host filesystem access, no network access from the container, all privileges dropped. The agent cannot touch anything on the system.
>
> Seventy-eight enterprise skills are deployed automatically — email, calendar, Jira, Webex, Workday, meeting prep, weekly digests — ready out of the box.
>
> For IT teams — this same command runs through Jamf or Intune. Pre-seed credentials in a config profile. Push to the fleet. Zero user interaction."

---

## [0:50–0:55] SLIDE 3: One Command Summary

**[Show: Slide 3 — checkmarks]**

> "One command — credentials, agent, sandbox, seventy-eight skills, security rules — all done."

---

## [0:55–1:10] LIVE DEMO: Start

**[Switch to: Terminal]**

```
defenseclaw-gateway start
```

**[Show log output — services starting]**

> "One more command starts everything. The gateway brings up the full stack — the LLM proxy with smart model routing, the integration gateway for Jira, Outlook, Webex — and the agent itself. All managed as one service."

---

## [1:10–1:15] SLIDE 4: Architecture

**[Show: Slide 4 — block diagram]**

> "The architecture. MyAgent at the top — sandboxed by macOS. The agent in Docker — sandboxed. The gateway managing models, integrations, and security below."

---

## [1:15–2:00] LIVE DEMO: User Experience + Routing

**[Switch to: macOS desktop with Slack, browser visible]**

> "Now — what the user sees."

**[Press Option+Space — command bar appears]**

> "Option-Space from anywhere. A floating command bar — like Spotlight, but for your AI agent."

**[Type: "What are my priority emails today?" → response streams]**

> "I ask about priority emails. The agent checks my Outlook inbox — using my credentials, on my machine — and surfaces what matters."

**[Press Option+Space again — expands to full window]**

> "Option-Space again — full resizable window."

**[Switch to Slack — notification appears — click it back]**

> "Switch away — macOS notification when it's done. Click to return."

**[Now routing demo — type: "Write a Python function to merge two sorted lists"]**

> "Now watch the smart routing. A coding question —"

**[Show log: `[SR] → coding-model (gpt-5-5)`]**

> "— automatically sent to the best coding model."

**[Type: "Compare the tradeoffs of microservices vs monolith"]**

**[Show log: `[SR] → reasoning-model (o3)`]**

> "A reasoning question — routed to the analysis model. Same interface. Different model underneath. Chosen automatically based on what you're asking."

---

## [2:00–2:05] SLIDE 5: UX Summary

**[Show: Slide 5]**

> "Native. Fast. Non-intrusive. The right model for every question."

---

## [2:05–2:35] SLIDE 6: Three-Layer Security

**[Show: Slide 6 — three columns]**

> "Security. Three independent layers.
>
> First — the MyAgent app is macOS sandboxed. It cannot read files, launch apps, or access anything on the system. It only connects to the local agent.
>
> Second — the agent itself runs inside a hardened Docker container. No filesystem access. No network. All capabilities dropped. Every command it runs is fully contained.
>
> Third — DefenseClaw's guardrail engine inspects every tool call in real-time. Prompt injection — blocked. Sandbox escape — blocked. Config tampering — detected and logged.
>
> And here's the key —"

**[Point to bottom box]**

> "All integrations — Outlook, Jira, Webex — authenticate on the user's own machine, using their own login session from their Cisco-managed device. Tokens never leave the device. No cloud relay. No third-party sees your data."

---

## [2:35–2:45] SLIDE 7: MCP Gateway

**[Show: Slide 7]**

> "Confluence, Jira, Outlook, Webex — connected through one local gateway. All apps the user is already logged into on this machine. Seventy-eight enterprise skills — meeting prep, sprint reports, weekly digests, time-off requests — ready instantly."

---

## [2:45–3:00] SLIDE 8: MDM Deployment

**[Show: Slide 8]**

> "For IT — push via Jamf or Intune. Config profile with credentials. The setup command runs silently. Users get a menu bar icon and a hotkey. No training. IT controls which models, which integrations, which policies — with full audit."

---

## [3:00–3:20] SLIDE 9: Closing

**[Show: Slide 9]**

> "One command to install. One service to run. One hotkey for the user.
>
> The agent is sandboxed — zero system access. All enterprise apps connected through one local gateway on the user's own secure device. Three layers of security. Seventy-eight skills out of the box.
>
> This is MyAgent — enterprise AI, sandboxed and secure, one Option-Space away.
>
> Thank you."

---

## Post-Production

**Record in this order:**
1. Live demo clips (terminal + MyAgent interaction)
2. Slide segments (presentation mode screen capture)
3. Voiceover as one continuous take
4. Combine in iMovie or Keynote

**Tips:**
- 2x speed for install segment
- Terminal font 16pt+
- Turn on Do Not Disturb except MyAgent
- Close Notification Center before recording
