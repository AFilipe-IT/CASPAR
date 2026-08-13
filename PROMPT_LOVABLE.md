# Prompt para o Lovable — CVM v2 Console

Copiar o bloco abaixo (a partir de "You are building…") para o Lovable.
Está em inglês de propósito: o Lovable responde melhor, e a UI é em inglês.

---

You are building **CVM** — Configuration Vulnerability Meter — a security posture platform. This is the management console: a professional security product, not an admin template.

## What the product does

CVM measures how secure a system's configuration actually is. It assesses infrastructure across six **dimensions** (configuration, permissions, network exposure, secrets, patch level, OS hardening), scores each one, and — this is what makes it different — detects **attack chains**: combinations of individually moderate weaknesses that together create severe risk. A version-disclosure header scores 8.5 alone; combined with a reachable service running an exploitable version, it scores 9.1, because the attacker no longer has to guess.

Users are security engineers and system administrators. They open this console to answer: *how exposed am I right now, why, and what do I fix first?*

## Non-negotiable rules

These are correctness requirements, not style preferences. Getting them wrong makes the product lie to its users.

**1. Scores are risk, not health. Higher is worse.**
`0.0` = nothing found. `10.0` = critical. It is NOT a percentage and NOT a grade. Never render a score as "8.5/10 achieved", never use a progress bar that fills toward 10, never colour a high score green.

Severity bands: `0.0` None (grey) · `0.1–3.9` Low (green) · `4.0–6.9` Medium (yellow) · `7.0–8.9` High (orange) · `9.0–10.0` Critical (red).

**2. "Not assessed" is a distinct state from "clean". Three states, never two.**
Every dimension carries `status`:
- `assessed` — evaluated, found problems → show score and findings
- `clean` — evaluated, found nothing → score 0.0, explicitly marked clean
- `not_assessed` — **never ran** → neutral placeholder, dashed border, muted grey, an "Not assessed" label and a short explanation

A `not_assessed` dimension must NEVER render as `0.0`, as green, as a full circle, or as anything a user could read as "fine". In this build **configuration**, **permissions** and **network exposure** are assessed; **secrets**, **patch intelligence** and **OS hardening** are `not_assessed` — and the dashboard must look honest about that, not broken or empty. This state is a first-class part of the design, so design it properly: it should look deliberate.

**3. `null` deltas are not zero.**
`delta: 0.0` means "unchanged". `delta: null` means "no comparable previous measurement". Show `0.0` as a neutral "no change" and `null` as "—" or "first assessment". Never render `null` as 0.

**4. Attack chains are not a list of findings.**
They are the product's signature feature. A chain must be shown as a **composition**: its steps in order, what each step contributes (`role`), and why the combination is worse than the parts. A plain table of chain names wastes the most distinctive thing here.

## Data contract

Build against these exact shapes. Use realistic mock data matching them.

`GET /api/v1/posture`:
```json
{
  "overall": { "score": 8.5, "severity": "High", "delta": -0.4,
    "driver": { "kind": "finding", "dimension": "configuration", "label": "ServerTokens = Full", "finding_id": "3f2b1c9a" } },
  "coverage": { "dimensions_total": 6, "dimensions_assessed": 3, "percent": 50 },
  "dimensions": [
    { "id": "configuration", "label": "Configuration", "status": "assessed", "score": 8.5, "severity": "High",
      "weight": 0.35, "findings_count": 23, "critical_count": 2, "delta": -0.4, "assessed_at": "2026-08-12T14:32:00Z" },
    { "id": "permissions", "label": "Identity & Permissions", "status": "assessed", "score": 6.2, "severity": "Medium",
      "weight": 0.30, "findings_count": 8, "critical_count": 0, "delta": 0.0, "assessed_at": "2026-08-12T14:32:00Z" },
    { "id": "exposure", "label": "Network Exposure", "status": "assessed", "score": 7.4, "severity": "High",
      "weight": 0.35, "findings_count": 11, "critical_count": 1, "delta": 1.2, "assessed_at": "2026-08-12T14:32:00Z" },
    { "id": "secrets", "label": "Secrets", "status": "not_assessed", "score": null, "severity": null, "weight": null, "findings_count": null, "critical_count": null, "delta": null, "assessed_at": null },
    { "id": "patch", "label": "Patch Intelligence", "status": "not_assessed", "score": null, "severity": null, "weight": null, "findings_count": null, "critical_count": null, "delta": null, "assessed_at": null },
    { "id": "hardening", "label": "OS Hardening", "status": "not_assessed", "score": null, "severity": null, "weight": null, "findings_count": null, "critical_count": null, "delta": null, "assessed_at": null }
  ],
  "chains": { "active_count": 6, "highest_score": 9.1, "exceeds_overall": true },
  "totals": { "targets_assessed": 12, "rules_evaluated": 514, "findings_open": 42, "critical_findings": 3, "related_cves": 6 },
  "scoring_model": { "version": "2.0", "aggregation": "weighted", "missing_dimension_policy": "excluded" },
  "manifest": { "cvm_version": "2.0.0", "db_sha256": "f595efe56da0", "scoring_model_version": "2.0" },
  "assessed_at": "2026-08-12T14:32:00Z"
}
```

A **finding**:
```json
{
  "id": "3f2b1c9a", "dimension": "configuration", "target": "apache-httpd", "target_label": "Apache HTTPD",
  "identifier": "ServerTokens", "observed_value": "Full", "expected_value": "Prod",
  "score": 8.5, "severity": "High",
  "title": "Server version disclosed in HTTP responses",
  "impact": "Reveals the exact Apache version to any client, letting an attacker match known exploits without probing.",
  "recommendation": "Set ServerTokens to Prod in the main configuration.",
  "evidence": { "kind": "config_file", "location": "/etc/apache2/apache2.conf", "line": 142, "snippet": "ServerTokens Full" },
  "cves": ["CVE-2023-25690"], "in_chains": ["chain-rce-escalation-03"], "status": "open"
}
```
`evidence.kind` varies by dimension and the UI shows provenance accordingly:
`config_file` (location + line + snippet) · `file_metadata` (path + mode + owner) · `listening_socket` (tcp/0.0.0.0:6379 + process) · `package` (name + installed_version + fixed_version).

The three assessed dimensions produce visibly different evidence — the detail panel must render each properly, not force all three into a "file + line" layout:

```json
{
  "id": "9d1f4e2c", "dimension": "exposure", "target": "redis", "target_label": "Redis",
  "identifier": "tcp/0.0.0.0:6379", "observed_value": "0.0.0.0 (all interfaces)", "expected_value": "127.0.0.1",
  "score": 9.4, "severity": "Critical",
  "title": "Redis listening on all network interfaces without authentication",
  "impact": "Any host that can route to this machine can read and write the entire dataset, and Redis commands allow writing files to disk.",
  "recommendation": "Bind Redis to 127.0.0.1, or restrict access at the firewall and enable requirepass.",
  "evidence": { "kind": "listening_socket", "location": "tcp/0.0.0.0:6379", "process": "redis-server", "pid": 1412 },
  "cves": [], "in_chains": ["chain-data-exfiltration-01"], "status": "open"
}
```

```json
{
  "id": "5a8c3b7d", "dimension": "permissions", "target": "ubuntu", "target_label": "Ubuntu",
  "identifier": "/etc/shadow", "observed_value": "0644 root:root", "expected_value": "0640 root:shadow",
  "score": 7.8, "severity": "High",
  "title": "Password hash file readable by all local users",
  "impact": "Any local account can read every password hash on the system and attempt offline cracking.",
  "recommendation": "Run: chmod 0640 /etc/shadow && chown root:shadow /etc/shadow",
  "evidence": { "kind": "file_metadata", "location": "/etc/shadow", "mode": "0644", "owner": "root", "group": "root" },
  "cves": [], "in_chains": ["chain-local-escalation-02"], "status": "open"
}
```

An **attack chain**:
```json
{
  "id": "chain-rce-escalation-03",
  "title": "Version disclosure on an exposed service enables targeted exploitation",
  "score": 9.1, "severity": "Critical", "active": true, "amplification": 1.4,
  "exceeds_overall": true, "cross_dimension": true,
  "narrative": "Apache discloses its exact version, the service answers on every interface, and the running version has a public RCE. An attacker does not need to fingerprint anything — the banner names the exploit to use, and the port is already open.",
  "steps": [
    { "order": 1, "finding_id": "7c4e2a1b", "dimension": "exposure", "identifier": "tcp/0.0.0.0:80", "score": 5.2, "role": "Service reachable from any network" },
    { "order": 2, "finding_id": "3f2b1c9a", "dimension": "configuration", "identifier": "ServerTokens", "score": 8.5, "role": "Reveals the exact version to every client" },
    { "order": 3, "finding_id": "b4e91d70", "dimension": "permissions", "identifier": "/var/www:mode", "score": 6.9, "role": "Web root writable by the service account, turning code execution into persistence" }
  ]
}
```

A chain spanning all three assessed dimensions is the product's strongest argument — design the chain view so that this reads clearly, with each step visibly tagged by its dimension (icon + colour) so the crossing is obvious at a glance:

```json
{
  "id": "chain-local-escalation-02",
  "title": "World-readable hashes on a host with a permissive sudo policy",
  "score": 8.7, "severity": "High", "active": true, "amplification": 1.2,
  "exceeds_overall": false, "cross_dimension": false,
  "narrative": "Every local account can read the password hashes, and a successful crack lands on an account that can escalate without re-authenticating.",
  "steps": [
    { "order": 1, "finding_id": "5a8c3b7d", "dimension": "permissions", "identifier": "/etc/shadow", "score": 7.8, "role": "Hashes readable by any local user" },
    { "order": 2, "finding_id": "c07a5f31", "dimension": "permissions", "identifier": "sudoers:NOPASSWD", "score": 6.5, "role": "Cracked account escalates without a password prompt" }
  ]
}
```

## Pages

1. **Overview** — the main screen. Overall score + what drives it; the six-dimension composition (two assessed, four not); coverage; KPI row (targets, rules evaluated, open findings, critical, attack chains, related CVEs); score over time; top findings; top attack chains; assessed technologies; recent activity. Footer strip with provenance: last assessment time, knowledge base + its sha256 hash, coverage, engine version, scoring model version.
2. **Dimensions** — one card per dimension leading to a detail view: score, trend, severity breakdown, its findings. The three assessed ones (Configuration, Identity & Permissions, Network Exposure) are full detail views. The three `not_assessed` ones show what they *would* measure and that they haven't run.

   Each assessed dimension has its own character and its detail view should reflect it: Configuration is directive-centric (file + line + snippet), Identity & Permissions is filesystem-centric (path, mode, owner, and the `chmod`/`chown` that fixes it), Network Exposure is service-centric (listening address, port, bound interface, owning process — and whether the port is reachable beyond localhost). Network Exposure benefits from a compact port/service table as well as a findings list.
3. **Findings** — filterable table (dimension, target, severity, has CVE, in chain, free text). Row expands or opens a detail panel with impact, recommendation, evidence with the exact location, CVE references, and which chains it belongs to.
4. **Attack Chains** — the showcase page. Each chain rendered as an ordered composition of its steps, with the narrative, the amplification, and clear marking when it's `cross_dimension` or `exceeds_overall`.
5. **Targets** — the twelve assessed technologies as cards with their brand glyph, score, findings count, benchmark source.
6. **Watch** — continuous monitoring: active sessions, live/stale state, events as configuration changes trigger re-assessment, score sparkline.
7. **Reports** — generate and export (JSON, SARIF, HTML).
8. **Settings** — theme, API, knowledge base info (read-only).

## Visual direction

Professional security tooling — the register of Grafana, Snyk, Datadog. Dense with information but calm; a security engineer looks at this for hours. Restrained, not playful. No gradients on cards, no glassmorphism, no decorative illustration.

**Light theme is the default and primary. Dark theme must be equally finished** — define both as CSS custom properties and switch at token level, never per-component.

Exact palette (light):
```
--bg: #F6F8FB          background
--panel: #FFFFFF       cards
--panel-alt: #F3F5F9   supporting areas inside a card
--border: #E5E7EB
--text: #111827        --text-muted: #6B7280   --text-faint: #9CA3AF
--accent: #3B82F6      --accent-hover: #2563EB
severity:  none #9CA3AF · low #22C55E · medium #EAB308 · high #F59E0B · critical #EF4444
KPI accents (identity, not severity): blue #3B82F6 · teal #14B8A6 · orange #F97316 · purple #A855F7 · red #EF4444 · amber #F59E0B
```

Severity colours are **reserved for state**. Never reuse them as chart series colours — red must mean "critical" everywhere in the console, consistently.

Typography: Inter (or a close geometric sans). Numbers in a tabular-figures font so columns of scores align. Scores are the largest type on the page — they are the product.

Cards: white, 1px `--border`, ~12px radius, very subtle shadow. Generous internal padding. Section headers small, uppercase, letter-spaced, muted.

## Technology icons

Each target has an `icon_key` mapping to a glyph and its brand colour. Render as a rounded square with the brand colour at ~12% opacity as background and the glyph in full brand colour. In dark mode the glyph colour lightens (given in brackets).

| icon_key | Technology | Colour (dark) | Glyph |
|---|---|---|---|
| `apache` | Apache HTTPD | `#D22128` (`#F87171`) | feather |
| `nginx` | nginx | `#009639` (`#4ADE80`) | server |
| `docker` | Docker | `#2496ED` (`#60A5FA`) | container/box |
| `dockerfile` | Dockerfile | `#2496ED` (`#60A5FA`) | file-code |
| `kubernetes` | Kubernetes | `#326CE5` (`#818CF8`) | boxes |
| `mysql` | MySQL | `#00758F` (`#22D3EE`) | database |
| `postgres` | PostgreSQL | `#336791` (`#7DD3FC`) | database |
| `redis` | Redis | `#DC382D` (`#FB7185`) | database |
| `ssh` | SSH | `#4B5563` (`#9AA5B4`) | terminal / key |
| `ubuntu` | Ubuntu | `#E95420` (`#FB923C`) | server |
| `tomcat` | Apache Tomcat | `#BF9600` (`#FCD34D`) | server |
| `azure` | Azure IaC | `#0078D4` (`#38BDF8`) | cloud |

Brand colour is **identity, not severity** — Redis stays red even when its score is 0. The score next to it carries the state.

Dimension icons (use the accent palette, not severity colours): configuration → sliders · permissions → key/lock · exposure → globe/radio · secrets → eye-off · patch → package · hardening → shield.

## Charts

Use Recharts. Thin marks, recessive grids, no 3D, no donut hole filled with decoration.

- **Overall score**: a large radial/arc gauge. It must read as risk — the arc fills toward critical, coloured by severity band, with the numeral dominant.
- **Dimension composition**: horizontal bars, one per dimension, each in its severity colour, with the four not-assessed rows rendered as dashed empty tracks labelled "Not assessed" — not zero-length bars.
- **Score over time**: line chart. **If the scoring model version changes mid-series, draw a vertical boundary marker with a label** — never connect points computed by different models with an unbroken line.
- **Severity distribution**: donut, severity colours, with counts.
- **Sparklines** in target cards and watch sessions.

Every chart needs a hover tooltip. Charts get a legend when they carry more than one series.

## Details that matter

- Empty states are designed, not blank: what the section would show and how to make it appear.
- Loading states are skeletons matching the final layout, not spinners.
- The whole console is responsive; tables scroll horizontally inside their own container rather than breaking the page.
- Every score is accompanied by its severity label — colour alone must never be the only carrier of meaning.
- Timestamps show absolute time on hover, relative in the label.
- The footer provenance strip is a real feature, not decoration: it proves the numbers are reproducible (engine version + knowledge base hash + scoring model version).

Build the full console with realistic mock data across all pages. Make it look like a product a security team would pay for.

---

# Iteration prompt — send this AFTER the first generation

Copiar o bloco abaixo (a partir de "The current build is functionally correct…")
como segunda instrução ao Lovable, com a **imagem de referência anexada**.

O registo mudou de propósito: a primeira ronda foi um brief de design e o
resultado foi um redesenho. Esta é uma lista de correcções — instruções, não
inspiração.

---

The current build is functionally correct: the score semantics, the `not_assessed` state, the attack-chain composition view and the provenance footer are all right. **Keep all of that behaviour exactly as it is.** This iteration is about layout density and about matching the attached reference image. Do not redesign anything.

## Rule for this iteration

The attached image is a **specification, not inspiration**. Match its visual hierarchy, card sizes, spacing, information density and chart choices. Where this instruction and your own design judgement disagree, follow the instruction. Do not simplify components, do not increase whitespace, do not substitute chart types, and do not "clean up" the layout.

The current build reads as a generic SaaS dashboard: large cards, wide spacing, few elements per screen. The target is a **technical security console**: compact, dense, many values visible without scrolling. Think of a monitoring console an operator keeps open all day, not a marketing dashboard.

## 1. Density — the main change

Reduce vertical space so the Overview fits roughly one and a half screens instead of three.

- Card padding: reduce by about a third. Section headers small, uppercase, letter-spaced, tight against their content.
- KPI row: compact tiles in a single row — label, number, one line of sub-text. No sparkline inside the KPI tiles.
- Dimension rows: one line each. Icon, name, score, severity badge, weight, delta, sparkline — all on the same row, vertically centred. No sub-lines wrapping underneath, no full-width progress bar dominating the row.
- Remove the standalone "Coverage" card. Coverage belongs in the footer strip, which already carries it.
- The "Primary driver" block becomes one compact line inside the overall-risk card, not a separate panel.
- Tables: tighter row height, smaller type, more rows visible.

## 2. Add the radar chart — it is missing

The reference image has a **radar / spider chart** ("Postura de Segurança" / "Security posture") showing all six dimensions on one polygon. The current build does not have it and it must be added to the Overview, beside the dimension list.

- One axis per dimension, in this order clockwise from top: Configuration, Secrets, Network Exposure, Platform Hardening, Software & Patch, Permissions.
- Scale 0 at the centre to 10 at the outer ring, with rings labelled 0 / 2.5 / 5 / 7.5 / 10.
- A single filled polygon: red/orange stroke, same colour at low opacity as fill.
- Dimensions that are `not_assessed` have no value — the polygon does not pass through them at zero, because zero would read as "clean". Break the polygon there, or draw those axes greyed with an explicit "not assessed" marker. **Never plot a not-assessed dimension as 0.**

## 3. Score-over-time chart — shrink it

The scoring-model boundary is currently a full-width chart with its own explanatory subtitle and a two-colour split series. That is far too much space for an edge case.

- Make it a normal single-series line chart, same compact size as the other Overview panels.
- Keep the rule that points from different scoring models are never joined by a line — but express it as a thin dashed vertical marker with a small label, nothing more. No subtitle explaining the concept, no separate legend for the two model segments.

## 4. Fix the mock-data inconsistencies

The same numbers must agree across every screen:

- Overview says `OPEN FINDINGS 42` and `CRITICAL 3`; the Findings page says `24 open` with 4 critical; the severity donut says 24. Pick one set and use it everywhere: **24 open findings, 4 critical**.
- The Attack Chains page header says `HIGHEST CHAIN RISK 9.1` but lists a 9.5 chain first. Make it **9.5**.
- Dimension label: use **"Configuration"** everywhere (not "Configuration Security").
- Targets: the twelve are exactly `apache-httpd`, `nginx`, `ssh`, `mysql`, `postgresql`, `redis`, `tomcat`, `docker`, `dockerfile`, `kubernetes`, `azure-iac`, `ubuntu`. The Dockerfile benchmark is a curated CIS ruleset, not "CVM Container Build Rules".

## 5. What must not change

Do not touch any of this — it is already correct:

- Higher score = worse; the severity bands and their legend.
- `not_assessed` as a distinct state, with its explanation text and "What it would measure" link. Never rendered as 0 or green.
- `delta: null` shown as "—", distinct from `0.0` "no change".
- The attack-chain composition view: steps as cards with dimension, technology, score and role; the amplification; and the closing sentence comparing the worst step to the chain score.
- The provenance footer strip on every page.
- Evidence rendered per kind: config directive with file and line, listening socket with process, file metadata with mode and owner.
- The brand colours and glyphs for the twelve technologies.
