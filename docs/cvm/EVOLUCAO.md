# Configuration Vulnerability Meter (CVM)
## Evolution Specification for Claude Code

> **Purpose**
>
> This document explains the evolution of the existing CASPAR proof of concept into the new **Configuration Vulnerability Meter (CVM)** platform. It should be used as architectural guidance. The objective is **not** to rewrite everything from scratch, but to preserve the existing technical assets while reorganising them into a modular and extensible platform.

---

# Project Philosophy

The existing implementation already contains the core scientific contribution:

- automated knowledge construction;
- CCSS-based scoring engine;
- deterministic runtime evaluation;
- attack chain evaluation;
- structured knowledge base.

These components remain valid and should be preserved.

The evolution consists of transforming the current proof of concept into a complete security platform called **Configuration Vulnerability Meter (CVM)**.

The emphasis is no longer on "operationalising CCSS", but on delivering a platform capable of measuring the vulnerability introduced by configuration choices.

---

# Product Vision

The Configuration Vulnerability Meter is a platform that measures the vulnerability of system configurations.

Unlike traditional compliance scanners, it does not simply determine whether a recommendation is satisfied.

Unlike vulnerability scanners, it does not search for software vulnerabilities.

Instead, it quantifies how vulnerable a system becomes because of its configuration.

The platform must support assessments at multiple levels:

- Individual configuration file.
- Individual service.
- Operating system.
- Cluster.
- Infrastructure.

The same scoring model should apply consistently across all levels.

---

# Preserve Existing Assets

The following components already implemented in CASPAR should be migrated with minimal changes:

## Build-time

- LLM processing.
- RAG.
- Benchmark ingestion.
- Rule extraction.
- SQLite knowledge base.
- CCSS vectors.

## Runtime

- Configuration parsers.
- Rule matching.
- CCSS scoring.
- Attack chain evaluation.
- Report generation.

These components become part of the CVM Core.

---

# New Product Architecture

```
Configuration Vulnerability Meter

├── Dashboard
├── CLI
├── REST API
│
├── CVM Core
│   ├── Assessment Engine
│   ├── Scoring Engine
│   ├── Aggregation Engine
│   ├── Attack Chain Engine
│   ├── Knowledge Engine
│   └── Reporting Engine
│
├── Plugins
│   ├── Apache
│   ├── SSH
│   ├── Docker
│   ├── Kubernetes
│   ├── Azure
│   └── ...
│
└── Knowledge Base
```

---

# Interfaces

The platform exposes **two first-class interfaces**.

## CLI

The CLI is a primary interface.

It must remain fully supported.

Typical users:

- DevSecOps
- CI/CD
- Automation
- Terminal users

The CLI should expose every platform capability.

Examples:

```bash
cvm assess apache.conf

cvm assess server/

cvm build apache

cvm report results.json
```

---

## Dashboard

The dashboard has **exactly the same importance as the CLI**.

It is **not** a simplified interface.

Instead, it offers richer visualisation and exploration capabilities.

Typical users:

- Security analysts
- Auditors
- Administrators
- SOC teams

The dashboard should visualise exactly the same information exposed by the CLI, but with additional navigation, filtering and aggregation.

---

# Core Principles

The CLI and Dashboard must use the same backend.

Neither interface contains business logic.

All business logic belongs to the CVM Core.

Both interfaces must always produce identical assessment results.

---

# Assessment Levels

The platform must support hierarchical evaluation.

```
Infrastructure
    │
Operating System
    │
Service
    │
Configuration File
    │
Configuration Rule
```

Each level produces:

- score;
- severity;
- recommendations;
- evidence;
- explanation.

---

# Dashboard Features

The dashboard should provide:

- Overall Configuration Vulnerability Score;
- Service scores;
- Host scores;
- Infrastructure score;
- Findings explorer;
- Rule details;
- Attack chains;
- Benchmark information;
- Knowledge base explorer;
- Report generation.

The dashboard must never hide technical details.

Instead, it should make them easier to understand.

---

# CLI Features

The CLI should support:

- assessment;
- report generation;
- benchmark management;
- knowledge management;
- export;
- scripting;
- CI/CD integration.

The CLI remains the preferred interface for automation.

---

# Plugin Architecture

Technology-specific logic must live inside plugins.

The CVM Core must never contain Apache-, SSH- or Kubernetes-specific logic.

Plugins are responsible for:

- parsing;
- normalisation;
- benchmark mapping.

The Core only understands abstract concepts such as Rules, Findings, Scores and Recommendations.

---

# Overall Goal

Transform the existing CASPAR implementation into a modular, extensible and production-oriented Configuration Vulnerability Meter while preserving the scientific foundation already developed.

The implementation should prioritise clean architecture, modularity, extensibility and long-term maintainability over short-term feature additions.
