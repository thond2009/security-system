# Security Management System for Yocto-Based Embedded Linux

## Overview

A security management system for companies building embedded Linux OS images using Yocto Project. Provides automated CVE vulnerability tracking and security hardening compliance monitoring, integrated into the CI/CD pipeline with a central web dashboard.

### Motivation

- Yocto's built-in `cve-check` relies on NVD which has API reliability and rate-limiting problems
- Security hardening (CIS benchmarks, custom policies) needs automated, repeatable verification
- Multiple product teams need centralized visibility into security posture

## Architecture

```
CI Build Server                    Dashboard Server
┌──────────────────────┐          ┌──────────────────────────┐
│ BitBake Build        │          │ FastAPI Backend           │
│  │                   │  HTTPS   │  │  Celery Workers        │
│  ▼                   │ ──────►  │  │  APScheduler (cron)    │
│ security-check.bbclass│          │  │  PostgreSQL             │
│  │                   │          │  ▼                        │
│  ▼                   │          │ React Frontend            │
│ security-report.py   │          └──────────────────────────┘
│  ├─ SPDX SBOM parse  │                    ▲
│  ├─ PURL mapping     │                    │
│  ├─ OSV API query    ├────────────────────┘
│  ├─ Version match    │        (REST API)
│  ├─ Hardening engine │
│  └─ Upload to API    │
└──────────────────────┘
```

## Key Design Decisions

### 1. OSV.dev as primary CVE source (not NVD)
- PURL-based batch queries, no rate limits
- Aggregates OSS-Fuzz, GitHub Advisory, language ecosystems
- Package→PURL mapping from Yocto recipe metadata (~80-90% auto-mapped)
- See: [tools/purl_mapper.py](tools/purl_mapper.py), [tools/osv_client.py](tools/osv_client.py)

### 2. Hybrid BitBake class + external CLI tool
- Thin `security-check.bbclass` hooks into `do_image_complete`, captures build context (kernel config, DISTRO_FEATURES, SPDX SBOM)
- Standalone `security-report.py` does all real work — can run locally for debugging
- See: [meta-security/classes/security-check.bbclass](meta-security/classes/security-check.bbclass), [tools/security_report.py](tools/security_report.py)

### 3. YAML-based hardening rules with typed evaluators
- Security engineers write rules in YAML without learning a policy language
- Evaluator types: `kernel_config_not_set`, `kernel_config_is_set`, `cflag_contains`, `distro_features_contain`, `service_list_match`, `file_content_check`, `file_permission_check`, `pn_blacklist_check`
- Extensible with custom Python evaluators
- See: [tools/rule_engine.py](tools/rule_engine.py), [rules/](rules/)

### 4. Configurable CI blocking behavior
- `SECURITY_CHECK_FAIL_ON_CRITICAL` variable per-image, per-pipeline
- Dashboard always shows all results regardless of CI threshold
- CI tool exits with code 2 on critical CVEs for optional pipeline enforcement

## Data Pipeline

```
Package manifest → PURL mapper (recipe class heuristics)
  → OSV POST /v1/queryBatch (100 pkg/batch)
  → Version match (semver + Yocto version normalizer strips git suffixes)
  → Deduplicate by CVE ID (merge aliases: CVE ↔ GHSA ↔ OSV)
  → Status assignment (new / existing from prior builds)
  → Upload to dashboard API
```

## Database Schema

| Table | Purpose |
|-------|---------|
| `builds` | Per-build metadata (image, product, machine, yocto_version, timestamp) |
| `packages` | Per-build package list (name, version, PURL, layer, recipe_class) |
| `cve_findings` | Matched CVEs per package per build (severity, status, remediation, triage) |
| `hardening_rules` | Rule definitions (eval_type, params as JSONB) |
| `hardening_results` | Per-build rule evaluation outcomes |
| `remediation_log` | Audit trail for CVE status changes |
| `policy_profiles` | Named sets of hardening rules assigned to products |
| `build_summary` | Materialized view: CVE counts + hardening scores per build |

## API Endpoints

### CI Integration (token auth)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/builds` | Upload build with packages and CVE findings |
| POST | `/api/v1/builds/{id}/hardening` | Upload hardening evaluation results |

### Dashboard (JWT auth)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/login` | Login, returns JWT |
| GET | `/api/v1/builds` | List builds with summary stats |
| GET | `/api/v1/builds/{id}` | Single build detail |
| GET | `/api/v1/builds/{id}/cves` | CVEs for a build (filterable) |
| PATCH | `/api/v1/cves/{id}/status` | Update CVE triage status |
| GET | `/api/v1/builds/{id}/hardening` | Hardening results |
| GET | `/api/v1/hardening/rules` | List all hardening rules |
| POST | `/api/v1/hardening/rules` | Create custom rule |
| PUT | `/api/v1/hardening/rules/{id}` | Update rule |
| GET | `/api/v1/products/{p}/trends/cves` | CVE count over time |
| GET | `/api/v1/products/{p}/trends/compliance` | Compliance score over time |
| GET | `/api/v1/products/{p}/compare` | Side-by-side build comparison |

## Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| CI-side tool | Python CLI | Same language as BitBake, reusable standalone |
| Backend API | Python FastAPI + SQLAlchemy 2.0 | Yocto ecosystem is Python; mature ORM |
| Database | PostgreSQL 15+ | JSONB for flexible rules, concurrent access |
| Task queue | Celery + Redis | Background rescans and periodic jobs |
| Frontend | React 18 + TypeScript + Mantine | Pre-built dashboard components |
| Charting | Recharts | Good time-series support for trends |
| CVE source | OSV.dev | No rate limits, PURL batch API |

## Project Structure

```
security-system/
├── backend/                    # Dashboard API server
│   ├── app/
│   │   ├── main.py             # FastAPI entry point
│   │   ├── models.py           # SQLAlchemy ORM (8 tables)
│   │   ├── schemas.py          # Pydantic models
│   │   ├── routes.py           # All API endpoints
│   │   ├── auth.py             # JWT + CI token auth
│   │   └── config.py           # Environment config
│   └── alembic/                # Database migrations
├── tools/                      # CI-side Python tools
│   ├── security_report.py      # Main orchestrator CLI
│   ├── osv_client.py           # OSV.dev API client
│   ├── purl_mapper.py          # Recipe → PURL mapping
│   ├── version_normalizer.py   # Yocto version normalization
│   ├── rule_engine.py          # Hardening rule evaluator
│   └── export_manifest.py      # Yocto manifest exporter
├── rules/                      # Hardening policy YAML files
│   ├── cis-benchmark/embedded-linux/cis-v1.0.yaml  # 53 CIS rules
│   └── custom/company-policy.yaml                   # 8 company rules
├── meta-security/classes/
│   └── security-check.bbclass  # BitBake integration class
├── frontend/                   # React dashboard
│   └── src/
│       ├── pages/
│       │   ├── Login.tsx       # JWT login
│       │   ├── Builds.tsx      # Build list + summary cards
│       │   ├── BuildDetail.tsx # CVE triage + hardening tabs
│       │   └── Trends.tsx      # Trend charts
│       └── api/client.ts       # API client with auth
├── docker-compose.yml          # Backend + DB + Redis + Celery
└── test_backend.py             # Minimal backend for frontend dev
```

## Hardening Rule Evaluators

| eval_type | Context | Description |
|-----------|---------|-------------|
| `kernel_config_not_set` | kernel .config | Assert config keys are `is not set` |
| `kernel_config_is_set` | kernel .config | Assert config key has specific value (y/m/is not set) |
| `cflag_contains` | build flags JSON | Assert compiler flag present in packages |
| `distro_features_contain` | DISTRO_FEATURES | Assert required features enabled |
| `service_list_match` | rootfs systemd services | Validate service allowlist |
| `file_content_check` | rootfs config files | Regex match/no-match on file contents |
| `file_permission_check` | rootfs metadata | Assert file mode/owner constraints |
| `pn_blacklist_check` | build config | Assert no blacklisted packages in build |
