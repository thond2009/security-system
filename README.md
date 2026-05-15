# Security Management System for Yocto

Automated CVE vulnerability tracking and security hardening compliance for Yocto Project-based embedded Linux builds.

## Features

- **CVE Scanning** — Query OSV.dev (not NVD) during Yocto builds for package vulnerabilities
- **Hardening Compliance** — 53 CIS + 8 custom rules across kernel config, compiler flags, runtime config, and more
- **CI Integration** — BitBake class hooks into `do_image_complete`, optionally fails build on critical CVEs
- **Dashboard** — Web UI for build history, CVE triage, hardening results, and trend charts
- **Remediation Workflow** — Triage CVEs (waive, false positive, mitigated, fixed) with audit trail

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 15+ (for production; SQLite works for development)
- Redis (for Celery background tasks)

### Development Setup

```bash
# Backend
cd backend
pip install -r requirements.txt
cd ..

# Start test backend (no database required)
python3 test_backend.py

# Frontend (in another terminal)
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 — login with **admin / admin**.

### Production Setup

```bash
# Start the full stack
docker-compose up -d

# Run database migrations
docker-compose exec api alembic upgrade head

# Load hardening rules into database
# (Rules are loaded from YAML files into DB via the API or admin tools)
```

## Yocto Integration

1. Add `meta-security` layer to your Yocto build:

```bash
bitbake-layers add-layer meta-security
```

2. In your image recipe or `local.conf`:

```bitbake
inherit security-check

SECURITY_CHECK_API_URL = "http://security-dashboard.internal:8000/api/v1"
SECURITY_CHECK_API_TOKEN = "your-ci-token"
SECURITY_CHECK_PROJECT_NAME = "gateway-2000"
SECURITY_CHECK_FAIL_ON_CRITICAL = "0"  # Set to "1" to block builds
```

3. Build normally — security report runs automatically after each image build:

```bash
bitbake core-image-minimal
```

The report appears in `tmp/security-reports/<image>/security-report.json`.

## Usage

### Standalone CLI (outside BitBake)

```bash
python3 tools/security_report.py \
  --packages build/tmp/security-reports/core-image-minimal/packages.json \
  --kernel-config build/tmp/security-reports/core-image-minimal/kernel.config \
  --build-config build/tmp/security-reports/core-image-minimal/build-config.json \
  --rules-dir rules \
  --api-url http://dashboard:8000/api/v1 \
  --api-token ci-token-dev \
  --output-dir ./reports
```

### Dashboard

- **Builds** — View all builds, filter by product, see CVE counts and compliance at a glance
- **Build Detail → CVEs** — Filter by severity/status, click "Triage" to waive or mark false positives
- **Build Detail → Hardening** — See pass/fail breakdown by category (kernel-config, compiler-flags, runtime-file, etc.)
- **Trends** — CVE count and compliance score over time per product

### Hardening Rules

Rules are YAML files under `rules/`. Add custom rules:

```yaml
- id: "MY-RULE-1"
  category: "kernel-config"
  title: "Disable unused debug features"
  severity: "medium"
  eval_type: "kernel_config_not_set"
  source: "custom"
  params:
    config_keys:
      - "CONFIG_DEBUG_INFO"
      - "CONFIG_DEBUG_KERNEL"
```

## API

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /api/v1/auth/login` | — | Login (returns JWT) |
| `POST /api/v1/builds` | CI token | Upload build with packages + CVEs |
| `GET /api/v1/builds` | JWT | List builds |
| `GET /api/v1/builds/{id}/cves` | JWT | CVEs for a build |
| `PATCH /api/v1/cves/{id}/status` | JWT | Triage a CVE |
| `GET /api/v1/hardening/rules` | JWT | List hardening rules |
| `GET /api/v1/products/{p}/trends/cves` | JWT | CVE trend data |
| `GET /api/v1/products/{p}/trends/compliance` | JWT | Compliance trend data |

Full API documentation available at `http://localhost:8000/docs` when running in development.

## Architecture

See [DESIGN.md](DESIGN.md) for full architecture details, database schema, and design rationale.
