# TODO — Remaining Implementation Phases

## Phase 4: Remediation & Triage (Weeks 12-13)

### CVE Bulk Operations
- [ ] Multi-select CVEs and waive/assign in bulk
- [ ] Batch status change with single triage note
- [ ] Export CVE list as CSV/PDF

### Notifications
- [ ] Webhook on critical CVE discovery (Slack, Teams, generic webhook)
- [ ] Email notifications via SMTP
- [ ] Configurable alert thresholds per product
- [ ] Notification preferences per user

### Remediation Dashboard
- [ ] Track CVE aging (days since discovery)
- [ ] Assign CVE owners to team members
- [ ] SLA tracking with configurable deadlines per severity
- [ ] Remediation progress dashboard (open → affected → mitigated → fixed)

### Audit Trail
- [ ] Full remediation_log querying and display in UI
- [ ] Export audit trail for compliance reporting
- [ ] Change history for hardening rule modifications

### Auth Improvements
- [ ] Replace demo credentials with real authentication (LDAP / OAuth2 / OIDC)
- [ ] Role-based access control (viewer, triager, admin)
- [ ] CI token management UI (create/rotate/revoke API tokens per product)

---

## Phase 5: Rescan & Production Polish (Weeks 14-16)

### Celery Background Workers
- [ ] Celery worker setup with Redis broker
- [ ] `rescan_build` task: re-query OSV for all packages in a build
- [ ] `rescan_product` task: rescan latest build for a product
- [ ] Task result tracking and retry logic

### Scheduled Rescans
- [ ] Daily cron job for all active product lines
- [ ] Configurable rescan frequency per product
- [ ] Rescan trigger on new CVE feed data availability

### GitHub Advisory Database Sync
- [ ] Periodic GraphQL sync to supplement OSV data
- [ ] Cross-reference GitHub Advisory IDs with OSV aliases
- [ ] Merge deduplication across both sources

### Kernel CVE Feed
- [ ] Import kernel-specific CVEs from linuxkernelcves.com or kernel.org CNA
- [ ] Match kernel version against affected ranges
- [ ] Track kernel config — was the vulnerable feature even compiled in?

### Runtime Hardening via Rootfs Inspection
- [ ] Wire up `inspect_rootfs()` in security-report.py (code exists, needs integration testing)
- [ ] Extract systemd services list from rootfs tar
- [ ] Extract key config files (sshd_config, sysctl.conf, login.defs, fstab)
- [ ] Evaluate runtime rules (file permissions, service allowlist, config content checks)

### Build Flags Export
- [ ] `export-build-flags.py` tool to extract CFLAGS/LDFLAGS from buildhistory
- [ ] Per-package compiler flag tracking
- [ ] Integration with `security-check.bbclass`

### Performance
- [ ] PostgreSQL query optimization (EXPLAIN ANALYZE on dashboard queries)
- [ ] Add indexes for common filter combinations
- [ ] Materialized view refresh strategy (on-demand vs scheduled)
- [ ] Frontend bundle splitting (lazy-load pages)

### Deployment
- [ ] Kubernetes Helm chart (optional, if using K8s)
- [ ] Nginx reverse proxy configuration for production
- [ ] HTTPS/TLS setup
- [ ] Health check endpoints for orchestration
- [ ] Logging and metrics (Prometheus endpoint)

### Testing
- [ ] Backend API tests (pytest + httpx)
- [ ] Frontend component tests (Vitest + React Testing Library)
- [ ] End-to-end test with sample Yocto build artifacts
- [ ] CI pipeline for the security system itself

---

## Future Enhancements (Beyond Phase 5)

### SBOM Generation & Export
- [ ] Integrate with Yocto's native SPDX generation
- [ ] Export CycloneDX format for integration with other tools
- [ ] SBOM signing and verification

### Multi-Tenant Support
- [ ] Organization/team isolation
- [ ] Per-tenant hardening policies
- [ ] Cross-tenant analytics (for platform teams)

### Integration Plugins
- [ ] Jira integration (auto-create tickets for CVEs)
- [ ] GitLab/GitHub issue integration
- [ ] ServiceNow / ITIL integration

### Advanced Analytics
- [ ] CVE prediction (packages likely to get CVEs based on history)
- [ ] Mean time to remediate (MTTR) metrics
- [ ] Risk scoring per image (combining CVE severity + exploitability + hardening posture)

### Compliance Reporting
- [ ] Generate CIS benchmark compliance reports (PDF)
- [ ] Regulatory compliance mapping (IEC 62443, ISO 27001)
- [ ] Audit-ready evidence export
