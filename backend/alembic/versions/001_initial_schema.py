"""Initial schema: builds, packages, cve_findings, hardening, policies, remediation_log, build_summary MV

Revision ID: 001
Revises:
Create Date: 2026-05-15
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "builds",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("image_name", sa.String(255), nullable=False),
        sa.Column("product_name", sa.String(255), nullable=False),
        sa.Column("machine", sa.String(255), nullable=False),
        sa.Column("distro", sa.String(255), nullable=False),
        sa.Column("distro_version", sa.String(100)),
        sa.Column("yocto_version", sa.String(100)),
        sa.Column("build_number", sa.Integer, nullable=False),
        sa.Column("build_ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("ci_build_url", sa.Text),
        sa.Column("ci_build_id", sa.String(255)),
        sa.Column("total_packages", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("status", sa.String(50), nullable=False, server_default=sa.text("'completed'")),
        sa.Column("metadata", JSONB),
        sa.UniqueConstraint("product_name", "build_number"),
        sa.Index("idx_builds_product", "product_name"),
        sa.Index("idx_builds_ts", sa.text("build_ts DESC")),
    )

    op.create_table(
        "packages",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("build_id", UUID(as_uuid=True), sa.ForeignKey("builds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(255), nullable=False),
        sa.Column("purl", sa.Text, nullable=False),
        sa.Column("layer", sa.String(255)),
        sa.Column("recipe_class", sa.String(255)),
        sa.Column("license", sa.String(255)),
        sa.Column("is_kernel", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.UniqueConstraint("build_id", "name"),
        sa.Index("idx_packages_build", "build_id"),
        sa.Index("idx_packages_purl", "purl"),
    )

    op.create_table(
        "cve_findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("build_id", UUID(as_uuid=True), sa.ForeignKey("builds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("package_id", UUID(as_uuid=True), sa.ForeignKey("packages.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cve_id", sa.String(50), nullable=False),
        sa.Column("osv_id", sa.String(100)),
        sa.Column("summary", sa.Text),
        sa.Column("severity", sa.String(20)),
        sa.Column("cvss_score", sa.Numeric(3, 1)),
        sa.Column("cvss_vector", sa.String(100)),
        sa.Column("affected_version", sa.String(255)),
        sa.Column("fixed_version", sa.String(255)),
        sa.Column("status", sa.String(50), nullable=False, server_default=sa.text("'new'")),
        sa.Column("remediation", sa.String(50)),
        sa.Column("triage_notes", sa.Text),
        sa.Column("triaged_by", sa.String(255)),
        sa.Column("triaged_at", sa.DateTime(timezone=True)),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("aliases", JSONB),
        sa.UniqueConstraint("build_id", "package_id", "cve_id"),
        sa.Index("idx_cve_build", "build_id"),
        sa.Index("idx_cve_package", "package_id"),
        sa.Index("idx_cve_status", "status"),
        sa.Index("idx_cve_severity", "severity"),
    )

    op.create_table(
        "hardening_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("rule_id", sa.String(100), unique=True, nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("eval_type", sa.String(100), nullable=False),
        sa.Column("params", JSONB, nullable=False),
        sa.Column("source", sa.String(100)),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_table(
        "hardening_results",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("build_id", UUID(as_uuid=True), sa.ForeignKey("builds.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", UUID(as_uuid=True), sa.ForeignKey("hardening_rules.id"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("message", sa.Text),
        sa.Column("evidence", JSONB),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("build_id", "rule_id"),
        sa.Index("idx_harden_build", "build_id"),
    )

    op.create_table(
        "policy_profiles",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), unique=True, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("is_default", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_table(
        "policy_profile_rules",
        sa.Column("profile_id", UUID(as_uuid=True), sa.ForeignKey("policy_profiles.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("rule_id", UUID(as_uuid=True), sa.ForeignKey("hardening_rules.id", ondelete="CASCADE"), primary_key=True),
    )

    op.create_table(
        "product_policies",
        sa.Column("product_name", sa.String(255), primary_key=True),
        sa.Column("profile_id", UUID(as_uuid=True), sa.ForeignKey("policy_profiles.id", ondelete="CASCADE"), primary_key=True),
    )

    op.create_table(
        "remediation_log",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("cve_finding_id", UUID(as_uuid=True), sa.ForeignKey("cve_findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("previous_status", sa.String(50)),
        sa.Column("new_status", sa.String(50)),
        sa.Column("changed_by", sa.String(255)),
        sa.Column("change_reason", sa.Text),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Index("idx_remlog_cve", "cve_finding_id"),
    )

    # Materialized view for dashboard performance
    op.execute("""
        CREATE MATERIALIZED VIEW build_summary AS
        SELECT
            b.id AS build_id,
            b.product_name,
            b.image_name,
            b.build_number,
            b.build_ts,
            b.total_packages,
            COUNT(DISTINCT cf.id) FILTER (
                WHERE cf.severity = 'CRITICAL' AND cf.status = 'new'
            ) AS critical_cves,
            COUNT(DISTINCT cf.id) FILTER (
                WHERE cf.severity = 'HIGH' AND cf.status = 'new'
            ) AS high_cves,
            COUNT(DISTINCT cf.id) FILTER (
                WHERE cf.severity = 'MEDIUM' AND cf.status = 'new'
            ) AS medium_cves,
            COUNT(DISTINCT cf.id) FILTER (
                WHERE cf.status = 'new'
            ) AS total_new_cves,
            COUNT(DISTINCT cf.id) FILTER (
                WHERE cf.status = 'affected'
            ) AS total_open_cves,
            COUNT(DISTINCT cf.id) FILTER (
                WHERE cf.status IN ('waived', 'false_positive')
            ) AS total_waived_cves,
            COUNT(DISTINCT hr.id) FILTER (
                WHERE hr.status = 'FAIL'
            ) AS hardening_fails,
            COUNT(DISTINCT hr.id) FILTER (
                WHERE hr.status = 'PASS'
            ) AS hardening_passes,
            COUNT(DISTINCT hr.id) AS hardening_total
        FROM builds b
        LEFT JOIN cve_findings cf ON cf.build_id = b.id
        LEFT JOIN hardening_results hr ON hr.build_id = b.id
        GROUP BY b.id
    """)

    op.execute("CREATE UNIQUE INDEX idx_build_summary_id ON build_summary (build_id)")


def downgrade() -> None:
    op.execute("DROP MATERIALIZED VIEW IF EXISTS build_summary")
    op.drop_table("remediation_log")
    op.drop_table("product_policies")
    op.drop_table("policy_profile_rules")
    op.drop_table("policy_profiles")
    op.drop_table("hardening_results")
    op.drop_table("hardening_rules")
    op.drop_table("cve_findings")
    op.drop_table("packages")
    op.drop_table("builds")
