import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Index, Integer, Numeric,
    String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Build(Base):
    __tablename__ = "builds"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    image_name = Column(String(255), nullable=False)
    product_name = Column(String(255), nullable=False)
    machine = Column(String(255), nullable=False)
    distro = Column(String(255), nullable=False)
    distro_version = Column(String(100))
    yocto_version = Column(String(100))
    build_number = Column(Integer, nullable=False)
    build_ts = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    ci_build_url = Column(Text)
    ci_build_id = Column(String(255))
    total_packages = Column(Integer, nullable=False, default=0)
    status = Column(String(50), nullable=False, default="completed")
    metadata_ = Column("metadata", JSONB)

    packages = relationship("Package", back_populates="build", cascade="all, delete-orphan")
    cve_findings = relationship("CVEFinding", back_populates="build", cascade="all, delete-orphan")
    hardening_results = relationship("HardeningResult", back_populates="build", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("product_name", "build_number"),
        Index("idx_builds_product", "product_name"),
        Index("idx_builds_ts", build_ts.desc()),
    )


class Package(Base):
    __tablename__ = "packages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    build_id = Column(UUID(as_uuid=True), ForeignKey("builds.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    version = Column(String(255), nullable=False)
    purl = Column(Text, nullable=False)
    layer = Column(String(255))
    recipe_class = Column(String(255))
    license_ = Column("license", String(255))
    is_kernel = Column(Boolean, nullable=False, default=False)

    build = relationship("Build", back_populates="packages")
    cve_findings = relationship("CVEFinding", back_populates="package", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("build_id", "name"),
        Index("idx_packages_build", "build_id"),
        Index("idx_packages_purl", "purl"),
    )


class CVEFinding(Base):
    __tablename__ = "cve_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    build_id = Column(UUID(as_uuid=True), ForeignKey("builds.id", ondelete="CASCADE"), nullable=False)
    package_id = Column(UUID(as_uuid=True), ForeignKey("packages.id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(String(50), nullable=False)
    osv_id = Column(String(100))
    summary = Column(Text)
    severity = Column(String(20))
    cvss_score = Column(Numeric(3, 1))
    cvss_vector = Column(String(100))
    affected_version = Column(String(255))
    fixed_version = Column(String(255))
    status = Column(String(50), nullable=False, default="new")
    remediation = Column(String(50))
    triage_notes = Column(Text)
    triaged_by = Column(String(255))
    triaged_at = Column(DateTime(timezone=True))
    discovered_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    aliases = Column(JSONB)

    build = relationship("Build", back_populates="cve_findings")
    package = relationship("Package", back_populates="cve_findings")

    __table_args__ = (
        UniqueConstraint("build_id", "package_id", "cve_id"),
        Index("idx_cve_build", "build_id"),
        Index("idx_cve_package", "package_id"),
        Index("idx_cve_status", "status"),
        Index("idx_cve_severity", "severity"),
    )


class HardeningRule(Base):
    __tablename__ = "hardening_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id = Column(String(100), unique=True, nullable=False)
    category = Column(String(100), nullable=False)
    title = Column(Text, nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)
    eval_type = Column(String(100), nullable=False)
    params = Column(JSONB, nullable=False)
    source = Column(String(100))
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)


class HardeningResult(Base):
    __tablename__ = "hardening_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    build_id = Column(UUID(as_uuid=True), ForeignKey("builds.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(UUID(as_uuid=True), ForeignKey("hardening_rules.id"), nullable=False)
    status = Column(String(20), nullable=False)
    message = Column(Text)
    evidence = Column(JSONB)
    evaluated_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    build = relationship("Build", back_populates="hardening_results")

    __table_args__ = (
        UniqueConstraint("build_id", "rule_id"),
        Index("idx_harden_build", "build_id"),
    )


class PolicyProfile(Base):
    __tablename__ = "policy_profiles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    is_default = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)


class PolicyProfileRule(Base):
    __tablename__ = "policy_profile_rules"

    profile_id = Column(UUID(as_uuid=True), ForeignKey("policy_profiles.id", ondelete="CASCADE"), primary_key=True)
    rule_id = Column(UUID(as_uuid=True), ForeignKey("hardening_rules.id", ondelete="CASCADE"), primary_key=True)


class ProductPolicy(Base):
    __tablename__ = "product_policies"

    product_name = Column(String(255), primary_key=True)
    profile_id = Column(UUID(as_uuid=True), ForeignKey("policy_profiles.id", ondelete="CASCADE"), primary_key=True)


class RemediationLog(Base):
    __tablename__ = "remediation_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_finding_id = Column(UUID(as_uuid=True), ForeignKey("cve_findings.id", ondelete="CASCADE"), nullable=False)
    previous_status = Column(String(50))
    new_status = Column(String(50))
    changed_by = Column(String(255))
    change_reason = Column(Text)
    changed_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    __table_args__ = (Index("idx_remlog_cve", "cve_finding_id"),)
