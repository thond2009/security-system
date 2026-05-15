from datetime import datetime
from decimal import Decimal
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ---- Package ----
class PackageCreate(BaseModel):
    name: str
    version: str
    purl: str
    layer: Optional[str] = None
    recipe_class: Optional[str] = None
    license: Optional[str] = Field(None, alias="license_")
    is_kernel: bool = False

    class Config:
        populate_by_name = True


class PackageOut(BaseModel):
    id: UUID
    name: str
    version: str
    purl: str
    layer: Optional[str] = None
    recipe_class: Optional[str] = None
    license: Optional[str] = None
    is_kernel: bool

    class Config:
        from_attributes = True


# ---- CVE Finding ----
class CVEFindingCreate(BaseModel):
    package_name: str
    package_version: str
    cve_id: str
    osv_id: Optional[str] = None
    summary: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[Decimal] = None
    cvss_vector: Optional[str] = None
    affected_version: Optional[str] = None
    fixed_version: Optional[str] = None
    status: str = "new"
    aliases: Optional[list[str]] = None


class CVEFindingOut(BaseModel):
    id: UUID
    build_id: UUID
    package_id: UUID
    cve_id: str
    osv_id: Optional[str] = None
    summary: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[Decimal] = None
    cvss_vector: Optional[str] = None
    affected_version: Optional[str] = None
    fixed_version: Optional[str] = None
    status: str
    remediation: Optional[str] = None
    triage_notes: Optional[str] = None
    triaged_by: Optional[str] = None
    triaged_at: Optional[datetime] = None
    discovered_at: datetime
    updated_at: datetime
    aliases: Optional[list[str]] = None

    class Config:
        from_attributes = True


class CVEFindingStatusUpdate(BaseModel):
    status: str
    remediation: Optional[str] = None
    triage_notes: Optional[str] = None
    changed_by: Optional[str] = None


# ---- Build ----
class BuildCreate(BaseModel):
    image_name: str
    product_name: str
    machine: str
    distro: str
    distro_version: Optional[str] = None
    yocto_version: Optional[str] = None
    build_number: int
    ci_build_url: Optional[str] = None
    ci_build_id: Optional[str] = None
    total_packages: int = 0
    status: str = "completed"
    metadata_: Optional[dict] = Field(None, alias="metadata_")
    packages: list[PackageCreate] = []
    cve_findings: list[CVEFindingCreate] = []

    class Config:
        populate_by_name = True


class BuildOut(BaseModel):
    id: UUID
    image_name: str
    product_name: str
    machine: str
    distro: str
    distro_version: Optional[str] = None
    yocto_version: Optional[str] = None
    build_number: int
    build_ts: datetime
    ci_build_url: Optional[str] = None
    ci_build_id: Optional[str] = None
    total_packages: int
    status: str
    metadata_: Optional[dict] = Field(None, alias="metadata_")

    class Config:
        from_attributes = True
        populate_by_name = True


class BuildSummaryOut(BaseModel):
    build_id: UUID
    product_name: str
    image_name: str
    build_number: int
    build_ts: datetime
    total_packages: int
    critical_cves: int
    high_cves: int
    medium_cves: int
    total_new_cves: int
    total_open_cves: int
    total_waived_cves: int
    hardening_fails: int
    hardening_passes: int
    hardening_total: int

    class Config:
        from_attributes = True


# ---- Hardening ----
class HardeningRuleCreate(BaseModel):
    rule_id: str
    category: str
    title: str
    description: Optional[str] = None
    severity: str
    eval_type: str
    params: dict
    source: Optional[str] = None
    enabled: bool = True


class HardeningRuleOut(BaseModel):
    id: UUID
    rule_id: str
    category: str
    title: str
    description: Optional[str] = None
    severity: str
    eval_type: str
    params: dict
    source: Optional[str] = None
    enabled: bool

    class Config:
        from_attributes = True


class HardeningResultCreate(BaseModel):
    rule_id: str
    status: str
    message: Optional[str] = None
    evidence: Optional[dict] = None


class HardeningResultOut(BaseModel):
    id: UUID
    build_id: UUID
    rule_id: UUID
    status: str
    message: Optional[str] = None
    evidence: Optional[dict] = None
    evaluated_at: datetime

    class Config:
        from_attributes = True


# ---- Trends ----
class TrendPoint(BaseModel):
    date: str
    build_number: int
    value: float


class CVECompareOut(BaseModel):
    build_a: BuildOut
    build_b: BuildOut
    new_cves: list[CVEFindingOut]
    resolved_cves: list[CVEFindingOut]


# ---- API Token ----
class TokenRequest(BaseModel):
    token: str
