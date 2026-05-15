from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from backend.app.auth import create_jwt_token, verify_ci_token, verify_jwt_token
from backend.app.database import get_db
from backend.app.models import (
    Build, CVEFinding, HardeningResult, HardeningRule, Package, RemediationLog,
)
from backend.app.schemas import HardeningRuleCreate, HardeningRuleOut
from backend.app.schemas import (
    BuildCreate, BuildOut, BuildSummaryOut,
    CVEFindingOut, CVEFindingStatusUpdate,
    HardeningResultCreate, HardeningResultOut,
)

router = APIRouter(prefix="/api/v1")


# ---- Auth ----

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/auth/login")
def login(body: LoginRequest):
    # Demo credentials — replace with real LDAP/OAuth in production
    if body.username == "admin" and body.password == "admin":
        token = create_jwt_token(body.username)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")


# ---- Builds ----

@router.post("/builds", response_model=BuildOut, status_code=201)
def create_build(
    payload: BuildCreate,
    db: Session = Depends(get_db),
    _: str = Depends(verify_ci_token),
):
    build = Build(
        image_name=payload.image_name,
        product_name=payload.product_name,
        machine=payload.machine,
        distro=payload.distro,
        distro_version=payload.distro_version,
        yocto_version=payload.yocto_version,
        build_number=payload.build_number,
        ci_build_url=payload.ci_build_url,
        ci_build_id=payload.ci_build_id,
        total_packages=payload.total_packages,
        status=payload.status,
    )
    if payload.metadata_:
        build.metadata_ = payload.metadata_
    db.add(build)
    db.flush()

    # Create packages
    pkg_map = {}
    for pkg_data in payload.packages:
        pkg = Package(
            build_id=build.id,
            name=pkg_data.name,
            version=pkg_data.version,
            purl=pkg_data.purl,
            layer=pkg_data.layer,
            recipe_class=pkg_data.recipe_class,
            license_=pkg_data.license,
            is_kernel=pkg_data.is_kernel,
        )
        db.add(pkg)
        db.flush()
        pkg_map[pkg_data.name] = pkg.id

    # Create CVE findings
    for cve_data in payload.cve_findings:
        pkg_id = pkg_map.get(cve_data.package_name)
        if pkg_id is None:
            continue
        finding = CVEFinding(
            build_id=build.id,
            package_id=pkg_id,
            cve_id=cve_data.cve_id,
            osv_id=cve_data.osv_id,
            summary=cve_data.summary,
            severity=cve_data.severity,
            cvss_score=cve_data.cvss_score,
            cvss_vector=cve_data.cvss_vector,
            affected_version=cve_data.affected_version,
            fixed_version=cve_data.fixed_version,
            status=cve_data.status,
            aliases=cve_data.aliases,
        )
        db.add(finding)

    db.commit()
    db.refresh(build)
    return build


@router.get("/builds", response_model=list[BuildSummaryOut])
def list_builds(
    product_name: str = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    _: str = Depends(verify_jwt_token),
):
    query = db.execute(
        text("SELECT * FROM build_summary ORDER BY build_ts DESC LIMIT :limit OFFSET :offset"),
        {"limit": limit, "offset": offset},
    )
    rows = query.fetchall()
    return [
        BuildSummaryOut(
            build_id=row.build_id,
            product_name=row.product_name,
            image_name=row.image_name,
            build_number=row.build_number,
            build_ts=row.build_ts,
            total_packages=row.total_packages,
            critical_cves=row.critical_cves,
            high_cves=row.high_cves,
            medium_cves=row.medium_cves,
            total_new_cves=row.total_new_cves,
            total_open_cves=row.total_open_cves,
            total_waived_cves=row.total_waived_cves,
            hardening_fails=row.hardening_fails,
            hardening_passes=row.hardening_passes,
            hardening_total=row.hardening_total,
        )
        for row in rows
    ]


@router.get("/builds/{build_id}", response_model=BuildOut)
def get_build(
    build_id: UUID,
    db: Session = Depends(get_db),
    _: str = Depends(verify_jwt_token),
):
    build = db.get(Build, build_id)
    if not build:
        raise HTTPException(status_code=404, detail="Build not found")
    return build


@router.delete("/builds/{build_id}", status_code=204)
def delete_build(
    build_id: UUID,
    db: Session = Depends(get_db),
    _: str = Depends(verify_ci_token),
):
    build = db.get(Build, build_id)
    if not build:
        raise HTTPException(status_code=404, detail="Build not found")
    db.delete(build)
    db.commit()


# ---- CVEs ----

@router.get("/builds/{build_id}/cves", response_model=list[CVEFindingOut])
def list_cves(
    build_id: UUID,
    severity: str = Query(None),
    status: str = Query(None),
    limit: int = Query(200, le=1000),
    db: Session = Depends(get_db),
    _: str = Depends(verify_jwt_token),
):
    query = db.query(CVEFinding).filter(CVEFinding.build_id == build_id)
    if severity:
        query = query.filter(CVEFinding.severity == severity.upper())
    if status:
        query = query.filter(CVEFinding.status == status)
    return query.limit(limit).all()


@router.get("/builds/{build_id}/cves/{cve_id}", response_model=CVEFindingOut)
def get_cve(
    build_id: UUID,
    cve_id: UUID,
    db: Session = Depends(get_db),
    _: str = Depends(verify_jwt_token),
):
    finding = db.query(CVEFinding).filter(
        CVEFinding.build_id == build_id,
        CVEFinding.id == cve_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="CVE finding not found")
    return finding


@router.patch("/cves/{cve_id}/status", response_model=CVEFindingOut)
def update_cve_status(
    cve_id: UUID,
    update: CVEFindingStatusUpdate,
    db: Session = Depends(get_db),
    user: str = Depends(verify_jwt_token),
):
    finding = db.get(CVEFinding, cve_id)
    if not finding:
        raise HTTPException(status_code=404, detail="CVE finding not found")

    previous_status = finding.status
    finding.status = update.status
    if update.remediation is not None:
        finding.remediation = update.remediation
    if update.triage_notes is not None:
        finding.triage_notes = update.triage_notes
    finding.triaged_by = user
    finding.triaged_at = datetime.utcnow()
    finding.updated_at = datetime.utcnow()

    log_entry = RemediationLog(
        cve_finding_id=cve_id,
        previous_status=previous_status,
        new_status=update.status,
        changed_by=update.changed_by or user,
        change_reason=update.triage_notes,
    )
    db.add(log_entry)
    db.commit()
    db.refresh(finding)
    return finding


# ---- Hardening Results ----

@router.post("/builds/{build_id}/hardening", status_code=201)
def create_hardening_results(
    build_id: UUID,
    results: list[HardeningResultCreate],
    db: Session = Depends(get_db),
    _: str = Depends(verify_ci_token),
):
    build = db.get(Build, build_id)
    if not build:
        raise HTTPException(status_code=404, detail="Build not found")

    # Resolve rule_id strings (e.g. "CIS-1.1.1") to hardening_rules.id UUIDs
    rule_lookup = {}
    for r in results:
        if r.rule_id not in rule_lookup:
            rule = db.query(HardeningRule).filter(HardeningRule.rule_id == r.rule_id).first()
            if rule:
                rule_lookup[r.rule_id] = rule.id

    created = []
    for r in results:
        rule_uuid = rule_lookup.get(r.rule_id)
        if not rule_uuid:
            continue
        hr = HardeningResult(
            build_id=build_id,
            rule_id=rule_uuid,
            status=r.status,
            message=r.message,
            evidence=r.evidence,
        )
        db.add(hr)
        created.append(hr)
    db.commit()
    return {"created": len(created)}


@router.get("/builds/{build_id}/hardening", response_model=list[HardeningResultOut])
def get_hardening_results(
    build_id: UUID,
    db: Session = Depends(get_db),
    _: str = Depends(verify_jwt_token),
):
    return db.query(HardeningResult).filter(HardeningResult.build_id == build_id).all()


# ---- Trends ----

@router.get("/products/{product}/trends/cves")
def get_cve_trends(
    product: str,
    days: int = Query(90),
    db: Session = Depends(get_db),
    _: str = Depends(verify_jwt_token),
):
    rows = (
        db.query(Build.build_ts, Build.build_number, func.count(CVEFinding.id).label("count"))
        .outerjoin(CVEFinding, (CVEFinding.build_id == Build.id) & (CVEFinding.status == "new"))
        .filter(
            Build.product_name == product,
            Build.build_ts >= func.now() - func.make_interval(days=days),
        )
        .group_by(Build.id)
        .order_by(Build.build_ts)
        .all()
    )
    return [
        {"date": str(row.build_ts.date()), "build_number": row.build_number, "value": row.count}
        for row in rows
    ]


@router.get("/products/{product}/compare")
def compare_builds(
    product: str,
    b1: int = Query(description="Build number A"),
    b2: int = Query(description="Build number B"),
    db: Session = Depends(get_db),
    _: str = Depends(verify_jwt_token),
):
    build_a = db.query(Build).filter(Build.product_name == product, Build.build_number == b1).first()
    build_b = db.query(Build).filter(Build.product_name == product, Build.build_number == b2).first()
    if not build_a or not build_b:
        raise HTTPException(status_code=404, detail="One or both builds not found")

    cves_a = {c.cve_id for c in db.query(CVEFinding).filter(CVEFinding.build_id == build_a.id).all()}
    cves_b = {c.cve_id for c in db.query(CVEFinding).filter(CVEFinding.build_id == build_b.id).all()}

    new_in_b = cves_b - cves_a
    resolved_in_b = cves_a - cves_b

    return {
        "build_a": BuildOut.model_validate(build_a),
        "build_b": BuildOut.model_validate(build_b),
        "new_cves": [CVEFindingOut.model_validate(c) for c in build_b.cve_findings if c.cve_id in new_in_b],
        "resolved_cves": [CVEFindingOut.model_validate(c) for c in build_a.cve_findings if c.cve_id in resolved_in_b],
    }


# ---- Hardening Rules CRUD ----

@router.get("/hardening/rules", response_model=list[HardeningRuleOut])
def list_hardening_rules(
    category: str = Query(None),
    enabled: bool = Query(None),
    db: Session = Depends(get_db),
    _: str = Depends(verify_jwt_token),
):
    q = db.query(HardeningRule)
    if category:
        q = q.filter(HardeningRule.category == category)
    if enabled is not None:
        q = q.filter(HardeningRule.enabled == enabled)
    return q.order_by(HardeningRule.rule_id).all()


@router.post("/hardening/rules", response_model=HardeningRuleOut, status_code=201)
def create_hardening_rule(
    rule: HardeningRuleCreate,
    db: Session = Depends(get_db),
    _: str = Depends(verify_jwt_token),
):
    existing = db.query(HardeningRule).filter(HardeningRule.rule_id == rule.rule_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Rule ID already exists")
    hr = HardeningRule(**rule.model_dump())
    db.add(hr)
    db.commit()
    db.refresh(hr)
    return hr


@router.put("/hardening/rules/{rule_id}", response_model=HardeningRuleOut)
def update_hardening_rule(
    rule_id: UUID,
    rule: HardeningRuleCreate,
    db: Session = Depends(get_db),
    _: str = Depends(verify_jwt_token),
):
    hr = db.get(HardeningRule, rule_id)
    if not hr:
        raise HTTPException(status_code=404, detail="Rule not found")
    for key, val in rule.model_dump().items():
        setattr(hr, key, val)
    hr.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(hr)
    return hr


@router.delete("/hardening/rules/{rule_id}", status_code=204)
def delete_hardening_rule(
    rule_id: UUID,
    db: Session = Depends(get_db),
    _: str = Depends(verify_jwt_token),
):
    hr = db.get(HardeningRule, rule_id)
    if not hr:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(hr)
    db.commit()


# ---- Hardening Compliance Trends ----

@router.get("/products/{product}/trends/compliance")
def get_compliance_trends(
    product: str,
    days: int = Query(90),
    db: Session = Depends(get_db),
    _: str = Depends(verify_jwt_token),
):
    rows = (
        db.query(
            Build.build_ts,
            Build.build_number,
            func.count(HardeningResult.id).label("total"),
            func.sum(
                func.case((HardeningResult.status == "PASS", 1), else_=0)
            ).label("passed"),
        )
        .outerjoin(HardeningResult, HardeningResult.build_id == Build.id)
        .filter(
            Build.product_name == product,
            Build.build_ts >= func.now() - func.make_interval(days=days),
        )
        .group_by(Build.id)
        .order_by(Build.build_ts)
        .all()
    )
    return [
        {
            "date": str(row.build_ts.date()),
            "build_number": row.build_number,
            "value": round((row.passed / row.total * 100) if row.total else 0, 1),
            "passed": row.passed,
            "total": row.total,
        }
        for row in rows
    ]
