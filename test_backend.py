"""Minimal test backend for frontend development — no database required."""
import json
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

security = HTTPBearer(auto_error=False)
JWT_SECRET = "dev-secret"
CI_TOKEN = "ci-token-dev"

# In-memory stores
builds_db: list[dict] = []
cves_db: dict[str, list[dict]] = {}  # build_id -> list of CVEs
hardening_db: dict[str, list[dict]] = {}  # build_id -> list of hardening results


class LoginRequest(BaseModel):
    username: str
    password: str


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(401, "Missing auth")
    token = credentials.credentials
    if token == CI_TOKEN:
        return "ci"
    if token.startswith("eyJ"):
        return "user"
    raise HTTPException(403, "Invalid token")


@app.post("/api/v1/auth/login")
def login(body: LoginRequest):
    if body.username == "admin" and body.password == "admin":
        from jose import jwt
        token = jwt.encode(
            {"sub": body.username, "exp": datetime.now(timezone.utc).timestamp() + 28800},
            JWT_SECRET, algorithm="HS256"
        )
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(401, "Invalid credentials")


@app.post("/api/v1/builds", status_code=201)
def create_build(payload: dict, _: str = Depends(verify_token)):
    build_id = str(uuid.uuid4())
    build = {
        "id": build_id,
        "image_name": payload.get("image_name", "test-image"),
        "product_name": payload.get("product_name", "test-product"),
        "machine": payload.get("machine", "x86_64"),
        "distro": payload.get("distro", "poky"),
        "distro_version": payload.get("distro_version"),
        "yocto_version": payload.get("yocto_version"),
        "build_number": payload.get("build_number", 1),
        "build_ts": datetime.now(timezone.utc).isoformat(),
        "ci_build_url": payload.get("ci_build_url"),
        "ci_build_id": payload.get("ci_build_id"),
        "total_packages": payload.get("total_packages", 0),
        "status": "completed",
        "metadata_": payload.get("metadata_"),
    }
    builds_db.insert(0, build)

    # Store CVEs
    cve_list = []
    for c in payload.get("cve_findings", []):
        cve = {
            "id": str(uuid.uuid4()),
            "build_id": build_id,
            "package_id": str(uuid.uuid4()),
            "cve_id": c.get("cve_id", "CVE-2024-0000"),
            "osv_id": c.get("osv_id"),
            "summary": c.get("summary"),
            "severity": c.get("severity", "HIGH"),
            "cvss_score": c.get("cvss_score"),
            "cvss_vector": c.get("cvss_vector"),
            "affected_version": c.get("affected_version"),
            "fixed_version": c.get("fixed_version"),
            "status": c.get("status", "new"),
            "remediation": None,
            "triage_notes": None,
            "triaged_by": None,
            "triaged_at": None,
            "discovered_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "aliases": c.get("aliases"),
        }
        cve_list.append(cve)
    cves_db[build_id] = cve_list
    hardening_db[build_id] = []

    return build


@app.get("/api/v1/builds")
def list_builds(product_name: str = None):
    result = []
    for b in builds_db:
        if product_name and b["product_name"] != product_name:
            continue
        b_cves = cves_db.get(b["id"], [])
        b_hard = hardening_db.get(b["id"], [])
        result.append({
            "build_id": b["id"],
            "product_name": b["product_name"],
            "image_name": b["image_name"],
            "build_number": b["build_number"],
            "build_ts": b["build_ts"],
            "total_packages": b["total_packages"],
            "critical_cves": sum(1 for c in b_cves if c["severity"] == "CRITICAL" and c["status"] == "new"),
            "high_cves": sum(1 for c in b_cves if c["severity"] == "HIGH" and c["status"] == "new"),
            "medium_cves": sum(1 for c in b_cves if c["severity"] == "MEDIUM" and c["status"] == "new"),
            "total_new_cves": sum(1 for c in b_cves if c["status"] == "new"),
            "total_open_cves": sum(1 for c in b_cves if c["status"] in ("new", "affected")),
            "total_waived_cves": sum(1 for c in b_cves if c["status"] in ("waived", "false_positive")),
            "hardening_fails": sum(1 for h in b_hard if h["status"] == "FAIL"),
            "hardening_passes": sum(1 for h in b_hard if h["status"] == "PASS"),
            "hardening_total": len(b_hard),
        })
    return result


@app.get("/api/v1/builds/{build_id}")
def get_build(build_id: str):
    for b in builds_db:
        if b["id"] == build_id:
            return b
    raise HTTPException(404, "Not found")


@app.get("/api/v1/builds/{build_id}/cves")
def list_cves(build_id: str, severity: str = None, status: str = None):
    cves = cves_db.get(build_id, [])
    if severity:
        cves = [c for c in cves if c["severity"] == severity.upper()]
    if status:
        cves = [c for c in cves if c["status"] == status]
    return cves


@app.patch("/api/v1/cves/{cve_id}/status")
def update_cve_status(cve_id: str, update: dict):
    for build_cves in cves_db.values():
        for c in build_cves:
            if c["id"] == cve_id:
                c["status"] = update.get("status", c["status"])
                c["triage_notes"] = update.get("triage_notes", c.get("triage_notes"))
                c["updated_at"] = datetime.now(timezone.utc).isoformat()
                return c
    raise HTTPException(404, "Not found")


@app.post("/api/v1/builds/{build_id}/hardening", status_code=201)
def create_hardening(build_id: str, results: list[dict]):
    hardening_db[build_id] = []
    for r in results:
        hardening_db[build_id].append({
            "id": str(uuid.uuid4()),
            "build_id": build_id,
            "rule_id": str(uuid.uuid4()),
            "status": r.get("status", "UNKNOWN"),
            "message": r.get("message"),
            "evidence": r.get("evidence"),
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        })
    return {"created": len(results)}


@app.get("/api/v1/builds/{build_id}/hardening")
def get_hardening(build_id: str):
    return hardening_db.get(build_id, [])


@app.get("/api/v1/hardening/rules")
def list_rules():
    return [
        {"id": str(uuid.uuid4()), "rule_id": "CIS-1.1.1", "category": "kernel-config",
         "title": "Disable unused filesystems", "description": None, "severity": "medium",
         "eval_type": "kernel_config_not_set", "params": {}, "source": "cis-embedded-v1.0", "enabled": True},
        {"id": str(uuid.uuid4()), "rule_id": "CIS-1.5.1", "category": "kernel-config",
         "title": "Enable ASLR", "description": None, "severity": "high",
         "eval_type": "kernel_config_is_set", "params": {}, "source": "cis-embedded-v1.0", "enabled": True},
        {"id": str(uuid.uuid4()), "rule_id": "CIS-2.1.2", "category": "compiler-flags",
         "title": "Enable stack smashing protection", "description": None, "severity": "high",
         "eval_type": "cflag_contains", "params": {}, "source": "cis-embedded-v1.0", "enabled": True},
        {"id": str(uuid.uuid4()), "rule_id": "CIS-5.1.1", "category": "runtime-file",
         "title": "Ensure /etc/shadow has correct permissions", "description": None, "severity": "high",
         "eval_type": "file_permission_check", "params": {}, "source": "cis-embedded-v1.0", "enabled": True},
    ]


@app.get("/api/v1/products/{product}/trends/cves")
def cve_trends(product: str, days: int = 90):
    import random
    product_builds = [b for b in builds_db if b["product_name"] == product]
    return [
        {"date": b["build_ts"][:10], "build_number": b["build_number"],
         "value": random.randint(0, 15)}
        for b in product_builds
    ]


@app.get("/api/v1/products/{product}/trends/compliance")
def compliance_trends(product: str, days: int = 90):
    import random
    product_builds = [b for b in builds_db if b["product_name"] == product]
    return [
        {"date": b["build_ts"][:10], "build_number": b["build_number"],
         "value": random.randint(65, 95)}
        for b in product_builds
    ]


@app.get("/api/v1/products/{product}/compare")
def compare(product: str, b1: int = 0, b2: int = 0):
    return {"build_a": {}, "build_b": {}, "new_cves": [], "resolved_cves": []}


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
