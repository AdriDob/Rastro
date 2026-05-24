import logging
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ai.analysis import AIAnalyzer
from core.analysis.analyzer import EndpointAnalyzer
from core.attack import AttackDecisionEngine
from core.recon.runner import ReconRunner
from core.scoring.scorer import Scorer
from database import db, models

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(name)s — %(levelname)s: %(message)s")
logger = logging.getLogger("rastro.main")

app = FastAPI(title="Rastro", version="0.2")


def get_db():
    db_obj = db.SessionLocal()
    try:
        yield db_obj
    finally:
        db_obj.close()


class TargetCreate(BaseModel):
    name: str
    domain: str | None = None
    mode: str | None = "FAST"


class EndpointCreate(BaseModel):
    target_id: int
    path: str
    method: str = "GET"
    params: dict | None = None


class FindingCreate(BaseModel):
    target_id: int
    endpoint_id: int | None = None
    title: str
    severity: str | None = "medium"
    description: str | None = None


class EndpointAnalysisRequest(BaseModel):
    path: str
    method: str = "GET"
    params: dict | None = None
    model: str | None = None


@app.on_event("startup")
async def startup_event():
    db.init_db()


@app.get("/")
async def root():
    return {"message": "Rastro backend inicializado"}


@app.post("/targets")
async def create_target(target: TargetCreate, session: Session = Depends(get_db)):
    db_target = models.Target(name=target.name, domain=target.domain)
    session.add(db_target)
    session.commit()
    session.refresh(db_target)
    return {"id": db_target.id, "name": db_target.name, "domain": db_target.domain, "mode": target.mode}


@app.get("/targets")
async def list_targets(session: Session = Depends(get_db)):
    targets = session.query(models.Target).all()
    return [{"id": t.id, "name": t.name, "domain": t.domain} for t in targets]


@app.get("/targets/{target_id}/summary")
async def target_summary(target_id: int, session: Session = Depends(get_db)):
    target = session.query(models.Target).filter(models.Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    endpoints = session.query(models.Endpoint).filter(models.Endpoint.target_id == target.id).all()
    analyzer = EndpointAnalyzer()
    entries = []
    for endpoint in endpoints:
        try:
            params = eval(endpoint.params or "{}")
        except Exception:
            params = {}
        metadata = analyzer.classify_endpoint(endpoint.path, endpoint.method, params)
        entries.append({
            "path": endpoint.path,
            "method": endpoint.method,
            "labels": metadata.get("labels", []),
        })
    score = Scorer().score_target({
        "is_saas": bool(target.domain),
        "has_api": any("api" in item.get("labels", []) for item in entries),
        "multi_tenant": any("org" in item.get("labels", []) or "tenant" in item.get("labels", []) for item in entries),
        "has_admin": any("admin" in item.get("labels", []) for item in entries),
        "has_graphql": any("graphql" in item.get("labels", []) for item in entries),
    })
    return {"target": {"id": target.id, "name": target.name, "domain": target.domain}, "endpoints": entries, "score": score}


@app.post("/analysis/endpoint")
async def analyze_endpoint(request: EndpointAnalysisRequest):
    analyzer = EndpointAnalyzer()
    local = analyzer.classify_endpoint(request.path, request.method, request.params or {})
    result = {"local": local}
    try:
        ai = AIAnalyzer()
        result["ai"] = ai.analyze_endpoint(request.path, request.method, request.params or {})
    except Exception as exc:
        result["ai_error"] = str(exc)
    return result


@app.post("/endpoints")
async def create_endpoint(endpoint: EndpointCreate, session: Session = Depends(get_db)):
    target = session.query(models.Target).filter(models.Target.id == endpoint.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db_endpoint = models.Endpoint(
        target_id=endpoint.target_id,
        path=endpoint.path,
        method=endpoint.method,
        params=str(endpoint.params) if endpoint.params else None,
    )
    session.add(db_endpoint)
    session.commit()
    session.refresh(db_endpoint)
    return {
        "id": db_endpoint.id,
        "target_id": db_endpoint.target_id,
        "path": db_endpoint.path,
        "method": db_endpoint.method,
    }


@app.get("/endpoints")
async def list_endpoints(session: Session = Depends(get_db)):
    endpoints = session.query(models.Endpoint).all()
    return [
        {
            "id": e.id,
            "target_id": e.target_id,
            "path": e.path,
            "method": e.method,
            "params": e.params,
        }
        for e in endpoints
    ]


@app.post("/findings")
async def create_finding(finding: FindingCreate, session: Session = Depends(get_db)):
    target = session.query(models.Target).filter(models.Target.id == finding.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if finding.endpoint_id:
        endpoint = session.query(models.Endpoint).filter(models.Endpoint.id == finding.endpoint_id).first()
        if not endpoint:
            raise HTTPException(status_code=404, detail="Endpoint not found")
    db_finding = models.Finding(
        target_id=finding.target_id,
        endpoint_id=finding.endpoint_id,
        title=finding.title,
        severity=finding.severity,
        description=finding.description,
    )
    session.add(db_finding)
    session.commit()
    session.refresh(db_finding)
    return {"id": db_finding.id, "title": db_finding.title, "severity": db_finding.severity}


@app.get("/findings")
async def list_findings(session: Session = Depends(get_db)):
    findings = session.query(models.Finding).all()
    return [
        {
            "id": f.id,
            "target_id": f.target_id,
            "endpoint_id": f.endpoint_id,
            "title": f.title,
            "severity": f.severity,
            "description": f.description,
        }
        for f in findings
    ]


@app.post("/scans")
async def launch_scan(target: TargetCreate, session: Session = Depends(get_db)):
    import asyncio
    import json
    import logging
    from datetime import datetime
    from core.recon.tools import verify_recon_tools, validate_mode_compatibility

    logger = logging.getLogger("rastro.main")

    # Validate inputs
    if not target.name or not target.name.strip():
        raise HTTPException(status_code=400, detail="Target name is required")
    if not target.domain or not target.domain.strip():
        raise HTTPException(status_code=400, detail="Target domain is required")

    mode = (target.mode or "FAST").upper()
    if mode not in {"FAST", "DEEP", "API"}:
        raise HTTPException(status_code=400, detail=f"Invalid mode: {mode}. Use FAST, DEEP, or API")

    # Verify recon tools are available
    logger.info(f"Verifying recon tools for mode {mode}...")
    tool_status = await verify_recon_tools(mode)
    is_compatible, reason = validate_mode_compatibility(mode, tool_status)
    if not is_compatible:
        logger.error(f"Recon tools incompatible: {reason}")
        raise HTTPException(status_code=412, detail=f"Recon tools not available: {reason}")

    # Ensure target exists in DB
    db_target = session.query(models.Target).filter(models.Target.name == target.name).first()
    if not db_target:
        db_target = models.Target(name=target.name, domain=target.domain)
        session.add(db_target)
        session.commit()
        session.refresh(db_target)
        logger.info(f"Created target: {target.name}")

    # Create scan run record
    scan = models.ScanRun(target_id=db_target.id, mode=mode, status="running")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    logger.info(f"Started scan run {scan.id} for target {target.name}")

    runner = ReconRunner(Path("./targets") / target.name)
    outputs = {}
    endpoint_count = 0

    try:
        timeout = int(__import__("os").environ.get("SCAN_TIMEOUT", "600"))
        logger.info(f"Running recon pipeline with timeout {timeout}s...")
        outputs = await asyncio.wait_for(runner.run_pipeline(target.domain, mode=mode), timeout=timeout)
        logger.info("Recon pipeline completed successfully")

        # Persist normalized endpoints into DB
        normalized_path = outputs.get("normalized_endpoints")
        if normalized_path:
            logger.info(f"Parsing normalized endpoints from {normalized_path}")
            try:
                with open(normalized_path, "r", encoding="utf-8", errors="ignore") as fh:
                    entries = json.load(fh)
                logger.info(f"Found {len(entries)} endpoint entries to persist")

                for entry in entries:
                    try:
                        path = entry.get("normalized") or entry.get("path") or entry.get("raw")
                        if not path:
                            logger.warning(f"Skipping entry with no path: {entry}")
                            continue

                        method = entry.get("method", "GET").upper()

                        # Avoid duplicates by normalized path + method
                        exists = session.query(models.Endpoint).filter(
                            models.Endpoint.target_id == db_target.id,
                            models.Endpoint.path == path,
                            models.Endpoint.method == method
                        ).first()
                        if exists:
                            logger.debug(f"Skipping duplicate: {method} {path}")
                            continue

                        # Store metadata as JSON
                        params_meta = {
                            "labels": entry.get("labels", []),
                            "score": entry.get("score", 0),
                            "raw": entry.get("raw"),
                            "host": entry.get("host"),
                            "auth_smells": entry.get("auth_smells", []),
                        }
                        db_ep = models.Endpoint(
                            target_id=db_target.id,
                            path=path,
                            method=method,
                            params=json.dumps(params_meta, ensure_ascii=False)
                        )
                        session.add(db_ep)
                        endpoint_count += 1
                    except Exception as ep_exc:
                        logger.warning(f"Error persisting endpoint {entry}: {ep_exc}")
                        continue

                session.commit()
                logger.info(f"Persisted {endpoint_count} endpoints to DB")
            except json.JSONDecodeError as json_exc:
                logger.error(f"Failed to parse normalized endpoints JSON: {json_exc}")
                endpoint_count = 0
            except Exception as persist_exc:
                logger.error(f"Error during endpoint persistence: {persist_exc}")
                endpoint_count = 0

        # Update scan record with success
        scan.status = "completed"
        scan.finished_at = datetime.utcnow()
        scan.endpoint_count = endpoint_count
        try:
            scan.outputs = json.dumps(outputs, ensure_ascii=False)
        except Exception as json_exc:
            logger.warning(f"Could not serialize outputs to JSON: {json_exc}")
            scan.outputs = str(outputs)[:500]
        session.add(scan)
        session.commit()
        logger.info(f"Scan {scan.id} completed: {endpoint_count} endpoints")

    except asyncio.TimeoutError:
        logger.warning(f"Scan {scan.id} timed out after {timeout}s")
        scan.status = "timeout"
        scan.finished_at = datetime.utcnow()
        scan.outputs = f"Scan timed out after {timeout}s"
        session.add(scan)
        session.commit()
        raise HTTPException(status_code=504, detail=f"Scan timed out after {timeout}s. Check tool availability and network connectivity.")

    except Exception as exc:
        logger.error(f"Scan {scan.id} failed: {exc}", exc_info=True)
        scan.status = "failed"
        scan.finished_at = datetime.utcnow()
        scan.outputs = str(exc)[:500]
        session.add(scan)
        session.commit()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(exc)[:200]}")

    return {
        "scan_id": scan.id,
        "target": target.name,
        "mode": mode,
        "endpoint_count": endpoint_count,
        "status": "completed",
        "outputs": outputs
    }


@app.get("/scan_runs")
async def list_scan_runs(target_id: int | None = None, session: Session = Depends(get_db)):
    q = session.query(models.ScanRun)
    if target_id:
        q = q.filter(models.ScanRun.target_id == target_id)
    runs = q.order_by(models.ScanRun.started_at.desc()).limit(50).all()
    out = []
    for r in runs:
        out.append({
            "id": r.id,
            "target_id": r.target_id,
            "mode": r.mode,
            "status": r.status,
            "endpoint_count": r.endpoint_count,
            "started_at": r.started_at.isoformat(sep=" ", timespec="seconds") if r.started_at else None,
            "finished_at": r.finished_at.isoformat(sep=" ", timespec="seconds") if r.finished_at else None,
        })
    return out


@app.get("/scan_runs/{scan_id}")
async def get_scan_run(scan_id: int, session: Session = Depends(get_db)):
    run = session.query(models.ScanRun).filter(models.ScanRun.id == scan_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="ScanRun not found")
    return {
        "id": run.id,
        "target_id": run.target_id,
        "mode": run.mode,
        "status": run.status,
        "endpoint_count": run.endpoint_count,
        "outputs": run.outputs,
        "started_at": run.started_at.isoformat(sep=" ", timespec="seconds") if run.started_at else None,
        "finished_at": run.finished_at.isoformat(sep=" ", timespec="seconds") if run.finished_at else None,
    }


@app.get("/digest")
async def daily_digest(session: Session = Depends(get_db)):
    import json
    logger = logging.getLogger("rastro.main")
    
    analyzer = EndpointAnalyzer()
    scorer = Scorer()
    entries = []
    endpoints = session.query(models.Endpoint).all()
    
    for endpoint in endpoints:
        params = {}
        if endpoint.params:
            try:
                # Try JSON first (preferred)
                params = json.loads(endpoint.params)
            except (json.JSONDecodeError, ValueError):
                # Fallback: try to interpret as Python dict string (legacy)
                try:
                    import ast
                    params = ast.literal_eval(endpoint.params)
                except (ValueError, SyntaxError):
                    logger.warning(f"Could not parse params for endpoint {endpoint.id}: {endpoint.params[:100]}")
                    params = {}
        
        labels = analyzer.classify_endpoint(endpoint.path, endpoint.method, params).get("labels", [])
        endpoint_score = scorer.score_endpoint({
            "export": "export" in labels,
            "admin": "admin" in labels,
            "graphql": "graphql" in labels,
            "internal": "internal" in labels,
            "uuid": "uuid" in endpoint.path.lower() or endpoint.path.lower().find("uuid") != -1,
            "numeric_id": any(part.isdigit() for part in endpoint.path.split("/")),
            "auth_smell": any(smell in endpoint.path.lower() for smell in ["org_id", "tenant_id", "workspace_id", "account_id", "user_id", "team_id"]),
        })
        entries.append({
            "id": endpoint.id,
            "target_id": endpoint.target_id,
            "path": endpoint.path,
            "method": endpoint.method,
            "labels": labels,
            "risk_score": endpoint_score["risk_score"],
        })
    
    entries.sort(key=lambda item: item["risk_score"], reverse=True)
    return {"high_signal": entries[:20], "total_endpoints": len(endpoints)}



@app.get("/attack/decision")
async def attack_decision(target_id: int | None = None, session: Session = Depends(get_db)):
    import json
    import ast
    logger = logging.getLogger("rastro.main")
    
    engine = AttackDecisionEngine()
    query = session.query(models.Endpoint)
    if target_id is not None:
        query = query.filter(models.Endpoint.target_id == target_id)
    endpoints = query.all()
    
    if not endpoints:
        return {"message": "No hay endpoints disponibles para evaluar."}

    endpoint_data = []
    for endpoint in endpoints:
        params = {}
        if endpoint.params:
            try:
                # Try JSON first (preferred)
                params = json.loads(endpoint.params)
            except (json.JSONDecodeError, ValueError):
                # Fallback: try to interpret as Python dict string (legacy)
                try:
                    params = ast.literal_eval(endpoint.params)
                except (ValueError, SyntaxError):
                    logger.warning(f"Could not parse params for endpoint {endpoint.id}: {endpoint.params[:100]}")
                    params = {}
        
        endpoint_data.append({
            "path": endpoint.path,
            "method": endpoint.method,
            "params": params,
            "target_id": endpoint.target_id,
        })

    return engine.evaluate_endpoints(endpoint_data)
