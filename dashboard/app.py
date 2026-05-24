import ast
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st

try:
    import requests
except ImportError:
    requests = None
    import urllib.request as urlrequest
    import urllib.error as urlerror

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

from core.analysis.analyzer import EndpointAnalyzer
from core.scoring.scorer import Scorer
from database import db, models

st.set_page_config(page_title="Rastro", layout="wide", initial_sidebar_state="expanded")

# Initialize database when the dashboard starts
try:
    db.init_db()
except Exception:
    pass

# Ensure targets intelligence models are registered so tables get created
try:
    import core.targets.models as targets_models
except Exception:
    pass

analyzer = EndpointAnalyzer()
scorer = Scorer()

BACKEND_BASE = st.sidebar.text_input("Backend URL", "http://127.0.0.1:8000")
use_backend = st.sidebar.checkbox("Usar backend", value=True)


def backend_request(path: str, method: str = "GET", payload: dict | None = None) -> dict | None:
    if not use_backend or not BACKEND_BASE:
        return None
    url = BACKEND_BASE.rstrip("/") + path
    if requests:
        try:
            if method == "GET":
                response = requests.get(url, timeout=10)
            else:
                response = requests.post(url, json=payload or {}, timeout=60)
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            st.warning(f"Backend request failed: {exc}")
            return None
    try:
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urlrequest.Request(url, data=data, headers=headers)
        with urlrequest.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        st.warning(f"Backend request failed: {exc}")
        return None


def backend_health() -> tuple[str, str]:
    if not use_backend or not BACKEND_BASE:
        return "disabled", "Backend integration disabled"
    response = backend_request("/")
    if response and response.get("message"):
        return "connected", response["message"]
    return "offline", "No se pudo conectar al backend"


def scan_artifact_timestamp(target_name: str) -> str | None:
    summary_path = ROOT / "targets" / target_name / "analysis" / "summary.json"
    if summary_path.exists():
        return datetime.fromtimestamp(summary_path.stat().st_mtime).isoformat(sep=" ", timespec="seconds")
    latest = None
    recon_dir = ROOT / "targets" / target_name / "recon"
    if recon_dir.exists():
        for file in recon_dir.glob("**/*"):
            if file.is_file():
                modified = datetime.fromtimestamp(file.stat().st_mtime)
                if latest is None or modified > latest:
                    latest = modified
    return latest.isoformat(sep=" ", timespec="seconds") if latest else None


def get_last_scan_info(target_id: int) -> dict:
    session = db.SessionLocal()
    try:
        from database.models import ScanRun
        last = session.query(ScanRun).filter(ScanRun.target_id == target_id).order_by(ScanRun.started_at.desc()).first()
        if not last:
            return {"status": "none", "endpoint_count": 0, "started_at": None}
        return {"status": last.status or "unknown", "endpoint_count": last.endpoint_count or 0, "started_at": last.started_at.isoformat(sep=' ', timespec='seconds') if last.started_at else None}
    finally:
        session.close()


def copy_button(text: str, key: str):
    try:
        import streamlit.components.v1 as components
        escaped = text.replace("\n", "\\n").replace("\r", "")
        html = f"""
        <button onclick="navigator.clipboard.writeText(`{escaped}`)">Copiar</button>
        """
        components.html(html, height=30)
    except Exception:
        st.write("(Copia manual) ")


def load_scan_logs(target_name: str) -> dict[str, str]:
    logs = {}
    log_dirs = [ROOT / "targets" / target_name / "logs", ROOT / "targets" / target_name / "recon"]
    for log_dir in log_dirs:
        if log_dir.exists():
            for path in sorted(log_dir.glob("**/*.txt")):
                if path.is_file():
                    logs[path.name] = path.read_text(encoding="utf-8", errors="ignore")
    return logs


def format_params(raw: str) -> str:
    try:
        params = ast.literal_eval(raw) if raw else {}
        return json.dumps(params, indent=2, ensure_ascii=False)
    except Exception:
        return raw


def score_endpoint_record(endpoint: models.Endpoint) -> dict[str, Any]:
    params = {}
    try:
        params = ast.literal_eval(endpoint.params or "{}")
    except Exception:
        params = {}
    labels = analyzer.classify_endpoint(endpoint.path, endpoint.method, params).get("labels", [])
    score = scorer.score_endpoint({
        "export": "export" in labels,
        "admin": "admin" in labels,
        "graphql": "graphql" in labels,
        "internal": "internal" in labels,
        "uuid": "uuid" in endpoint.path.lower() or endpoint.path.lower().find("uuid") != -1,
        "numeric_id": any(part.isdigit() for part in endpoint.path.split("/")),
        "auth_smell": any(smell in endpoint.path.lower() for smell in ["org_id", "tenant_id", "workspace_id", "account_id", "user_id", "team_id"]),
    })
    return {
        "id": endpoint.id,
        "target_id": endpoint.target_id,
        "path": endpoint.path,
        "method": endpoint.method,
        "labels": labels,
        "score": score["risk_score"],
        "discovered_at": endpoint.discovered_at.isoformat(sep=" ", timespec="seconds") if endpoint.discovered_at else None,
    }


st.sidebar.header("Status")
health_state, health_message = backend_health()
if health_state == "connected":
    st.sidebar.success("Backend conectado")
elif health_state == "offline":
    st.sidebar.error("Backend offline")
else:
    st.sidebar.info("Backend deshabilitado")

st.sidebar.markdown(f"**Estado:** {health_message}")

st.title("Rastro — Dashboard")
st.markdown("Ciberrecon táctico con señales claras, interfaz ligera y modo oscuro sutil.")

tabs = st.tabs(["Targets", "Recon", "Endpoints", "High Signal", "Attack Decision", "Findings", "Daily Digest", "Logs", "Targets Intelligence"])

with tabs[0]:
    st.header("Targets")
    with st.expander("Crear nuevo target"):
        with st.form("create_target"):
            target_name = st.text_input("Nombre del target")
            target_domain = st.text_input("Dominio / URL principal")
            create_target = st.form_submit_button("Crear target")
            if create_target and target_name:
                session = db.SessionLocal()
                target = models.Target(name=target_name, domain=target_domain or None)
                session.add(target)
                session.commit()
                session.close()
                st.success(f"Target '{target_name}' creado")
                st.experimental_rerun()

    session = db.SessionLocal()
    targets = session.query(models.Target).order_by(models.Target.created_at.desc()).all()
    if targets:
        for target in targets:
            scan_time = scan_artifact_timestamp(target.name)
            scan_info = get_last_scan_info(target.id)
            # count endpoints
            ep_count = session.query(models.Endpoint).filter(models.Endpoint.target_id == target.id).count()
            st.markdown(f"**{target.name}** — {target.domain or 'sin dominio'}")
            cols = st.columns([2, 1, 1, 1])
            cols[0].write(f"`{target.id}`")
            cols[1].write(f"Último scan: {scan_time or 'nunca'}")
            cols[2].write(f"Estado: {scan_info.get('status')} — {scan_info.get('endpoint_count')} endpoints")
            cols[3].write(f"Creado: {target.created_at.isoformat(sep=' ', timespec='seconds')}")
            st.divider()
    else:
        st.info("No hay targets. Crea uno para comenzar.")
    session.close()

with tabs[1]:
    st.header("Recon")
    selected_target = None
    session = db.SessionLocal()
    targets = session.query(models.Target).order_by(models.Target.created_at.desc()).all()
    if targets:
        target_options = {f"{t.id}: {t.name}": t.id for t in targets}
        selected = st.selectbox("Selecciona un target para recon", list(target_options.keys()))
        selected_target = session.query(models.Target).filter(models.Target.id == target_options[selected]).first()
    else:
        st.warning("Crea un target primero.")

    if selected_target:
        st.markdown(f"### Recon para {selected_target.name}")
        st.write(f"Dominio: {selected_target.domain or 'no especificado'}")
        
        recon_mode = st.selectbox("Modo de recon", ["FAST", "DEEP", "API"], key="recon_mode_selector")
        
        last_scan = scan_artifact_timestamp(selected_target.name)
        scan_info = get_last_scan_info(selected_target.id)
        st.write(f"Último scan registrado: {last_scan or 'ninguno'}")
        st.write(f"Estado último scan: {scan_info.get('status')} — endpoints: {scan_info.get('endpoint_count')}")

        if st.button("Run Scan"):
            if not selected_target.domain:
                st.error("El target necesita un dominio para ejecutar un scan.")
            else:
                with st.spinner("Ejecutando scan..."):
                    payload = {"name": selected_target.name, "domain": selected_target.domain, "mode": recon_mode}
                    scan_result = backend_request("/scans", method="POST", payload=payload)
                if scan_result:
                    st.success("Scan completado")
                    st.json(scan_result)
                    # refresh counts
                    scan_info = get_last_scan_info(selected_target.id)
                    st.write(f"Endoints registrados: {scan_info.get('endpoint_count')}")
                    scan_id = scan_result.get("scan_id")
                    if scan_id:
                        st.write("Scan ID:", scan_id)
                else:
                    st.error("El scan no se completó. Verifica el backend.")

        # show recent scan runs
        runs = backend_request(f"/scan_runs?target_id={selected_target.id}")
        if runs:
            st.markdown("#### Ejecuciones recientes")
            for r in runs:
                cols = st.columns([1,1,1,2])
                cols[0].write(f"#{r['id']}")
                cols[1].write(r['status'])
                cols[2].write(r.get('endpoint_count') or 0)
                with cols[3]:
                    st.write(f"{r.get('started_at')} → {r.get('finished_at') or '-'}")
                    if st.button(f"Ver detalles {r['id']}", key=f"details_{r['id']}"):
                        details = backend_request(f"/scan_runs/{r['id']}")
                        st.json(details)

        st.markdown("#### Logs de scan")
        logs = load_scan_logs(selected_target.name)
        if logs:
            for name, content in logs.items():
                with st.expander(name, expanded=False):
                    st.code(content[:10000], language="text")
        else:
            st.info("No hay logs disponibles localmente para este target.")
    session.close()

with tabs[2]:
    st.header("Endpoints")
    try:
        from core.targets import scorer as targets_scorer
    except Exception:
        targets_scorer = None
    with st.expander("¿Cómo se calcula el score?", expanded=False):
        st.markdown("Scoring heurístico: se combinan indicadores como GraphQL, APIs, SaaS, admin, multi-tenant, export, y auth-heavy para producir `quality`, `complexity` y `roi`.")
        if targets_scorer:
            st.code('''Reglas principales:
- GraphQL: +20
- API density: +6 por API (máx 30)
- SaaS: +25 si probabilidad > 0.5
- B2B: +15
- Admin: +15
- Multi-tenant: +20
- Auth-heavy: +15
- Static: penaliza ruido''')
    session = db.SessionLocal()
    endpoints = session.query(models.Endpoint).order_by(models.Endpoint.discovered_at.desc()).all()
    if endpoints:
        selected_endpoint = st.selectbox(
            "Selecciona un endpoint",
            [f"{e.id}: {e.method} {e.path}" for e in endpoints],
        )
        endpoint_id = int(selected_endpoint.split(":")[0])
        endpoint = session.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
        if endpoint:
            params = {}
            try:
                params = ast.literal_eval(endpoint.params or "{}")
            except Exception:
                params = {}
            local_meta = analyzer.classify_endpoint(endpoint.path, endpoint.method, params)
            score_data = score_endpoint_record(endpoint)
            cols = st.columns(3)
            cols[0].metric("Endpoint score", score_data["score"])
            cols[1].metric("Discovered", score_data["discovered_at"] or "-" )
            cols[2].metric("Target ID", score_data["target_id"])

            st.markdown("#### Metadata y etiquetas")
            st.json(local_meta)
            st.markdown("#### Parámetros")
            st.code(format_params(endpoint.params or "{}"), language="json")
            st.markdown("#### Path")
            st.code(endpoint.path)
            copy_button(endpoint.path, key=f"copy_{endpoint.id}")

            with st.expander("AI summary"):
                if st.button("Generar AI summary", key=f"ai_summary_{endpoint.id}"):
                    analysis = backend_request(
                        "/analysis/endpoint",
                        method="POST",
                        payload={"path": endpoint.path, "method": endpoint.method, "params": params},
                    )
                    if analysis:
                        st.json(analysis.get("ai") or analysis)
                    else:
                        st.error("No se pudo obtener resumen AI.")
    else:
        st.info("No hay endpoints registrados.")
    session.close()

with tabs[3]:
    st.header("High Signal")
    digest = backend_request("/digest")
    if digest and digest.get("high_signal"):
        for item in digest["high_signal"]:
            st.markdown(f"- **{item['method']} {item['path']}** — score {item['risk_score']} — target {item['target_id']}")
    else:
        st.info("No hay señales de alto impacto. Ejecuta un scan o comprueba el backend.")

with tabs[4]:
    st.header("Attack Decision")
    st.markdown("Prioriza objetivos con vectores de ataque y sugiere pruebas manuales basadas en el estado actual del backend.")
    session = db.SessionLocal()
    targets = session.query(models.Target).order_by(models.Target.created_at.desc()).all()
    if targets:
        target_options = {f"{t.id}: {t.name}": t.id for t in targets}
        selected = st.selectbox("Selecciona un target para la decisión de ataque", list(target_options.keys()), key="attack_decision_target")
        target_id = target_options[selected]
        selected_target = session.query(models.Target).filter(models.Target.id == target_id).first()
        if selected_target:
            if st.button("Generar decisión de ataque"):
                with st.spinner("Solicitando evaluación de ataque..."):
                    decision = backend_request(f"/attack/decision?target_id={selected_target.id}")
                if decision:
                    st.success("Decisión generada")
                    st.markdown(f"**Target:** {selected_target.name} — {selected_target.domain or 'sin dominio'}")
                    st.markdown(f"**Motivo principal:** {decision.get('summary') or 'No hay resumen disponible.'}")

                    attack_vectors = decision.get('attack_vectors') or []
                    if attack_vectors:
                        st.markdown("#### Vectores de ataque detectados")
                        for vector in attack_vectors:
                            with st.expander(f"{vector.get('vector')} — score {vector.get('confidence')}"):
                                st.write(vector.get('description'))
                                if vector.get('suggestions'):
                                    st.markdown("**Sugerencias:**")
                                    for suggestion in vector.get('suggestions'):
                                        st.markdown(f"- {suggestion}")

                    high_value = decision.get('high_value_targets') or []
                    if high_value:
                        st.markdown("#### Objetivos de alto valor")
                        for item in high_value:
                            st.markdown(f"- `{item.get('method')} {item.get('path')}` — {item.get('reason')} — score {item.get('risk_score')}")
                            if item.get('notes'):
                                st.write(item.get('notes'))

                    ownership = decision.get('ownership_risks') or []
                    if ownership:
                        st.markdown("#### Riesgos de filtración de propiedad / credenciales")
                        for risk in ownership:
                            st.markdown(f"- {risk.get('issue')} — {risk.get('confidence')}")
                            if risk.get('details'):
                                st.write(risk.get('details'))

                    suggestions = decision.get('manual_test_suggestions') or []
                    if suggestions:
                        st.markdown("#### Pruebas manuales sugeridas")
                        for suggestion in suggestions:
                            st.markdown(f"- {suggestion}")
                else:
                    st.error("No se pudo obtener la decisión de ataque. Verifica el backend.")
    else:
        st.info("Crea un target para generar decisiones de ataque.")
    session.close()

with tabs[5]:
    st.header("Findings")
    session = db.SessionLocal()
    findings = session.query(models.Finding).order_by(models.Finding.created_at.desc()).all()
    if findings:
        for finding in findings:
            st.markdown(f"- **{finding.severity or 'info'}** | {finding.title}")
            st.write(f"Target ID: {finding.target_id} — Endpoint ID: {finding.endpoint_id or 'N/A'}")
            if finding.description:
                st.write(finding.description)
            st.write(f"Creado: {finding.created_at.isoformat(sep=' ', timespec='seconds')}")
            st.divider()
    else:
        st.info("No se han guardado hallazgos aún.")
    session.close()

with tabs[6]:
    st.header("Daily Digest")
    digest = backend_request("/digest")
    if digest and digest.get("high_signal"):
        st.write("Resumen diario de endpoints de alto riesgo:")
        for item in digest["high_signal"]:
            st.markdown(
                f"- `{item['method']} {item['path']}` — score **{item['risk_score']}** — target **{item['target_id']}**"
            )
    else:
        st.info("No se pudo cargar el digest. Verifica el backend y el estado de conexión.")

with tabs[7]:
    st.header("Logs")
    session = db.SessionLocal()
    targets = session.query(models.Target).order_by(models.Target.created_at.desc()).all()
    if targets:
        target_options = {f"{t.id}: {t.name}": t.id for t in targets}
        selected = st.selectbox("Selecciona un target para ver logs", list(target_options.keys()), key="logs_target_select")
        target_id = target_options[selected]
        target = session.query(models.Target).filter(models.Target.id == target_id).first()
        if target:
            logs = load_scan_logs(target.name)
            if logs:
                st.write(f"Logs para **{target.name}**:")
                for name, content in sorted(logs.items()):
                    with st.expander(f"📄 {name}"):
                        st.code(content[:20000], language="text")
            else:
                st.info(f"No hay logs para {target.name}. Ejecuta un scan primero.")
    else:
        st.info("No hay targets registrados.")
    session.close()

with tabs[8]:
    st.header("Targets Intelligence")
    st.markdown("Información agregada desde programas públicos (HackerOne, Bugcrowd, Intigriti, YesWeHack)")

    # simple controls
    sort_opt = st.selectbox("Ordenar por", ["quality_score", "roi_score", "complexity_score", "noise_score", "created_at"])
    show_only_priority = st.checkbox("Mostrar solo prioridades", value=False)

    # load intelligence
    session = db.SessionLocal()
    try:
        from core.targets.models import TargetIntel

        q = session.query(TargetIntel).order_by(getattr(TargetIntel, sort_opt).desc())
        items = q.limit(200).all()

        displayed = []
        for t in items:
            meta = {
                "id": t.id,
                "name": t.name,
                "domain": t.domain,
                "quality_score": t.quality_score or 0,
                "roi_score": t.roi_score or 0,
                "complexity_score": t.complexity_score or 0,
                "noise_score": t.noise_score or 0,
                "graphql": bool(t.graphql_detected),
                "api_count": int(t.api_density or 0),
                "saas_prob": float(t.saas_probability or 0.0),
                "admin": bool(t.admin_detected),
                "multi_tenant": bool(t.multi_tenant),
            }
            if show_only_priority:
                if not (meta["quality_score"] >= 50 or meta["roi_score"] >= 40):
                    continue
            displayed.append((t, meta))

        if not displayed:
            st.info("No hay objetivos de inteligencia cargados. Usa core.targets.hunter.ingest_programs() para importar.")
        else:
            for t, meta in displayed:
                cols = st.columns([3, 1, 1, 1, 1])
                cols[0].markdown(f"**{t.name or 'sin nombre'}** — {t.domain or 'sin dominio'}")
                cols[1].metric("Quality", meta["quality_score"])
                cols[2].metric("ROI", meta["roi_score"])
                cols[3].metric("Complexity", meta["complexity_score"])
                cols[4].metric("Noise", meta["noise_score"])

                with st.expander("Detalles / acciones"):
                    st.write(meta)
                    action_cols = st.columns([1, 1, 1])
                    if action_cols[0].button("Bookmark", key=f"bm_{t.id}"):
                        t.tags = (t.tags or "") + ",bookmarked"
                        session.add(t)
                        session.commit()
                        st.success("Bookmark agregado")
                    if action_cols[1].button("Send to Recon", key=f"recon_{t.id}"):
                        # create a Target entry usable by recon pipeline
                        from database import models as dbmodels

                        new_session = db.SessionLocal()
                        try:
                            exists = new_session.query(dbmodels.Target).filter(dbmodels.Target.name == (t.name or t.domain)).first()
                            if not exists:
                                created = dbmodels.Target(name=(t.name or t.domain), domain=t.domain)
                                new_session.add(created)
                                new_session.commit()
                                st.success("Target añadido para recon")
                            else:
                                st.info("Target ya existe en la base de datos de targets")
                        finally:
                            new_session.close()
                    if action_cols[2].button("Add Note", key=f"note_{t.id}"):
                        note = st.text_area("Nota rápida")
                        if note:
                            t.notes = (t.notes or "") + "\n" + note
                            session.add(t)
                            session.commit()
                            st.success("Nota guardada")
    finally:
        session.close()
