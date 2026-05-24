RASTRO v1.0
=================

Semi-Autonomous Bug Bounty Operating System — Diseño inicial y artefactos.

Objetivo: ayudar a cazar fallos de autorización, IDOR y problemas de APIs con un enfoque automatizado y local-first.

Quickstart (WSL Ubuntu):

1. Crear virtualenv:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Inicializar base de datos:

```bash
python scripts/bootstrap.py
```

3. Ejecutar backend:

```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

4. En otra terminal, ejecutar dashboard Streamlit:

```bash
streamlit run dashboard/app.py
```

### Endpoints disponibles

- `POST /targets` — crear un target
- `GET /targets` — listar targets
- `GET /targets/{target_id}/summary` — meta y prioridad del target
- `POST /endpoints` — registrar un endpoint
- `GET /endpoints` — listar endpoints
- `POST /findings` — guardar hallazgos
- `GET /findings` — listar hallazgos
- `GET /attack/decision` — generar la decisión de ataque, vectores y pruebas sugeridas
- `POST /analysis/endpoint` — análisis local + AI de un endpoint
- `POST /scans` — ejecutar recon local en un target (FAST/DEEP/API)
- `GET /digest` — obtener digest diario de endpoints de mayor riesgo

### UI

El dashboard ofrece:

- gestión de targets
- creación de endpoints
- análisis de endpoints y etiquetas de riesgo
- scoring de prioridad de target y endpoint
- pestaña Attack Decision con priorización de vectores y pruebas manuales sugeridas
- generación de hipótesis AI usando Ollama (si está disponible)

Lee `ARCHITECTURE.md` para una descripción del diseño del pipeline, los componentes y la filosofía de señal sobre ruido.

Estructura inicial creada por Rastro.

---

## Screenshots

(Placeholder) Añade capturas en `screenshots/` y actualiza esta sección con rutas a las imágenes.

---

## First-run setup (herramientas externas)

Estas son instrucciones mínimas para instalar las utilidades recomendadas. Ajusta según tu sistema.

### subfinder (ProjectDiscovery)

```bash
# usando go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# asegúrate de que $GOPATH/bin está en tu PATH
```

### katana (ProjectDiscovery)

```bash
# descarga binario o usa release
# ejemplo (Linux x86_64):
wget -qO- https://github.com/projectdiscovery/katana/releases/latest/download/katana-linux-amd64.tar.gz | tar xvz -C /usr/local/bin
```

### httpx (ProjectDiscovery)

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### nuclei (opcional)

```bash
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### gowitness (opcional)

```bash
# instalar desde release o usar cargo/homebrew según plataforma
```

### Ollama (opcional, local LLM)

Sigue las instrucciones en https://ollama.com/ para instalar y ejecutar Ollama localmente. Rastro detecta su disponibilidad y falla con gracia si no está presente.

---

