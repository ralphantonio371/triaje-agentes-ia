"""
Configuración central del workflow de triaje con agentes de IA.

Valores calibrados empíricamente sobre un conjunto de calibración de
50 alertas (excluido de la evaluación), según se describe en la
metodología del trabajo.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Modelo local (Ollama) — Llama 3.1 8B Instruct
# ---------------------------------------------------------------------------
MODELO = "llama3.1:8b-instruct"
OLLAMA_BASE_URL = "http://localhost:11434"

# Agente triador: la clasificación exige determinismo.
TRIADOR_TEMPERATURE = 0.1
TRIADOR_TOP_P = 0.9
TRIADOR_MAX_TOKENS = 1024

# Agente reportador: la redacción admite variabilidad.
REPORTADOR_TEMPERATURE = 0.4

# ---------------------------------------------------------------------------
# Reglas de gobierno (human-in-the-loop)
# ---------------------------------------------------------------------------
UMBRAL_CONFIDIANZA = 0.7          # confianza < 0.7 -> supervisor humano
SEVERIDADES_ESCALADO = {"CRITICA", "ALTA"}  # TP con estas severidades -> humano
MAX_REINTENTOS_VALIDACION = 2     # reintentos del nodo triador ante esquema inválido

# ---------------------------------------------------------------------------
# RAG
# ---------------------------------------------------------------------------
PRESUPUESTO_TOKENS_FRAGMENTOS = 4000   # presupuesto de tokens para fragmentos
FAISS_INDICE = "data/faiss/incidentes"
MITRE_CORPUS = "data/mitre/attack.json"
INVENTARIO_ACTIVOS = "data/inventario/activos.json"

# ---------------------------------------------------------------------------
# Persistencia y auditoría
# ---------------------------------------------------------------------------
SQLITE_DB = "data/triaje_state.db"      # estado del grafo + bitácora inmutable
BITACORA_TABLA = "bitacora_auditoria"

# ---------------------------------------------------------------------------
# Entrada (webhooks de Wazuh) y salida (gestor de incidentes / panel SOC)
# ---------------------------------------------------------------------------
WAZUH_WEBHOOK_HOST = "0.0.0.0"
WAZUH_WEBHOOK_PORT = 8080
WAZUH_WEBHOOK_PATH = "/wazuh/alerts"

# ---------------------------------------------------------------------------
# Etiquetas del laboratorio (referencia dorada)
# ---------------------------------------------------------------------------
N_ALERTAS = 300
N_VERDADEROS_POSITIVOS = 127
N_FALSOS_POSITIVOS_BENIGNOS = 173
