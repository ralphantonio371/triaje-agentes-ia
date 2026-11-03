"""
Agente Triador.

Núcleo del sistema: recibe la alerta enriquecida y produce un veredicto
estructurado (clase, severidad, técnica ATT&CK, justificación y
confianza en el rango [0, 1]). Su diseño sigue el patrón ReAct
(razonamiento y acción) con acciones acotadas al esquema de recuperación.

Regla de gobierno: toda alerta con confianza < 0.7, o clasificada como
VERDADERO_POSITIVO con severidad CRÍTICA o ALTA, pasa obligatoriamente
al supervisor humano (ver workflow.py).
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from src.config import (MODELO, OLLAMA_BASE_URL, REPORTADOR_TEMPERATURE,
                        SEVERIDADES_ESCALADO, TRIADOR_MAX_TOKENS,
                        TRIADOR_TEMPERATURE, TRIADOR_TOP_P, UMBRAL_CONFIDIANZA)
from src.schemas import AlertaEnriquecida, ClaseAlerta, Severidad, VeredictoTriaje

logger = logging.getLogger(__name__)

PROMPT_TRIADOR = (Path(__file__).resolve().parents[1] / "prompts" / "triador.txt").read_text(encoding="utf-8")

JSON_RE = re.compile(r"\{.*\}", re.S)


class AgenteTriador:
    """Clasifica la alerta con un LLM local (Ollama, Llama 3.1 8B)."""

    def __init__(self, llm=None, bitacora=None):
        self.llm = llm or self._llm_por_defecto()
        self.bitacora = bitacora

    # ------------------------------------------------------------------
    def _llm_por_defecto(self):
        try:
            from langchain_community.llms import Ollama
            return Ollama(
                model=MODELO,
                base_url=OLLAMA_BASE_URL,
                temperature=TRIADOR_TEMPERATURE,
                top_p=TRIADOR_TOP_P,
                num_predict=TRIADOR_MAX_TOKENS,
            )
        except Exception:
            logger.warning("Ollama no disponible; se requiere despliegue local.")
            raise

    # ------------------------------------------------------------------
    def _construir_prompt(self, alerta: AlertaEnriquecida) -> str:
        fragmentos = "\n\n".join(
            f"[FUENTE: {f.fuente}]\n{f.contenido}" for f in alerta.fragmentos
        )
        datos = json.dumps(alerta.model_dump(), ensure_ascii=False, indent=2)
        return (
            PROMPT_TRIADOR
            .replace("{{FRAGMENTOS_RAG}}", fragmentos or "(sin fragmentos)")
            .replace("{{ALERTA_JSON}}", datos)
        )

    # ------------------------------------------------------------------
    def clasificar(self, alerta: AlertaEnriquecida) -> VeredictoTriaje:
        prompt = self._construir_prompt(alerta)
        salida = self.llm.invoke(prompt)
        veredicto = self._parsear_salida(salida)
        if self.bitacora:
            self.bitacora.registrar("triador", alerta.alerta.id,
                                    "veredicto", veredicto.model_dump_json())
        return veredicto

    # ------------------------------------------------------------------
    def _parsear_salida(self, salida: str) -> VeredictoTriaje:
        """Valida la salida contra el esquema Pydantic.

        Si la salida no valida, el nodo se reintenta (hasta
        MAX_REINTENTOS_VALIDACION) antes de derivar al supervisor.
        """
        m = JSON_RE.search(salida)
        if not m:
            raise ValueError("Salida sin objeto JSON válido")
        datos = json.loads(m.group())
        return VeredictoTriaje(
            clase=ClaseAlerta(datos["clase"]),
            severidad=Severidad(datos["severidad"]),
            tecnica_attck=datos["tecnica_attck"],
            justificacion=datos["justificacion"],
            confianza=float(datos["confianza"]),
        )

    # ------------------------------------------------------------------
    @staticmethod
    def requiere_supervision_humana(veredicto: VeredictoTriaje) -> bool:
        """Regla de gobierno del sistema (human-in-the-loop)."""
        if veredicto.confianza < UMBRAL_CONFIDIANZA:
            return True
        if (veredicto.clase == ClaseAlerta.VERDADERO_POSITIVO
                and veredicto.severidad.value in SEVERIDADES_ESCALADO):
            return True
        return False
