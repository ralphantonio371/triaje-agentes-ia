"""
Agente Reportador.

Transforma el veredicto en artefactos operativos: un resumen ejecutivo
de máximo 150 palabras, un ticket estructurado para el gestor de
incidentes y, en el caso de verdaderos positivos, una lista de acciones
de respuesta sugeridas (aislamiento, bloqueo, recolección de evidencia).

El agente no ejecuta ninguna acción: las recomendaciones se registran
para validación humana (decisión justificada en la sección de ética
del trabajo: responsabilidad humana aumentada, no autonomía plena).
"""

from __future__ import annotations

import json
import logging

from src.config import MODELO, OLLAMA_BASE_URL, REPORTADOR_TEMPERATURE
from src.schemas import (AccionRespuesta, AlertaEnriquecida, ClaseAlerta,
                         ReporteIncidente, VeredictoTriaje)

logger = logging.getLogger(__name__)

PROMPT_REPORTADOR = """ROL: Eres un redactor de reportes de seguridad de un SOC.
CONTEXTO: Recibirás la alerta enriquecida y el veredicto validado del triador.
INSTRUCCIONES:
1. Redacta un resumen ejecutivo de MÁXIMO 150 palabras, en español.
2. Construye un ticket estructurado (título, prioridad, técnica ATT&CK,
   evidencia citada con su fuente, recomendación).
3. Si el veredicto es VERDADERO_POSITIVO, sugiere acciones de respuesta
   no destructivas (aislamiento, bloqueo, recolección de evidencia).
GUARDRAILS:
- No inventes indicadores que no estén en la evidencia.
- No recomiendas acciones destructivas.
- No incluyas datos personales identificables.
SALIDA: únicamente un objeto JSON válido con las claves:
{"resumen_ejecutivo": "", "ticket": {}, "acciones_respuesta": []}
"""


class AgenteReportador:
    """Genera resumen ejecutivo, ticket y acciones sugeridas."""

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
                temperature=REPORTADOR_TEMPERATURE,
            )
        except Exception:
            logger.warning("Ollama no disponible; se requiere despliegue local.")
            raise

    # ------------------------------------------------------------------
    def reportar(self, alerta: AlertaEnriquecida, veredicto: VeredictoTriaje,
                 escalado: bool) -> ReporteIncidente:
        entrada = json.dumps({
            "alerta": alerta.alerta.model_dump(),
            "fragmentos": [f.model_dump() for f in alerta.fragmentos],
            "veredicto": veredicto.model_dump(),
            "escalado_humano": escalado,
        }, ensure_ascii=False, indent=2)

        salida = self.llm.invoke(PROMPT_REPORTADOR + "\n\nDATOS:\n" + entrada)
        datos = json.loads(salida[salida.index("{"):salida.rindex("}") + 1])

        acciones = [
            AccionRespuesta(**a) for a in datos.get("acciones_respuesta", [])
        ]
        reporte = ReporteIncidente(
            resumen_ejecutivo=datos["resumen_ejecutivo"],
            ticket=datos["ticket"],
            acciones_respuesta=acciones,
            escalado_humano=escalado,
        )
        if self.bitacora:
            self.bitacora.registrar("reportador", alerta.alerta.id,
                                    "reporte", reporte.model_dump_json())
        return reporte
