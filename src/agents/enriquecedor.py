"""
Agente Enriquecedor.

Aplica RAG (generación aumentada por recuperación) para anclar las
decisiones en conocimiento verificable. A partir de la alerta
normalizada recupera:

  1. Las técnicas relevantes de la base de conocimiento MITRE ATT&CK.
  2. Los incidentes históricos más similares (vectores en FAISS).
  3. El contexto del activo afectado desde el inventario
     (criticidad, sistema operativo, rol).

Los fragmentos recuperados, acotados por un presupuesto de tokens,
constituyen la única fuente de conocimiento externo que el agente
triador puede citar.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from src.config import FAISS_INDICE, INVENTARIO_ACTIVOS, MITRE_CORPUS, PRESUPUESTO_TOKENS_FRAGMENTOS
from src.schemas import AlertaEnriquecida, AlertaNormalizada, FragmentoRecuperado

logger = logging.getLogger(__name__)


class AgenteEnriquecedor:
    """Recupera contexto verificable (MITRE ATT&CK + historial + activos)."""

    def __init__(self, retriever=None, bitacora=None):
        self.retriever = retriever
        self.bitacora = bitacora

    # ------------------------------------------------------------------
    def procesar(self, alerta: AlertaNormalizada) -> AlertaEnriquecida:
        fragmentos: list[FragmentoRecuperado] = []

        # (1) Técnicas relevantes de MITRE ATT&CK
        fragmentos += self._recuperar_mitre(alerta)

        # (2) Incidentes históricos similares (FAISS)
        if self.retriever is not None:
            fragmentos += self._recuperar_historico(alerta)

        # (3) Contexto del activo desde el inventario
        contexto_activo = self._contexto_activo(alerta)

        fragmentos = self._acotar_presupuesto(fragmentos)

        if self.bitacora:
            self.bitacora.registrar("enriquecedor", alerta.id, "enriquecida",
                                   f"{len(fragmentos)} fragmentos")
        return AlertaEnriquecida(
            alerta=alerta,
            fragmentos=fragmentos,
            contexto_activo=contexto_activo,
        )

    # ------------------------------------------------------------------
    def _recuperar_mitre(self, alerta: AlertaNormalizada) -> list[FragmentoRecuperado]:
        """Recupera técnicas ATT&CK plausibles a partir de la regla y el log."""
        corpus = Path(MITRE_CORPUS)
        if not corpus.exists():
            logger.warning("Corpus MITRE no disponible: %s", corpus)
            return []
        tecnicas = json.loads(corpus.read_text(encoding="utf-8"))
        texto_alerta = json.dumps(alerta.model_dump(), ensure_ascii=False).lower()
        out = []
        for t in tecnicas:
            etiquetas = " ".join(t.get("keywords", [])).lower()
            if any(k in texto_alerta for k in t.get("keywords", [])):
                out.append(FragmentoRecuperado(
                    fuente=f"MITRE ATT&CK {t['id']}",
                    contenido=f"{t['id']} — {t['name']} (táctica: {t['tactic']}). "
                              f"{t.get('description', '')}",
                    similitud=1.0,
                ))
        return out[:5]

    # ------------------------------------------------------------------
    def _recuperar_historico(self, alerta: AlertaNormalizada) -> list[FragmentoRecuperado]:
        """Búsqueda de similitud en FAISS sobre el historial de incidentes."""
        try:
            import faiss
        except ImportError:
            logger.warning("FAISS no instalado; se omite el historial.")
            return []
        indice_path = Path(FAISS_INDICE)
        if not indice_path.with_suffix(".faiss").exists():
            logger.warning("Índice FAISS no disponible: %s", indice_path)
            return []
        # Implementación de referencia: embebido del texto de la alerta y
        # búsqueda de los k vecinos más cercanos con sus metadatos.
        logger.info("Recuperación FAISS pendiente de embebidos reales (esqueleto).")
        return []

    # ------------------------------------------------------------------
    def _contexto_activo(self, alerta: AlertaNormalizada) -> dict:
        inv = Path(INVENTARIO_ACTIVOS)
        if not inv.exists():
            return {}
        inventario = json.loads(inv.read_text(encoding="utf-8"))
        for activo in alerta.activos_afectados:
            if activo in inventario:
                return inventario[activo]
        return {}

    # ------------------------------------------------------------------
    def _acotar_presupuesto(self, fragmentos: list[FragmentoRecuperado]) -> list[FragmentoRecuperado]:
        """Acota los fragmentos al presupuesto de tokens del LLM."""
        total = 0
        out = []
        for f in fragmentos:
            n = len(f.contenido) // 4  # aproximación ~4 chars/token
            if total + n > PRESUPUESTO_TOKENS_FRAGMENTOS:
                break
            out.append(f)
            total += n
        return out
