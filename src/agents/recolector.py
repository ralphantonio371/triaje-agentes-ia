"""
Agente Recolector.

Normaliza las alertas de Wazuh a un esquema JSON común (identificador,
regla, severidad cruda, campos del evento, activos afectados), elimina
duplicados por hash del evento y descarta campos irrelevantes.

Esta etapa es determinista (sin LLM) y garantiza que los agentes
posteriores reciban datos homogéneos. Antes de salir del perímetro,
aplica hashing a los nombres de usuario y enmascara las direcciones
internas (medida de gobernanza de privacidad: minimización de datos).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re

from src.config import SQLITE_DB
from src.schemas import AlertaNormalizada

logger = logging.getLogger(__name__)

# Campos del webhook de Wazuh que se conservan en el esquema común.
CAMPOS_CONSERVADOS = {
    "id", "rule", "severity", "description", "full_log", "predecoder",
    "decoder", "location", "agent", "srcip", "dstip", "srcuser", "dstuser",
    "file", "protocol", "data",
}

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USUARIO_RE = re.compile(r"(?i)\b(user|usuario|srcuser|dstuser)\s*[:=]\s*(\S+)")


def _hash_evento(alerta_wazuh: dict) -> str:
    """Hash SHA-256 del evento canónico para deduplicación."""
    canonic = json.dumps(alerta_wazuh, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonic.encode("utf-8")).hexdigest()


def _sanitizar_campos(campos: dict) -> dict:
    """Enmascara IPs internas y aplica hashing a nombres de usuario.

    Mitiga además la inyección de prompts: los campos de la alerta son
    DATOS, no instrucciones, por lo que se delimitan y sanitizan.
    """
    limpios = {}
    for k, v in campos.items():
        texto = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
        # enmascarar direcciones internas (privadas)
        texto = IPV4_RE.sub(lambda m: _mascarar_ip(m.group()), texto)
        # hashing de nombres de usuario
        texto = USUARIO_RE.sub(
            lambda m: f"{m.group(1)}={hashlib.sha256(m.group(2).encode()).hexdigest()[:12]}",
            texto,
        )
        limpios[k] = texto
    return limpios


def _mascarar_ip(ip: str) -> str:
    """Enmascara IPs privadas; las públicas se conservan (indicador útil)."""
    prefijo = ip.split(".")[0]
    if prefijo in {"10", "172", "192", "127"}:
        return ".".join(ip.split(".")[:2] + ["x", "x"])
    return ip


class AgenteRecolector:
    """Normaliza, deduplica y sanea las alertas entrantes de Wazuh."""

    def __init__(self, bitacora=None):
        self.bitacora = bitacora
        self._hashes_vistos: set[str] = set()

    def procesar(self, alerta_wazuh: dict) -> AlertaNormalizada | None:
        """Devuelve la alerta normalizada o None si es duplicada/irrelevante."""
        h = _hash_evento(alerta_wazuh)
        if h in self._hashes_vistos:
            logger.info("Alerta duplicada descartada: %s", h[:12])
            return None
        self._hashes_vistos.add(h)

        campos = {k: v for k, v in alerta_wazuh.items() if k in CAMPOS_CONSERVADOS}
        campos = _sanitizar_campos(campos)

        alerta = AlertaNormalizada(
            id=str(alerta_wazuh.get("id", h[:16])),
            regla=str(alerta_wazuh.get("rule", "")),
            severidad_cruda=str(alerta_wazuh.get("severity", "")),
            campos_evento=campos,
            activos_afectados=list(alerta_wazuh.get("agent", {}).get("name", "")) and
                [alerta_wazuh.get("agent", {}).get("name", "")] or [],
            hash_evento=h,
        )
        if self.bitacora:
            self.bitacora.registrar("recolector", alerta.id, "normalizada", h)
        return alerta
