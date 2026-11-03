"""
Esquemas de salida validados con Pydantic.

Cada agente produce artefactos tipados y validados contra esquema;
si la salida del triador no valida, el nodo se reintenta hasta dos veces
antes de derivar la alerta al supervisor humano (ver workflow.py).
"""

from __future__ import annotations

from enum import Enum
from typing import List

from pydantic import BaseModel, Field, field_validator


class ClaseAlerta(str, Enum):
    VERDADERO_POSITIVO = "VERDADERO_POSITIVO"
    FALSO_POSITIVO = "FALSO_POSITIVO"
    BENIGNO = "BENIGNO"


class Severidad(str, Enum):
    CRITICA = "CRITICA"
    ALTA = "ALTA"
    MEDIA = "MEDIA"
    BAJA = "BAJA"


class AlertaNormalizada(BaseModel):
    """Esquema JSON común producido por el Agente Recolector."""

    id: str
    regla: str
    severidad_cruda: str
    campos_evento: dict
    activos_afectados: List[str]
    hash_evento: str


class FragmentoRecuperado(BaseModel):
    """Fragmento de conocimiento recuperado por RAG (única fuente citable)."""

    fuente: str
    contenido: str
    similitud: float


class AlertaEnriquecida(BaseModel):
    """Alerta normalizada + fragmentos recuperados (contexto del activo incluido)."""

    alerta: AlertaNormalizada
    fragmentos: List[FragmentoRecuperado] = []
    contexto_activo: dict = {}


class VeredictoTriaje(BaseModel):
    """Veredicto estructurado del Agente Triador.

    El campo confianza gobierna el paso a supervisión humana:
    toda alerta con confianza < UMBRAL_CONFIDIANZA (0.7), o clasificada
    como VERDADERO_POSITIVO con severidad CRITICA o ALTA, pasa
    obligatoriamente al supervisor humano.
    """

    clase: ClaseAlerta
    severidad: Severidad
    tecnica_attck: str = Field(pattern=r"^[Tt]\d{4}(\.\d{3})?$|^EVIDENCIA_INSUFICIENTE$")
    justificacion: str
    confianza: float = Field(ge=0.0, le=1.0)

    @field_validator("justificacion")
    @classmethod
    def _justificacion_no_vacia(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("La justificación no puede estar vacía")
        return v


class AccionRespuesta(BaseModel):
    """Acción de respuesta sugerida (nunca ejecutada por el sistema)."""

    tipo: str
    descripcion: str
    requiere_validacion_humana: bool = True


class ReporteIncidente(BaseModel):
    """Artefactos operativos producidos por el Agente Reportador."""

    resumen_ejecutivo: str
    ticket: dict
    acciones_respuesta: List[AccionRespuesta] = []
    escalado_humano: bool = False
