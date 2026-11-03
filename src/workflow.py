"""
Orquestación del workflow con LangGraph.

El flujo se modela como un grafo de estados con reintentos: si la salida
del triador no valida contra el esquema Pydantic, el nodo se reintenta
hasta dos veces antes de derivar la alerta al supervisor humano.

La persistencia del estado en SQLite habilita la reanudación del proceso
tras fallos y la auditoría posterior. El ciclo completo es:

    entrada (webhook Wazuh) → procesamiento (4 agentes) → salida
    (gestor de incidentes / panel SOC) → supervisión humana (conf < 0.7)
"""

from __future__ import annotations

import logging

from src.agents import (AgenteEnriquecedor, AgenteRecolector,
                        AgenteReportador, AgenteTriador)
from src.config import MAX_REINTENTOS_VALIDACION
from src.schemas import ReporteIncidente, VeredictoTriaje

logger = logging.getLogger(__name__)


class EstadoTriage:
    """Estado común compartido por los agentes a lo largo del grafo."""

    def __init__(self, alerta_wazuh: dict):
        self.alerta_wazuh = alerta_wazuh
        self.alerta_normalizada = None
        self.alerta_enriquecida = None
        self.veredicto: VeredictoTriaje | None = None
        self.reporte: ReporteIncidente | None = None
        self.escalado_humano = False
        self.reintentos = 0
        self.errores: list[str] = []


def construir_grafo():
    """Construye el grafo LangGraph del workflow de triaje."""
    from langgraph.graph import END, StateGraph

    recolector = AgenteRecolector()
    enriquecedor = AgenteEnriquecedor()
    triador = AgenteTriador()
    reportador = AgenteReportador()

    grafo = StateGraph(EstadoTriage)

    # ------------------------------------------------------------------
    def nodo_recolector(estado: EstadoTriage) -> EstadoTriage:
        estado.alerta_normalizada = recolector.procesar(estado.alerta_wazuh)
        if estado.alerta_normalizada is None:
            estado.errores.append("duplicada")
        return estado

    def nodo_enriquecedor(estado: EstadoTriage) -> EstadoTriage:
        estado.alerta_enriquecida = enriquecedor.procesar(estado.alerta_normalizada)
        return estado

    def nodo_triador(estado: EstadoTriage) -> EstadoTriage:
        try:
            estado.veredicto = triador.clasificar(estado.alerta_enriquecida)
            estado.reintentos = 0
        except Exception as exc:
            estado.reintentos += 1
            estado.errores.append(str(exc))
        return estado

    def decidir_tras_triador(estado: EstadoTriage) -> str:
        if estado.veredicto is None:
            if estado.reintentos <= MAX_REINTENTOS_VALIDACION:
                return "reintentar_triador"
            return "escalar_humano"
        if triador.requiere_supervision_humana(estado.veredicto):
            return "escalar_humano"
        return "reportar"

    def nodo_supervisor_humano(estado: EstadoTriage) -> EstadoTriage:
        """Nodo human-in-the-loop: el analista valida o corrige el veredicto."""
        logger.info("Alerta %s derivada al supervisor humano",
                    estado.alerta_normalizada.id)
        estado.escalado_humano = True
        return estado

    def nodo_reportador(estado: EstadoTriage) -> EstadoTriage:
        estado.reporte = reportador.reportar(
            estado.alerta_enriquecida, estado.veredicto, estado.escalado_humano
        )
        return estado

    def nodo_salida(estado: EstadoTriage) -> EstadoTriage:
        """Deposita la salida en el gestor de incidentes y el panel del SOC."""
        logger.info("Reporte emitido para la alerta %s",
                    estado.alerta_normalizada.id)
        return estado

    # ------------------------------------------------------------------
    grafo.add_node("recolector", nodo_recolector)
    grafo.add_node("enriquecedor", nodo_enriquecedor)
    grafo.add_node("triador", nodo_triador)
    grafo.add_node("supervisor_humano", nodo_supervisor_humano)
    grafo.add_node("reportador", nodo_reportador)
    grafo.add_node("salida", nodo_salida)

    grafo.set_entry_point("recolector")
    grafo.add_edge("recolector", "enriquecedor")
    grafo.add_edge("enriquecedor", "triador")
    grafo.add_conditional_edges(
        "triador",
        decidir_tras_triador,
        {
            "reintentar_triador": "triador",
            "escalar_humano": "supervisor_humano",
            "reportar": "reportador",
        },
    )
    grafo.add_edge("supervisor_humano", "reportador")
    grafo.add_edge("reportador", "salida")
    grafo.add_edge("salida", END)

    return grafo.compile()
