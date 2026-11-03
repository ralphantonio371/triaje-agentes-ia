"""Agentes especializados del workflow de triaje.

- recolector:  normaliza y deduplica (determinista, sin LLM)
- enriquecedor: RAG (MITRE ATT&CK + historial FAISS + inventario)
- triador:     clasificación con LLM local y veredicto estructurado
- reportador:  resumen ejecutivo, ticket y acciones sugeridas
"""

from src.agents.enriquecedor import AgenteEnriquecedor
from src.agents.recolector import AgenteRecolector
from src.agents.reportador import AgenteReportador
from src.agents.triador import AgenteTriador

__all__ = [
    "AgenteRecolector",
    "AgenteEnriquecedor",
    "AgenteTriador",
    "AgenteReportador",
]
