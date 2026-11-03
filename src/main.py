"""
Punto de entrada del workflow: servidor webhook para las alertas de Wazuh.

Las alertas ingresan por webhooks desde Wazuh (4.7); el grafo de estados
procesa cada una y la salida se deposita en el gestor de incidentes y en
el panel del SOC.

Uso:
    python -m src.main            # servidor webhook
    python -m src.main --demo     # procesa una alerta de ejemplo
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from src.config import WAZUH_WEBHOOK_HOST, WAZUH_WEBHOOK_PATH, WAZUH_WEBHOOK_PORT
from src.workflow import EstadoTriage, construir_grafo

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

EJEMPLO_ALERTA = Path(__file__).resolve().parents[1] / "data" / "ejemplos" / "alerta_wazuh.json"


def procesar_alerta(alerta_wazuh: dict) -> EstadoTriage:
    """Ejecuta el grafo completo para una alerta entrante."""
    grafo = construir_grafo()
    estado = EstadoTriage(alerta_wazuh=alerta_wazuh)
    resultado = grafo.invoke(estado, config={"recursion_limit": 20})
    return resultado


def main() -> None:
    parser = argparse.ArgumentParser(description="Workflow de triaje con agentes de IA")
    parser.add_argument("--demo", action="store_true", help="Procesa una alerta de ejemplo")
    args = parser.parse_args()

    if args.demo:
        alerta = json.loads(EJEMPLO_ALERTA.read_text(encoding="utf-8"))
        estado = procesar_alerta(alerta)
        if estado.reporte:
            print(json.dumps(estado.reporte.model_dump(), indent=2, ensure_ascii=False))
        else:
            print("La alerta fue descartada (duplicada) o derivada al supervisor.")
        return

    # Servidor webhook para Wazuh (referencia; en producción usar uvicorn).
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != WAZUH_WEBHOOK_PATH:
                self.send_response(404)
                self.end_headers()
                return
            longitud = int(self.headers.get("Content-Length", 0))
            cuerpo = self.rfile.read(longitud)
            alerta = json.loads(cuerpo)
            procesar_alerta(alerta)
            self.send_response(202)
            self.end_headers()

    logger.info("Escuchando webhooks de Wazuh en %s:%s%s",
                WAZUH_WEBHOOK_HOST, WAZUH_WEBHOOK_PORT, WAZUH_WEBHOOK_PATH)
    HTTPServer((WAZUH_WEBHOOK_HOST, WAZUH_WEBHOOK_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
