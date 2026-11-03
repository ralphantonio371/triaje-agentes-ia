"""
Bitácora inmutable de auditoría.

Cada transición del workflow queda registrada en SQLite: la persistencia
del estado habilita la reanudación del proceso tras fallos y la
auditoría posterior de cada decisión (trazabilidad exigida por la
normativa de protección de datos).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time

from src.config import BITACORA_TABLA, SQLITE_DB


class BitacoraAuditoria:
    """Registro append-only: cada entrada encadena el hash de la anterior."""

    def __init__(self, db_path: str = SQLITE_DB):
        self.conn = sqlite3.connect(db_path)
        self._crear_tabla()
        self._hash_anterior = self._ultimo_hash()

    def _crear_tabla(self) -> None:
        self.conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {BITACORA_TABLA} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                agente TEXT NOT NULL,
                alerta_id TEXT NOT NULL,
                evento TEXT NOT NULL,
                detalle TEXT,
                hash_prev TEXT,
                hash_reg TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def _ultimo_hash(self) -> str:
        fila = self.conn.execute(
            f"SELECT hash_reg FROM {BITACORA_TABLA} ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return fila[0] if fila else "GENESIS"

    def registrar(self, agente: str, alerta_id: str, evento: str, detalle: str) -> None:
        ts = time.time()
        entrada = json.dumps(
            {"ts": ts, "agente": agente, "alerta_id": alerta_id,
             "evento": evento, "detalle": detalle},
            sort_keys=True, ensure_ascii=False,
        )
        hash_reg = hashlib.sha256(
            (self._hash_anterior + entrada).encode("utf-8")
        ).hexdigest()
        self.conn.execute(
            f"INSERT INTO {BITACORA_TABLA} (ts, agente, alerta_id, evento, detalle, hash_prev, hash_reg) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, agente, alerta_id, evento, detalle, self._hash_anterior, hash_reg),
        )
        self.conn.commit()
        self._hash_anterior = hash_reg
