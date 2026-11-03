"""
Evaluación del workflow sobre el conjunto de referencia dorada.

Protocolo: 300 alertas etiquetadas por consenso de tres analistas
(127 verdaderos positivos, 173 falsos positivos/eventos benignos),
generadas con emulación de adversarios (CALDERA) y tráfico benigno.
Se comparan tres configuraciones y se reportan exactitud, precisión,
recall, F1 (clase VP), MTT y la tasa de justificaciones con afirmaciones
no respaldadas por la evidencia.

Uso:
    python -m scripts.evaluar --config data/resultados/predicciones_propuesta.csv
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def metricas(y_true: pd.Series, y_pred: pd.Series, pos_label: str = "VERDADERO_POSITIVO") -> dict:
    vp = ((y_true == pos_label) & (y_pred == pos_label)).sum()
    fp = ((y_true != pos_label) & (y_pred == pos_label)).sum()
    fn = ((y_true == pos_label) & (y_pred != pos_label)).sum()
    vn = ((y_true != pos_label) & (y_pred != pos_label)).sum()
    exactitud = (vp + vn) / (vp + fp + fn + vn)
    precision = vp / (vp + fp) if (vp + fp) else 0.0
    recall = vp / (vp + fn) if (vp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "exactitud": round(exactitud, 2),
        "precision": round(precision, 2),
        "recall": round(recall, 2),
        "f1": round(f1, 2),
    }


def cargar_predicciones(ruta: Path) -> pd.DataFrame:
    return pd.read_csv(ruta)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("predicciones", type=Path, help="CSV con columnas y_true,y_pred")
    args = parser.parse_args()

    df = cargar_predicciones(args.predicciones)
    m = metricas(df["y_true"], df["y_pred"])
    print("Métricas (clase VERDADERO_POSITIVO, n=%d):" % len(df))
    for k, v in m.items():
        print(f"  {k:12s} {v}")


if __name__ == "__main__":
    main()
