"""
Clasificador de riesgo basado en score ponderado
"""

SEVERITY_SCORES = {
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0
}

# Umbrales conservadores
THRESHOLD_ALTO = 30
THRESHOLD_MEDIO = 15


def classify_risk(vulnerabilities):
    """
    Clasifica el nivel de riesgo basado en score ponderado:
    - ALTA = 10 puntos
    - MEDIA = 5 puntos
    - BAJA = 2 puntos

    Umbrales:
    - ALTO: >= 30 puntos
    - MEDIO: >= 15 puntos
    - BAJO: < 15 puntos
    """
    if not vulnerabilities:
        return "BAJO"

    total_score = sum(
        SEVERITY_SCORES.get(v.get("severity", "MEDIUM"), 5)
        for v in vulnerabilities
    )

    if total_score >= THRESHOLD_ALTO:
        return "ALTO"
    elif total_score >= THRESHOLD_MEDIO:
        return "MEDIO"
    else:
        return "BAJO"
