"""
Pruebas unitarias para el módulo ai_classifier
Prueba la lógica de clasificación de riesgo basada en puntuaciones de vulnerabilidades
"""

import unittest
from analisis.ai_classifier import classify_risk, SEVERITY_SCORES, THRESHOLD_ALTO, THRESHOLD_MEDIO


class TestAIClassifier(unittest.TestCase):
    """Pruebas para el módulo clasificador de IA"""

    def test_empty_vulnerabilities_returns_bajo(self):
        """Prueba que una lista vacía de vulnerabilidades retorna riesgo BAJO"""
        result = classify_risk([])
        self.assertEqual(result, "BAJO")

    def test_single_low_severity_vulnerability(self):
        """Prueba clasificación con una vulnerabilidad de severidad BAJA"""
        vulns = [{"severity": "LOW"}]
        result = classify_risk(vulns)
        self.assertEqual(result, "BAJO")

    def test_multiple_low_severity_vulnerabilities(self):
        """Prueba clasificación con múltiples vulnerabilidades de severidad BAJA"""
        vulns = [
            {"severity": "LOW"},
            {"severity": "LOW"},
            {"severity": "LOW"},
            {"severity": "LOW"},
            {"severity": "LOW"},
            {"severity": "LOW"},
            {"severity": "LOW"},
            {"severity": "LOW"},
        ]
        result = classify_risk(vulns)
        # 8 * 2 = 16 > 15, por lo que debería ser MEDIO
        self.assertEqual(result, "MEDIO")

    def test_single_medium_severity_vulnerability(self):
        """Prueba clasificación con una vulnerabilidad de severidad MEDIA"""
        vulns = [{"severity": "MEDIUM"}]
        result = classify_risk(vulns)
        self.assertEqual(result, "BAJO")

    def test_medium_level_classification(self):
        """Prueba que la clasificación retorna MEDIO en el umbral"""
        # THRESHOLD_MEDIO = 15, MEDIUM = 5 puntos
        vulns = [
            {"severity": "MEDIUM"},
            {"severity": "MEDIUM"},
            {"severity": "MEDIUM"},
        ]
        result = classify_risk(vulns)
        # 3 * 5 = 15, debería ser MEDIO
        self.assertEqual(result, "MEDIO")

    def test_single_high_severity_vulnerability(self):
        """Prueba clasificación con una vulnerabilidad de severidad ALTA"""
        vulns = [{"severity": "HIGH"}]
        result = classify_risk(vulns)
        self.assertEqual(result, "BAJO")

    def test_high_level_classification(self):
        """Prueba que la clasificación retorna ALTO en el umbral"""
        # THRESHOLD_ALTO = 30, HIGH = 10 puntos
        vulns = [
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
        ]
        result = classify_risk(vulns)
        # 3 * 10 = 30, debería ser ALTO
        self.assertEqual(result, "ALTO")

    def test_mixed_severity_vulnerabilities_to_alto(self):
        """Prueba clasificación con severidades mixtas resultando en ALTO"""
        vulns = [
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
        ]
        result = classify_risk(vulns)
        # 1*10 + 2*5 + 1*2 = 22, debería ser MEDIO
        self.assertEqual(result, "MEDIO")

    def test_mixed_severity_vulnerabilities_boundary(self):
        """Prueba clasificación en el límite de ALTO"""
        vulns = [
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
        ]
        result = classify_risk(vulns)
        # 4*10 = 40 >= 30, debería ser ALTO
        self.assertEqual(result, "ALTO")

    def test_missing_severity_defaults_to_medium(self):
        """Prueba que un campo de severidad faltante usa por defecto puntuación MEDIUM"""
        vulns = [
            {"title": "Some vuln without severity"},
            {"severity": "HIGH"},
        ]
        result = classify_risk(vulns)
        # 1*5 (por defecto) + 1*10 = 15, debería ser MEDIO
        self.assertEqual(result, "MEDIO")

    def test_info_severity_has_zero_score(self):
        """Prueba que la severidad INFO tiene 0 puntos"""
        vulns = [
            {"severity": "INFO"},
            {"severity": "INFO"},
            {"severity": "INFO"},
        ]
        result = classify_risk(vulns)
        # 3 * 0 = 0 < 15, debería ser BAJO
        self.assertEqual(result, "BAJO")

    def test_many_info_and_low_vulnerabilities(self):
        """Prueba con muchas vulnerabilidades de baja severidad"""
        vulns = [
            {"severity": "INFO"},
            {"severity": "LOW"},
            {"severity": "LOW"},
            {"severity": "LOW"},
            {"severity": "LOW"},
        ]
        result = classify_risk(vulns)
        # 0 + 4*2 = 8 < 15, debería ser BAJO
        self.assertEqual(result, "BAJO")

    def test_severity_scores_constant(self):
        """Prueba que SEVERITY_SCORES tiene los valores esperados"""
        expected = {
            "HIGH": 10,
            "MEDIUM": 5,
            "LOW": 2,
            "INFO": 0
        }
        self.assertEqual(SEVERITY_SCORES, expected)

    def test_thresholds_constants(self):
        """Prueba que los umbrales están correctamente definidos"""
        self.assertEqual(THRESHOLD_ALTO, 30)
        self.assertEqual(THRESHOLD_MEDIO, 15)


if __name__ == '__main__':
    unittest.main()
