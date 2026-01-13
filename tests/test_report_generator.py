"""
Pruebas unitarias para el módulo report_generator
Prueba la funcionalidad de generación de reportes
"""

import unittest
from reports.report_generator import generate_report


class TestReportGenerator(unittest.TestCase):
    """Pruebas para el módulo generador de reportes"""

    def test_empty_vulnerabilities_report(self):
        """Prueba generación de reporte sin vulnerabilidades"""
        filename = "test_app.apk"
        vulnerabilities = []
        risk = "BAJO"

        report = generate_report(filename, vulnerabilities, risk)

        # Debe contener encabezado
        self.assertIn("INFORME DE SEGURIDAD - DROIDSECANALYZER", report)
        self.assertIn(filename, report)
        self.assertIn(risk, report)
        self.assertIn("Vulnerabilidades encontradas: 0", report)

    def test_single_vulnerability_report(self):
        """Prueba generación de reporte con una vulnerabilidad"""
        filename = "test_app.apk"
        vulnerabilities = [
            {
                "title": "Test Vulnerability",
                "description": "Test description",
                "solution": "Test solution",
                "file": "AndroidManifest.xml",
                "method": "test_method",
                "evidence": "test_evidence",
                "severity": "HIGH"
            }
        ]
        risk = "ALTO"

        report = generate_report(filename, vulnerabilities, risk)

        # Debe contener detalles de la vulnerabilidad
        self.assertIn("Test Vulnerability", report)
        self.assertIn("Test description", report)
        self.assertIn("Test solution", report)
        self.assertIn("HIGH", report)
        self.assertIn("AndroidManifest.xml", report)
        self.assertIn("test_method", report)
        self.assertIn("test_evidence", report)

    def test_multiple_vulnerabilities_count(self):
        """Prueba que el reporte cuente correctamente las vulnerabilidades"""
        filename = "test_app.apk"
        vulnerabilities = [
            {"severity": "HIGH", "title": "Vuln 1", "description": "D1", "solution": "S1",
             "file": "F1", "method": "M1", "evidence": "E1"},
            {"severity": "MEDIUM", "title": "Vuln 2", "description": "D2", "solution": "S2",
             "file": "F2", "method": "M2", "evidence": "E2"},
            {"severity": "LOW", "title": "Vuln 3", "description": "D3", "solution": "S3",
             "file": "F3", "method": "M3", "evidence": "E3"},
        ]
        risk = "MEDIO"

        report = generate_report(filename, vulnerabilities, risk)

        # Debe contar correctamente
        self.assertIn("Vulnerabilidades encontradas: 3", report)
        # El resumen debe mostrar los conteos correctos
        self.assertIn("1 ALTA | 1 MEDIA | 1 BAJA", report)

    def test_severity_summary_count(self):
        """Prueba que el resumen de severidad se calcula correctamente"""
        filename = "test_app.apk"
        vulnerabilities = [
            {"severity": "HIGH", "title": "H1", "description": "D", "solution": "S",
             "file": "F", "method": "M", "evidence": "E"},
            {"severity": "HIGH", "title": "H2", "description": "D", "solution": "S",
             "file": "F", "method": "M", "evidence": "E"},
            {"severity": "MEDIUM", "title": "M1", "description": "D", "solution": "S",
             "file": "F", "method": "M", "evidence": "E"},
            {"severity": "MEDIUM", "title": "M2", "description": "D", "solution": "S",
             "file": "F", "method": "M", "evidence": "E"},
            {"severity": "MEDIUM", "title": "M3", "description": "D", "solution": "S",
             "file": "F", "method": "M", "evidence": "E"},
            {"severity": "LOW", "title": "L1", "description": "D", "solution": "S",
             "file": "F", "method": "M", "evidence": "E"},
        ]
        risk = "ALTO"

        report = generate_report(filename, vulnerabilities, risk)

        # El resumen debe mostrar: 2 ALTA | 3 MEDIA | 1 BAJA
        self.assertIn("2 ALTA | 3 MEDIA | 1 BAJA", report)

    def test_vulnerability_numbering(self):
        """Prueba que las vulnerabilidades estén numeradas secuencialmente"""
        filename = "test_app.apk"
        vulnerabilities = [
            {"severity": "HIGH", "title": "Vuln 1", "description": "D1", "solution": "S1",
             "file": "F1", "method": "M1", "evidence": "E1"},
            {"severity": "MEDIUM", "title": "Vuln 2", "description": "D2", "solution": "S2",
             "file": "F2", "method": "M2", "evidence": "E2"},
        ]
        risk = "MEDIO"

        report = generate_report(filename, vulnerabilities, risk)

        # Debe contener vulnerabilidades numeradas
        self.assertIn("1. [HIGH]", report)
        self.assertIn("2. [MEDIUM]", report)

    def test_report_format_structure(self):
        """Prueba que el reporte tenga la estructura correcta"""
        filename = "test_app.apk"
        vulnerabilities = [
            {"severity": "HIGH", "title": "Test", "description": "D", "solution": "S",
             "file": "F", "method": "M", "evidence": "E"}
        ]
        risk = "ALTO"

        report = generate_report(filename, vulnerabilities, risk)

        # Debe contener todas las secciones requeridas
        self.assertIn("=====", report)
        self.assertIn("Aplicacion analizada:", report)
        self.assertIn("Nivel de riesgo global:", report)
        self.assertIn("Resumen:", report)
        self.assertIn("Descripcion:", report)
        self.assertIn("Ubicacion:", report)
        self.assertIn("Fichero:", report)
        self.assertIn("Metodo:", report)
        self.assertIn("Evidencia:", report)
        self.assertIn("Recomendacion:", report)
        self.assertIn("Generado por DroidSecAnalyzer", report)

    def test_report_contains_risk_level(self):
        """Prueba que el reporte muestre el nivel de riesgo correcto"""
        filename = "test_app.apk"
        vulnerabilities = []

        for risk_level in ["BAJO", "MEDIO", "ALTO"]:
            report = generate_report(filename, vulnerabilities, risk_level)
            self.assertIn(f"Nivel de riesgo global: {risk_level}", report)

    def test_missing_severity_defaults_to_medium(self):
        """Prueba el manejo de vulnerabilidades sin campo de severidad"""
        filename = "test_app.apk"
        vulnerabilities = [
            {"title": "Test", "description": "D", "solution": "S",
             "file": "F", "method": "M", "evidence": "E"}
            # Sin campo de severidad
        ]
        risk = "BAJO"

        # No debe lanzar una excepción
        report = generate_report(filename, vulnerabilities, risk)
        self.assertIn("Test", report)


if __name__ == '__main__':
    unittest.main()
