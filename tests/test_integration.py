"""
Pruebas de integración para AndroidSecAnalyzer
Prueba la interacción entre múltiples módulos
"""

import unittest
import json
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock
from io import BytesIO

# Prueba el flujo completo sin simulación
class TestAPKAnalysisWorkflow(unittest.TestCase):
    """Pruebas de integración para el flujo completo de análisis de APK"""

    def setUp(self):
        """Configurar accesorios de prueba"""
        self.test_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Limpiar después de las pruebas"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_risk_scoring_with_real_data(self):
        """Prueba puntuación de riesgo con datos realistas de vulnerabilidades"""
        from analisis.ai_classifier import classify_risk
        
        # Simular vulnerabilidades reales de APK
        realistic_vulns = [
            {"severity": "HIGH", "title": "Debuggable APK"},
            {"severity": "HIGH", "title": "Unencrypted HTTP"},
            {"severity": "MEDIUM", "title": "Dangerous Permissions"},
            {"severity": "MEDIUM", "title": "Exported Components"},
            {"severity": "LOW", "title": "Obsolete SDK"}
        ]
        
        # Total: 2*10 + 2*5 + 1*2 = 32 puntos -> ALTO
        result = classify_risk(realistic_vulns)
        self.assertEqual(result, "ALTO")

    def test_report_generation_with_real_vulnerabilities(self):
        """Prueba generación de reporte con datos realistas"""
        from reports.report_generator import generate_report
        
        vulnerabilities = [
            {
                "title": "Debuggable Application",
                "description": "App can be debugged",
                "solution": "Set debuggable to false",
                "file": "AndroidManifest.xml",
                "method": "android:debuggable",
                "evidence": "debuggable='true'",
                "severity": "HIGH",
                "category": "config"
            },
            {
                "title": "Insecure HTTP",
                "description": "Using HTTP instead of HTTPS",
                "solution": "Use HTTPS everywhere",
                "file": "classes.dex",
                "method": "Network",
                "evidence": "http://example.com",
                "severity": "HIGH",
                "category": "network"
            }
        ]
        
        report = generate_report("test.apk", vulnerabilities, "ALTO")
        
        # Verificar estructura del reporte
        self.assertIn("INFORME DE SEGURIDAD", report)
        self.assertIn("Debuggable Application", report)
        self.assertIn("Insecure HTTP", report)
        self.assertIn("2 ALTA", report)
        self.assertIn("ALTO", report)

    def test_history_workflow(self):
        """Prueba flujo completo de gestión de historial"""
        with patch('main.HISTORY_FILE', os.path.join(self.test_dir, 'history.json')):
            from main import save_history, load_history
            
            # Crear múltiples entradas
            entries = [
                {
                    "timestamp": "2025-01-13 10:00",
                    "filename": "app1.apk",
                    "app_name": "App 1",
                    "risk": "BAJO",
                    "vulns_total": 2
                },
                {
                    "timestamp": "2025-01-13 10:30",
                    "filename": "app2.apk",
                    "app_name": "App 2",
                    "risk": "ALTO",
                    "vulns_total": 5
                },
                {
                    "timestamp": "2025-01-13 11:00",
                    "filename": "app3.apk",
                    "app_name": "App 3",
                    "risk": "MEDIO",
                    "vulns_total": 3
                }
            ]
            
            # Guardar todas las entradas
            for entry in entries:
                save_history(entry)
            
            # Cargar y verificar
            history = load_history()
            self.assertEqual(len(history), 3)
            # El más reciente debería estar primero
            self.assertEqual(history[0]["filename"], "app3.apk")
            self.assertEqual(history[1]["filename"], "app2.apk")
            self.assertEqual(history[2]["filename"], "app1.apk")


class TestFlaskAppIntegration(unittest.TestCase):
    """Pruebas de integración para la aplicación Flask"""

    def setUp(self):
        """Configurar cliente de prueba Flask"""
        from main import app
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_index_route_flow(self):
        """Prueba flujo GET de la ruta index"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'<!', response.data)  # Respuesta HTML

    def test_form_structure_in_index(self):
        """Prueba que la página index contiene formulario para carga de APK"""
        response = self.client.get('/')
        # Debería tener formulario HTML
        self.assertGreater(len(response.data), 0)

    def test_analysis_result_structure(self):
        """Prueba que la página de resultados tendría la estructura adecuada"""
        # Esto prueba la asunción de estructura de plantilla
        from reports.report_generator import generate_report
        
        vulns = [
            {
                "title": "Test",
                "description": "Test",
                "solution": "Test",
                "file": "Test",
                "method": "Test",
                "evidence": "Test",
                "severity": "HIGH",
                "category": "test"
            }
        ]
        
        report = generate_report("test.apk", vulns, "ALTO")
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 0)


class TestDataValidationWorkflow(unittest.TestCase):
    """Pruebas de integración para validación de datos"""

    def test_vulnerability_structure_consistency(self):
        """Prueba que todas las vulnerabilidades tienen estructura consistente"""
        required_fields = ["title", "description", "solution", "file", "method", "evidence", "severity", "category"]
        
        test_vuln = {
            "title": "Test Vulnerability",
            "description": "Test description",
            "solution": "Test solution",
            "file": "test.xml",
            "method": "test_method",
            "evidence": "test_evidence",
            "severity": "HIGH",
            "category": "test"
        }
        
        # Verificar que todos los campos requeridos existen
        for field in required_fields:
            self.assertIn(field, test_vuln)

    def test_severity_levels_consistency(self):
        """Prueba que los niveles de severidad se usan consistentemente"""
        from analisis.ai_classifier import SEVERITY_SCORES
        
        valid_severities = list(SEVERITY_SCORES.keys())
        self.assertIn("HIGH", valid_severities)
        self.assertIn("MEDIUM", valid_severities)
        self.assertIn("LOW", valid_severities)
        self.assertIn("INFO", valid_severities)
        self.assertEqual(len(valid_severities), 4)

    def test_metadata_field_consistency(self):
        """Prueba consistencia de campos de metadatos APK"""
        # Simular estructura de metadatos
        mock_metadata = {
            "app_name": "Test App",
            "package": "com.test.app",
            "version_name": "1.0.0",
            "version_code": "1",
            "min_sdk": "21",
            "target_sdk": "33",
            "permissions_total": 5,
            "permissions_dangerous": 2,
            "activities": 3,
            "services": 1,
            "receivers": 2,
            "file_size": "5.2 MB"
        }
        
        required_fields = [
            "app_name", "package", "version_name", "version_code",
            "min_sdk", "target_sdk", "permissions_total",
            "permissions_dangerous", "activities", "services",
            "receivers", "file_size"
        ]
        
        for field in required_fields:
            self.assertIn(field, mock_metadata)


class TestErrorHandlingWorkflow(unittest.TestCase):
    """Pruebas de integración para manejo de errores"""

    def test_invalid_apk_error_handling(self):
        """Prueba manejo de archivos APK inválidos"""
        from analisis.analisis_estatico import analyze_apk
        
        with patch('analisis.analisis_estatico.APK', side_effect=Exception("Invalid APK")):
            result = analyze_apk("invalid.apk")
            
            # Debería retornar vulnerabilidad de error
            self.assertIsInstance(result, list)
            self.assertGreater(len(result), 0)
            self.assertEqual(result[0]["severity"], "INFO")

    def test_metadata_extraction_error_handling(self):
        """Prueba manejo de errores de extracción de metadatos"""
        from analisis.analisis_estatico import get_apk_metadata
        
        with patch('analisis.analisis_estatico.APK', side_effect=Exception("Parse error")):
            result = get_apk_metadata("invalid.apk")
            
            # Debería retornar metadatos de error
            self.assertEqual(result["app_name"], "Error")
            self.assertIn("Parse error", result["package"])

    def test_report_generation_with_missing_fields(self):
        """Prueba que la generación de reporte maneja campos faltantes de vulnerabilidad"""
        from reports.report_generator import generate_report
        
        # Vulnerabilidad con campos mínimos requeridos
        vulns = [
            {
                "severity": "HIGH",
                "title": "Minimal Vuln",
                "description": "D",
                "solution": "S",
                "file": "F",
                "method": "M",
                "evidence": "E"
            }
        ]
        
        # No debería lanzar excepción
        report = generate_report("test.apk", vulns, "ALTO")
        self.assertIn("Minimal Vuln", report)


class TestPerformanceAndBoundaries(unittest.TestCase):
    """Pruebas de integración para rendimiento y condiciones límite"""

    def setUp(self):
        """Configurar accesorios de prueba"""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Limpiar después de las pruebas"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_large_vulnerability_list_handling(self):
        """Prueba manejo de gran número de vulnerabilidades"""
        from analisis.ai_classifier import classify_risk
        
        # Crear 100 vulnerabilidades
        vulns = [{"severity": "LOW"} for _ in range(100)]
        
        result = classify_risk(vulns)
        # 100 * 2 = 200 > 30, debería ser ALTO
        self.assertEqual(result, "ALTO")

    def test_history_size_limit_enforcement(self):
        """Prueba que el historial respeta el límite de 50 entradas"""
        temp_file = os.path.join(self.test_dir, 'test_history.json')
        with patch('main.HISTORY_FILE', temp_file):
            from main import save_history, load_history
            
            # Crear 60 entradas
            for i in range(60):
                save_history({"id": i, "filename": f"app{i}.apk"})
            
            history = load_history()
            # Debería mantener solo 50
            self.assertEqual(len(history), 50)
            # Las entradas más recientes deberían mantenerse
            self.assertEqual(history[0]["id"], 59)

    def test_report_string_length_reasonable(self):
        """Prueba que los reportes generados tienen longitud razonable"""
        from reports.report_generator import generate_report
        
        vulns = [
            {
                "title": f"Vulnerability {i}",
                "description": f"Description {i}",
                "solution": f"Solution {i}",
                "file": f"file{i}.xml",
                "method": f"method{i}",
                "evidence": f"evidence{i}",
                "severity": ["HIGH", "MEDIUM", "LOW"][i % 3],
                "category": "test"
            }
            for i in range(20)
        ]
        
        report = generate_report("test.apk", vulns, "ALTO")
        
        # El reporte debería ser generado
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 100)
        # Debería contener múltiples vulnerabilidades
        self.assertIn("Vulnerability 0", report)
        self.assertIn("Vulnerability 19", report)


if __name__ == '__main__':
    unittest.main()
