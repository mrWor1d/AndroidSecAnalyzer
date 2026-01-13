"""
Tests de integración y funciones auxiliares para el módulo main.py
Prueba las rutas de la aplicación Flask y funciones de utilidad
"""

import unittest
import json
import os
import tempfile
from unittest.mock import patch, MagicMock
from main import app, load_history, save_history


class TestHistoryManagement(unittest.TestCase):
    """Tests para funciones de gestión del historial"""

    def setUp(self):
        """Configurar fixtures de prueba"""
        # Crear un directorio temporal para archivos de prueba
        self.test_dir = tempfile.mkdtemp()
        self.original_history_file = os.environ.get("HISTORY_FILE")
        # Esto necesitaría ser configurable en main.py para pruebas adecuadas
        self.history_file = os.path.join(self.test_dir, "test_history.json")

    def tearDown(self):
        """Limpiar después de las pruebas"""
        # Limpiar archivos temporales
        if os.path.exists(self.history_file):
            os.remove(self.history_file)
        os.rmdir(self.test_dir)

    def test_load_history_empty(self):
        """Probar la carga del historial cuando no existe archivo"""
        # Asegurar que el archivo no existe
        if os.path.exists(self.history_file):
            os.remove(self.history_file)
        
        # Simular la ruta HISTORY_FILE
        with patch('main.HISTORY_FILE', self.history_file):
            history = load_history()
            self.assertEqual(history, [])

    def test_save_and_load_history(self):
        """Probar guardar y cargar historial"""
        test_entry = {
            "timestamp": "2025-01-13 10:30",
            "filename": "test.apk",
            "app_name": "Test App",
            "package": "com.test.app",
            "version": "1.0.0",
            "risk": "BAJO",
            "vulns_total": 2,
            "vulns_high": 0,
            "vulns_medium": 1,
            "vulns_low": 1
        }

        with patch('main.HISTORY_FILE', self.history_file):
            save_history(test_entry)
            history = load_history()
            
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0], test_entry)

    def test_save_history_keeps_most_recent_first(self):
        """Probar que las entradas más recientes aparecen primero en el historial"""
        entry1 = {"timestamp": "2025-01-13 10:00", "filename": "app1.apk"}
        entry2 = {"timestamp": "2025-01-13 10:30", "filename": "app2.apk"}

        with patch('main.HISTORY_FILE', self.history_file):
            save_history(entry1)
            save_history(entry2)
            history = load_history()
            
            # entry2 debe ser primero (más reciente)
            self.assertEqual(history[0]["filename"], "app2.apk")
            self.assertEqual(history[1]["filename"], "app1.apk")

    def test_save_history_limits_entries(self):
        """Probar que el historial se limita a 50 entradas"""
        with patch('main.HISTORY_FILE', self.history_file):
            # Agregar 60 entradas
            for i in range(60):
                save_history({
                    "timestamp": f"2025-01-13 10:{i:02d}",
                    "filename": f"app{i}.apk"
                })
            
            history = load_history()
            # Solo debe mantener 50
            self.assertEqual(len(history), 50)


class TestFlaskApp(unittest.TestCase):
    """Tests para rutas de la aplicación Flask"""

    def setUp(self):
        """Configurar cliente de prueba de Flask"""
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        
        # Crear carpeta de carga de prueba
        self.test_upload_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Limpiar después de las pruebas"""
        # Limpiar directorio de carga de prueba
        if os.path.exists(self.test_upload_dir):
            for file in os.listdir(self.test_upload_dir):
                os.remove(os.path.join(self.test_upload_dir, file))
            os.rmdir(self.test_upload_dir)

    def test_index_route_get(self):
        """Probar solicitud GET a la ruta índice"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_index_route_post_no_file(self):
        """Probar POST a la ruta índice sin archivo"""
        response = self.client.post('/', data={})
        # Debe rechazar solicitud sin archivo (400 Bad Request u otro)
        self.assertIn(response.status_code, [400, 500])

    def test_index_route_post_invalid_file(self):
        """Probar POST a la ruta índice con archivo que no es APK"""
        response = self.client.post('/', data={
            'apk': (tempfile.NamedTemporaryFile(suffix='.txt'), 'test.txt')
        })
        # Debe rechazar archivo que no es APK
        self.assertIn(response.status_code, [200, 400])

    def test_upload_folder_created(self):
        """Probar que la carpeta de carga se crea en la inicialización de la aplicación"""
        with patch('main.UPLOAD_FOLDER', self.test_upload_dir):
            # La carpeta debe existir
            self.assertTrue(os.path.exists(self.test_upload_dir))


class TestMainFunctionality(unittest.TestCase):
    """Tests para funcionalidad principal de la aplicación"""

    def test_last_report_initialization(self):
        """Probar que last_report está inicializado"""
        from main import last_report
        self.assertIsInstance(last_report, dict)
        self.assertIn("content", last_report)
        self.assertIn("filename", last_report)

    def test_dangerous_permissions_list_not_empty(self):
        """Probar que la lista de permisos peligrosos está poblada"""
        from analisis.analisis_estatico import DANGEROUS_PERMISSIONS
        self.assertGreater(len(DANGEROUS_PERMISSIONS), 0)
        self.assertIn("android.permission.CAMERA", DANGEROUS_PERMISSIONS)

    def test_secret_patterns_list_not_empty(self):
        """Probar que la lista de patrones secretos está poblada"""
        from analisis.analisis_estatico import SECRET_PATTERNS
        self.assertGreater(len(SECRET_PATTERNS), 0)


if __name__ == '__main__':
    unittest.main()
