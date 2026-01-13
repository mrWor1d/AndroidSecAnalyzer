"""
Pruebas unitarias para el módulo analisis_estatico
Prueba las funciones de análisis estático para vulnerabilidades de seguridad en APK
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from analisis.analisis_estatico import (
    DANGEROUS_PERMISSIONS,
    SECRET_PATTERNS,
    is_exported,
    get_apk_metadata
)


class TestDangerousPermissions(unittest.TestCase):
    """Pruebas para la detección de permisos peligrosos"""

    def test_dangerous_permissions_list_exists(self):
        """Prueba que la lista de permisos peligrosos está definida"""
        self.assertIsInstance(DANGEROUS_PERMISSIONS, list)
        self.assertGreater(len(DANGEROUS_PERMISSIONS), 0)

    def test_dangerous_permissions_contain_expected_permissions(self):
        """Prueba que la lista contiene los permisos peligrosos esperados"""
        expected_perms = [
            "android.permission.CAMERA",
            "android.permission.READ_SMS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS"
        ]
        for perm in expected_perms:
            self.assertIn(perm, DANGEROUS_PERMISSIONS)

    def test_dangerous_permissions_are_strings(self):
        """Prueba que todos los permisos son cadenas de texto"""
        for perm in DANGEROUS_PERMISSIONS:
            self.assertIsInstance(perm, str)
            self.assertTrue(perm.startswith("android.permission."))


class TestSecretPatterns(unittest.TestCase):
    """Pruebas para la detección de patrones de secretos"""

    def test_secret_patterns_list_exists(self):
        """Prueba que la lista de patrones de secretos está definida"""
        self.assertIsInstance(SECRET_PATTERNS, list)
        self.assertGreater(len(SECRET_PATTERNS), 0)

    def test_secret_patterns_structure(self):
        """Prueba que los patrones de secretos tienen la estructura correcta (regex, etiqueta)"""
        for pattern in SECRET_PATTERNS:
            self.assertIsInstance(pattern, tuple)
            self.assertEqual(len(pattern), 2)
            # El primer elemento debe ser una cadena (patrón regex)
            self.assertIsInstance(pattern[0], str)
            # El segundo elemento debe ser una etiqueta
            self.assertIsInstance(pattern[1], str)

    def test_secret_patterns_contain_expected_types(self):
        """Prueba que los patrones detectan los tipos de secretos esperados"""
        pattern_labels = [p[1] for p in SECRET_PATTERNS]
        expected_labels = ["API Key", "Password", "Secret/Token", "AWS Credentials"]
        for label in expected_labels:
            self.assertIn(label, pattern_labels)


class TestIsExported(unittest.TestCase):
    """Pruebas para la detección de exportación de componentes"""

    def test_is_exported_returns_boolean(self):
        """Prueba que is_exported retorna un booleano"""
        mock_apk = Mock()
        mock_apk.get_attribute_value.return_value = "true"
        
        result = is_exported(mock_apk, "com.example.MainActivity", "activity")
        self.assertIsInstance(result, bool)

    def test_is_exported_true(self):
        """Prueba la detección de componente exportado"""
        mock_apk = Mock()
        mock_apk.get_attribute_value.return_value = "true"
        
        result = is_exported(mock_apk, "com.example.MainActivity", "activity")
        self.assertTrue(result)

    def test_is_exported_false(self):
        """Prueba la detección de componente no exportado"""
        mock_apk = Mock()
        mock_apk.get_attribute_value.return_value = "false"
        
        result = is_exported(mock_apk, "com.example.MainActivity", "activity")
        self.assertFalse(result)

    def test_is_exported_none_defaults_to_false(self):
        """Prueba que el valor de retorno None usa False por defecto"""
        mock_apk = Mock()
        mock_apk.get_attribute_value.return_value = None
        
        result = is_exported(mock_apk, "com.example.MainActivity", "activity")
        self.assertFalse(result)

    def test_is_exported_exception_handling(self):
        """Prueba que las excepciones son capturadas y retornan False"""
        mock_apk = Mock()
        mock_apk.get_attribute_value.side_effect = Exception("Error")
        
        result = is_exported(mock_apk, "com.example.MainActivity", "activity")
        self.assertFalse(result)

    def test_is_exported_with_different_component_types(self):
        """Prueba is_exported con diferentes tipos de componentes"""
        mock_apk = Mock()
        mock_apk.get_attribute_value.return_value = "true"
        
        for comp_type in ["activity", "service", "receiver", "provider"]:
            result = is_exported(mock_apk, "com.example.Component", comp_type)
            self.assertTrue(result)
            # Verifica que se comprobó el tipo de componente correcto
            mock_apk.get_attribute_value.assert_called_with(
                comp_type, "exported", name="com.example.Component"
            )


class TestGetApkMetadata(unittest.TestCase):
    """Pruebas para la extracción de metadatos de APK"""

    def test_metadata_returns_dict(self):
        """Prueba que get_apk_metadata retorna un diccionario"""
        mock_apk = Mock()
        mock_apk.get_app_name.return_value = "Test App"
        mock_apk.get_package.return_value = "com.test.app"
        mock_apk.get_androidversion_name.return_value = "1.0.0"
        mock_apk.get_androidversion_code.return_value = "1"
        mock_apk.get_min_sdk_version.return_value = "21"
        mock_apk.get_target_sdk_version.return_value = "33"
        mock_apk.get_permissions.return_value = []
        mock_apk.get_activities.return_value = []
        mock_apk.get_services.return_value = []
        mock_apk.get_receivers.return_value = []

        with patch('analisis.analisis_estatico.APK', return_value=mock_apk):
            with patch('os.path.getsize', return_value=1024):
                result = get_apk_metadata("test.apk")
                self.assertIsInstance(result, dict)

    def test_metadata_contains_required_fields(self):
        """Prueba que los metadatos contienen todos los campos requeridos"""
        mock_apk = Mock()
        mock_apk.get_app_name.return_value = "Test App"
        mock_apk.get_package.return_value = "com.test.app"
        mock_apk.get_androidversion_name.return_value = "1.0.0"
        mock_apk.get_androidversion_code.return_value = "1"
        mock_apk.get_min_sdk_version.return_value = "21"
        mock_apk.get_target_sdk_version.return_value = "33"
        mock_apk.get_permissions.return_value = []
        mock_apk.get_activities.return_value = []
        mock_apk.get_services.return_value = []
        mock_apk.get_receivers.return_value = []

        with patch('analisis.analisis_estatico.APK', return_value=mock_apk):
            with patch('os.path.getsize', return_value=1024):
                result = get_apk_metadata("test.apk")
                
                required_fields = [
                    "app_name", "package", "version_name", "version_code",
                    "min_sdk", "target_sdk", "permissions_total",
                    "permissions_dangerous", "activities", "services",
                    "receivers", "file_size"
                ]
                for field in required_fields:
                    self.assertIn(field, result)

    def test_metadata_handles_exception(self):
        """Prueba que los metadatos retornan un diccionario de error en excepción"""
        with patch('analisis.analisis_estatico.APK', side_effect=Exception("Parse error")):
            result = get_apk_metadata("invalid.apk")
            
            # Debería retornar un diccionario de error
            self.assertIsInstance(result, dict)
            self.assertEqual(result["app_name"], "Error")
            self.assertIn("Parse error", result["package"])

    def test_metadata_dangerous_permissions_count(self):
        """Prueba que los permisos peligrosos se cuentan correctamente"""
        mock_apk = Mock()
        mock_apk.get_app_name.return_value = "Test App"
        mock_apk.get_package.return_value = "com.test.app"
        mock_apk.get_androidversion_name.return_value = "1.0.0"
        mock_apk.get_androidversion_code.return_value = "1"
        mock_apk.get_min_sdk_version.return_value = "21"
        mock_apk.get_target_sdk_version.return_value = "33"
        mock_apk.get_permissions.return_value = [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.INTERNET"
        ]
        mock_apk.get_activities.return_value = []
        mock_apk.get_services.return_value = []
        mock_apk.get_receivers.return_value = []

        with patch('analisis.analisis_estatico.APK', return_value=mock_apk):
            with patch('os.path.getsize', return_value=1024):
                result = get_apk_metadata("test.apk")
                
                self.assertEqual(result["permissions_total"], 3)
                # CAMERA y RECORD_AUDIO son peligrosos
                self.assertEqual(result["permissions_dangerous"], 2)

    def test_metadata_file_size_formatting(self):
        """Prueba que el tamaño de archivo está formateado correctamente"""
        mock_apk = Mock()
        mock_apk.get_app_name.return_value = "Test App"
        mock_apk.get_package.return_value = "com.test.app"
        mock_apk.get_androidversion_name.return_value = "1.0.0"
        mock_apk.get_androidversion_code.return_value = "1"
        mock_apk.get_min_sdk_version.return_value = "21"
        mock_apk.get_target_sdk_version.return_value = "33"
        mock_apk.get_permissions.return_value = []
        mock_apk.get_activities.return_value = []
        mock_apk.get_services.return_value = []
        mock_apk.get_receivers.return_value = []

        with patch('analisis.analisis_estatico.APK', return_value=mock_apk):
            # Prueba formato KB (< 1 MB)
            with patch('os.path.getsize', return_value=512 * 1024):
                result = get_apk_metadata("test.apk")
                self.assertIn("KB", result["file_size"])

            # Prueba formato MB (>= 1 MB)
            with patch('os.path.getsize', return_value=2 * 1024 * 1024):
                result = get_apk_metadata("test.apk")
                self.assertIn("MB", result["file_size"])


class TestIntegration(unittest.TestCase):
    """Pruebas de integración para el módulo analisis_estatico"""

    def test_analyze_apk_structure(self):
        """Prueba la estructura del valor de retorno de analyze_apk"""
        from analisis.analisis_estatico import analyze_apk
        
        # Create a mock APK that will pass analysis
        mock_apk = Mock()
        mock_apk.get_permissions.return_value = []
        mock_apk.get_attribute_value.return_value = "false"
        mock_apk.get_files.return_value = []
        mock_apk.get_activities.return_value = []
        mock_apk.get_services.return_value = []
        mock_apk.get_receivers.return_value = []
        mock_apk.get_min_sdk_version.return_value = "21"

        with patch('analisis.analisis_estatico.APK', return_value=mock_apk):
            result = analyze_apk("test.apk")
            
            # Debería retornar una lista de vulnerabilidades
            self.assertIsInstance(result, list)
            
            # Cada elemento debería tener la estructura requerida
            for vuln in result:
                self.assertIsInstance(vuln, dict)
                required_keys = ["title", "description", "solution", "file", "method", "evidence", "severity", "category"]
                for key in required_keys:
                    self.assertIn(key, vuln)


if __name__ == '__main__':
    unittest.main()
