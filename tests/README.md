# Documentación de Pruebas

## Descripción General

Este directorio contiene pruebas unitarias exhaustivas para el paquete **AndroidSecAnalyzer** (DroidSecAnalyzer).


## Archivos de Prueba

### `test_ai_classifier.py`
Pruebas para el módulo clasificador de riesgos IA (`analisis/ai_classifier.py`).

**Cobertura:**
- Lógica de clasificación de riesgos basada en puntuaciones de vulnerabilidades
- Pruebas de límites para umbrales de riesgo (BAJO, MEDIO, ALTO)
- Manejo de campos de severidad faltantes
- Cálculos de puntuación de severidad

**Pruebas Clave:**
- `test_empty_vulnerabilities_returns_bajo` - Lista vacía devuelve riesgo BAJO
- `test_high_level_classification` - Clasificación correcta de riesgo ALTO
- `test_mixed_severity_vulnerabilities_*` - Manejo de severidad mixta
- `test_severity_scores_constant` - Constantes de puntuación de severidad
- `test_thresholds_constants` - Validación de umbrales de riesgo

### `test_report_generator.py`
Pruebas para el módulo de generación de reportes (`reports/report_generator.py`).

**Cobertura:**
- Estructura y formato de reportes
- Listado y numeración de vulnerabilidades
- Cálculos de resumen de severidad
- Visualización de nivel de riesgo
- Manejo de campos faltantes

**Pruebas Clave:**
- `test_empty_vulnerabilities_report` - Reporte sin vulnerabilidades
- `test_multiple_vulnerabilities_count` - Conteo correcto de vulnerabilidades
- `test_severity_summary_count` - Categorización precisa de severidad
- `test_vulnerability_numbering` - Numeración secuencial de hallazgos
- `test_report_format_structure` - Secciones correctas del reporte

### `test_analisis_estatico.py`
Pruebas para el módulo de análisis estático (`analisis/analisis_estatico.py`).

**Cobertura:**
- Detección de permisos peligrosos
- Detección de patrones de secretos
- Verificación de exportación de componentes
- Extracción de metadatos de APK
- Manejo de errores y casos límite

**Pruebas Clave:**
- `TestDangerousPermissions.*` - Validación de lista de permisos
- `TestSecretPatterns.*` - Estructura de patrones regex
- `TestIsExported.*` - Detección de exportación de componentes
- `TestGetApkMetadata.*` - Extracción y formato de metadatos
- `TestIntegration.*` - Integración con análisis de APK

### `test_main.py`
Pruebas para la aplicación Flask y funcionalidad principal (`main.py`).

**Cobertura:**
- Gestión de historial (cargar/guardar)
- Funcionalidad de rutas Flask
- Limitación y ordenamiento de historial
- Inicialización de aplicación
- Constantes de configuración

**Pruebas Clave:**
- `test_load_history_empty` - Manejo de historial vacío
- `test_save_and_load_history` - Persistencia de historial
- `test_save_history_keeps_most_recent_first` - Ordenamiento de historial
- `test_save_history_limits_entries` - Límite de tamaño de historial (50 entradas)
- `test_index_route_get` - Manejo de solicitud GET en Flask
- `test_index_route_post_invalid_file` - Validación de archivos

### `test_integration.py`
Pruebas de integración end-to-end.

**Cobertura:**
- Flujo completo de análisis de APK (riesgo, reporte, metadatos)
- Integración de rutas Flask (GET/POST) y plantillas
- Validación de estructura de vulnerabilidades y severidades
- Manejo de errores: APK inválido, metadatos con error, campos faltantes
- Límites: listas grandes (100+ vulnerabilidades), límite de historial (50), longitud razonable de reportes

**Pruebas Clave:**
- `test_risk_scoring_workflow` - Clasificación de riesgo end-to-end
- `test_report_generation_complete` - Reporte con vulnerabilidades completas
- `test_history_workflow` - Historial con múltiples entradas y orden correcto
- `test_flask_get_index` / `test_flask_form_structure` / `test_flask_result_page_structure` - Integración Flask
- `test_invalid_apk_handling` / `test_metadata_error_handling` / `test_missing_fields_resilience` - Robustez ante errores
- `test_large_vulnerability_list` / `test_history_size_limit` / `test_report_length_reasonable` - Rendimiento y límites


## Ejecutar Pruebas

### Ejecutar todas las pruebas:
```bash
python -m unittest discover tests -v
```

### Ejecutar pruebas de integración:
```bash
python -m unittest tests.test_integration -v
```

### Ejecutar archivo de prueba específico:
```bash
python -m unittest tests.test_ai_classifier -v
```

### Ejecutar clase de prueba específica:
```bash
python -m unittest tests.test_ai_classifier.TestAIClassifier -v
```

### Ejecutar prueba específica:
```bash
python -m unittest tests.test_ai_classifier.TestAIClassifier.test_empty_vulnerabilities_returns_bajo -v
```

### Ejecutar pruebas con reporte de cobertura:
```bash
pip install coverage
coverage run -m unittest discover tests
coverage report
coverage html  # Genera reporte de cobertura en HTML
```

### Usar el script ejecutor de pruebas:
```bash
python tests/__init__.py
```


## Estadísticas de Pruebas

- **Áreas de Cobertura:**
  - Lógica de clasificación de riesgos
  - Generación de reportes
  - Funciones de análisis estático
  - Rutas de aplicación Flask
  - Gestión de historial
  - Manejo de errores


## Dependencias

Las pruebas usan el módulo `unittest` integrado de Python y `unittest.mock` para simular dependencias externas. No se requiere marco de pruebas adicional más allá de lo que está en `requirements.txt`.


## Estrategia de Simulación

- **Análisis de APK:** Usa `unittest.mock.Mock` para simular objetos de APK de Android
- **Rutas Flask:** Usa cliente de prueba de Flask para pruebas de integración
- **Operaciones de Archivo:** Usa `tempfile` para pruebas seguras del sistema de archivos
- **Dependencias Externas:** Simula componentes de androguard y Flask


## Notas

- Las pruebas están diseñadas para ser independientes y pueden ejecutarse en cualquier orden
- Los archivos temporales se limpian después de cada prueba
- Se usan objetos simulados para evitar dependencia de archivos APK reales
- Las pruebas de Flask se ejecutan en modo de prueba (sin inicio de servidor real)
- Todas las pruebas siguen el patrón AAA (Arrange, Act, Assert)
