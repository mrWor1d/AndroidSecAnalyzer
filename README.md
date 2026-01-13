# DroidSecAnalyzer (DSA)

Herramienta web para analizar vulnerabilidades de seguridad en aplicaciones Android (APK).

## Descripción

DroidSecAnalyzer realiza análisis estático de archivos APK detectando:

- Permisos peligrosos (SMS, contactos, cámara, ubicación, etc.)
- Modo debug activado
- Backup de datos permitido
- URLs HTTP sin cifrar
- Componentes exportados sin protección
- Secretos hardcodeados (API keys, passwords)
- SDK mínimo obsoleto

## Requisitos

- Python 3.8+ (probado 3.8–3.11)
- Docker
- pip

## Instalación (local)

```bash
pip install -r requirements.txt
```

## Ejecución (local)

```bash
python main.py
```

La aplicación estará disponible en `http://localhost:5000` (modo local).


## Ejecución con Docker

Construir la imagen:
```bash
docker build -t androidsecanalyzer .
```

Ejecutar el contenedor (puerto 8000 expuesto por Flask dentro del contenedor):
```bash
docker run --rm -p 8000:8000 androidsecanalyzer
```

La aplicación estará disponible en `http://localhost:8000` (modo Docker).

Para persistir archivos subidos e historial fuera del contenedor:
```bash
docker run --rm -p 8000:8000 \
	-v ${PWD}/uploads:/app/uploads \
	-v ${PWD}/history.json:/app/history.json \
	androidsec-analyzer
```

## Uso

1. Acceder a la página principal
2. Subir un archivo APK (arrastrando o seleccionando)
3. Ver los resultados del análisis con vulnerabilidades agrupadas por severidad
4. Descargar el informe en formato TXT

## Estructura

```
├── Dockerfile              # Imagen Docker (Flask en puerto 8000)
├── .dockerignore           # Exclusiones de build
├── history.json            # Historial de analisis
├── requirements.txt        # Dependencias Python
├── main.py                 # Aplicación Flask principal
├── scripts/
│   ├── run_tests.py        # Test runner con menú interactivo
│   ├── run_docker_app.sh   # Construir un contenedor con la imagen Docker
│   ├── ci.py               # Pipeline de CI local
│   └── pre-commit-hook.py  # Hook de pre-commit
├── analisis/
│   ├── analisis_estatico.py   # Lógica de análisis con androguard
│   └── ai_classifier.py       # Clasificador de riesgo
├── reports/
│   └── report_generator.py    # Generador de informes
├── templates/
│   ├── index.html            # Página de subida
│   ├── result.html           # Resultados del análisis
│   └── history.html          # Historial de análisis
├── tests/                  # Suite de pruebas unitarias e integración
│   ├── test_ai_classifier.py
│   ├── test_analisis_estatico.py
│   ├── test_main.py
│   ├── test_report_generator.py
│   ├── test_integration.py
│   └── README.md           # Documentación y guía de ejecución de pruebas
├── uploads/                # APKs subidos (persistencia opcional)
└── history.json            # Historial (se puede montar como volumen)
```

## Testing

La aplicación incluye una suite completa de pruebas unitarias.

### Ejecutar pruebas

**Opción 1: Menú interactivo**
```bash
python scripts/run_tests.py
```

**Opción 2: Línea de comandos**
```bash
# Todas las pruebas (verbose)
python -m unittest discover tests -v

# Todas las pruebas (silencioso)
python -m unittest discover tests

# Módulo específico
python -m unittest tests.test_ai_classifier -v
python -m unittest tests.test_integration -v

# Test específico
python -m unittest tests.test_ai_classifier.TestAIClassifier.test_empty_vulnerabilities_returns_bajo
```

### Cobertura de pruebas

- **66 tests** en total (51 unitarias + 15 integración)
- Cobertura de módulos: ai_classifier, report_generator, analisis_estatico, main, flujos de integración
- Tests unitarios, integración, y casos límite

Ver [tests/README.md](tests/README.md) para documentación detallada y opciones de ejecución de pruebas.

## Tecnologías

- Flask (backend)
- Androguard (análisis de APK)
- HTML/CSS (frontend)
- unittest (testing)
