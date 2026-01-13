"""
Guía de Ejecución de Pruebas para AndroidSecAnalyzer
=====================================================

Este script proporciona funciones auxiliares para ejecutar pruebas en varias configuraciones.
"""

import subprocess
import sys
import os


def run_all_tests_verbose():
    """Ejecutar todas las pruebas con salida detallada"""
    print("=" * 70)
    print("Ejecutando TODAS LAS PRUEBAS (detallado)")
    print("=" * 70)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "tests", "-v"],
        cwd=project_root
    )
    return result.returncode == 0


def run_all_tests_quiet():
    """Ejecutar todas las pruebas con salida mínima"""
    print("=" * 70)
    print("Ejecutando TODAS LAS PRUEBAS (modo silencioso)")
    print("=" * 70)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "tests"],
        cwd=project_root
    )
    return result.returncode == 0

def run_single_module(module_name):
    """Ejecutar pruebas para un módulo específico"""
    print("=" * 70)
    print(f"Ejecutando pruebas para el módulo: {module_name}")
    print("=" * 70)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run(
        [sys.executable, "-m", "unittest", f"tests.{module_name}", "-v"],
        cwd=project_root
    )
    return result.returncode == 0
    return result.returncode == 0

def run_single_test(test_path):
    """Ejecutar una prueba específica"""
    print("=" * 70)
    print(f"Ejecutando prueba específica: {test_path}")
    print("=" * 70)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run(
        [sys.executable, "-m", "unittest", test_path, "-v"],
        cwd=project_root
    )
    return result.returncode == 0
    return result.returncode == 0


def run_with_coverage():
    """Ejecutar pruebas con informe de cobertura"""
    print("=" * 70)
    print("Ejecutando pruebas con informe de COBERTURA")
    print("=" * 70)
    
    try:
        # Intentar importar coverage
        import coverage
    except ImportError:
        print("\nADVERTENCIA: módulo coverage no instalado")
        print("Instálalo con: pip install coverage")
        return False
    
    # Ejecutar cobertura
    cov = coverage.Coverage()
    cov.start()
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "tests", "-v"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    
    cov.stop()
    cov.save()
    
    print("\nInforme de Cobertura:")
    cov.report()
    
    return result.returncode == 0

def show_test_modules():
    """Mostrar módulos de prueba disponibles"""
    test_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests")
    test_files = [f for f in os.listdir(test_dir) if f.startswith("test_") and f.endswith(".py")]
    test_files = [f for f in os.listdir(test_dir) if f.startswith("test_") and f.endswith(".py")]
    
    print("\n" + "=" * 70)
    print("Módulos de Prueba Disponibles")
    print("=" * 70)
    for i, test_file in enumerate(sorted(test_files), 1):
        module_name = test_file[:-3]  # Eliminar la extensión .py
        print(f"{i}. {module_name}")
    
    return test_files


def main():
    """Menú principal para ejecutar pruebas"""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print("CWD:", project_root)
    print("\n" + "=" * 70)
    print("AndroidSecAnalyzer - Ejecutador de Pruebas")
    print("=" * 70)
    print("\nOpciones:")
    print("  1. Ejecutar todas las pruebas (detallado)")
    print("  2. Ejecutar todas las pruebas (silencioso)")
    print("  3. Ejecutar módulo de prueba específico")
    print("  4. Ejecutar prueba específica")
    print("  5. Mostrar módulos de prueba disponibles")
    print("  0. Salir")
    print()
    
    choice = input("Selecciona una opción (0-5): ").strip()
    
    if choice == "1":
        success = run_all_tests_verbose()
    elif choice == "2":
        success = run_all_tests_quiet()
    elif choice == "3":
        modules = show_test_modules()
        module_choice = input("\nIngresa el nombre del módulo (sin el prefijo 'test_' y '.py'): ").strip()
        if f"test_{module_choice}.py" in modules:
            success = run_single_module(f"test_{module_choice}")
        else:
            print(f"¡Módulo 'test_{module_choice}' no encontrado!")
            success = False
    elif choice == "4":
        test_path = input("Ingresa la ruta de la prueba (ej., tests.test_ai_classifier.TestAIClassifier.test_empty_vulnerabilities_returns_bajo): ").strip()
        success = run_single_test(test_path)
    elif choice == "5":
        show_test_modules()
        success = True
    elif choice == "0":
        print("Saliendo...")
        return
    else:
        print("¡Opción inválida!")
        return
    
    print("\n" + "=" * 70)
    if success:
        print("RESULTADO: ✓ ¡Todas las pruebas pasaron!")
    else:
        print("RESULTADO: ✗ ¡Algunas pruebas fallaron!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
