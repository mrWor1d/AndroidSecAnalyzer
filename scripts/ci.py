"""
Script de Integración Continua Local
Ejecuta todas las pruebas y verificaciones de calidad localmente antes de hacer push
"""

import subprocess
import sys
import time
import os
from datetime import datetime

# Configurar codificación UTF-8 para terminal de Windows
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


class Colors:
    """Códigos de color ANSI para salida en terminal"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_header(text):
    """Imprime un encabezado formateado"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(70)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}\n")


def print_section(text):
    """Imprime un encabezado de sección formateado"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{text}{Colors.END}")
    print(f"{Colors.CYAN}{'-'*70}{Colors.END}")


def print_success(text):
    """Imprime mensaje de éxito"""
    symbol = "✓" if sys.platform != 'win32' else "[OK]"
    print(f"{Colors.GREEN}{symbol} {text}{Colors.END}")


def print_error(text):
    """Imprime mensaje de error"""
    symbol = "✗" if sys.platform != 'win32' else "[FAIL]"
    print(f"{Colors.RED}{symbol} {text}{Colors.END}")


def print_warning(text):
    """Imprime mensaje de advertencia"""
    symbol = "⚠" if sys.platform != 'win32' else "[!]"
    print(f"{Colors.YELLOW}{symbol} {text}{Colors.END}")


def run_command(command, description):
    """Ejecuta un comando y retorna el estado de éxito"""
    print_section(description)
    print(f"Ejecutando: {' '.join(command)}\n")
    
    start_time = time.time()
    try:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        result = subprocess.run(
            command,
            cwd=project_root,
            capture_output=True,
            text=True
        )
        elapsed = time.time() - start_time
        
        if result.returncode == 0:
            print_success(f"{description} (completado en {elapsed:.2f}s)")
            if result.stdout:
                print(result.stdout)
            return True
        else:
            print_error(f"{description} (falló en {elapsed:.2f}s)")
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(f"{Colors.RED}{result.stderr}{Colors.END}")
            return False
    except Exception as e:
        print_error(f"Error ejecutando comando: {str(e)}")
        return False


def main():
    """Ejecutor principal de CI"""
    print_header("AndroidSecAnalyzer - Pipeline de CI Local")
    print(f"Iniciado en: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    results = {}
    
    # Etapa 1: Pruebas Unitarias
    results['unit_tests'] = run_command(
        [sys.executable, '-m', 'unittest', 'discover', 'tests', '-v'],
        'Etapa 1: Ejecutando Pruebas Unitarias'
    )
    
    # Etapa 2: Pruebas de Integración
    results['integration_tests'] = run_command(
        [sys.executable, '-m', 'unittest', 'tests.test_integration', '-v'],
        'Etapa 2: Ejecutando Pruebas de Integración'
    )
    
    # Etapa 3: Validación de Sintaxis
    print_section('Etapa 3: Validando Sintaxis de Python')
    files_to_check = [
        'main.py',
        'scripts/run_tests.py',
        'analisis/ai_classifier.py',
        'analisis/analisis_estatico.py',
        'reports/report_generator.py'
    ]
    
    syntax_ok = True
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for file in files_to_check:
        try:
            file_path = os.path.join(project_root, file)
            with open(file_path, 'r', encoding='utf-8') as f:
                compile(f.read(), file, 'exec')
            print_success(f"Sintaxis OK: {file}")
        except SyntaxError as e:
            print_error(f"Error de Sintaxis en {file}: {str(e)}")
            syntax_ok = False
    
    results['syntax'] = syntax_ok
    
    # Etapa 4: Verificar importaciones
    print_section('Etapa 4: Comprobando Importaciones de Módulos')
    try:
        # Agregar directorio raíz al sys.path para imports
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        
        import main
        print_success("módulo main importado correctamente")
        import analisis.ai_classifier
        print_success("analisis.ai_classifier importado correctamente")
        import analisis.analisis_estatico
        print_success("analisis.analisis_estatico importado correctamente")
        import reports.report_generator
        print_success("reports.report_generator importado correctamente")
        results['imports'] = True
    except ImportError as e:
        print_error(f"Error de Importación: {str(e)}")
        results['imports'] = False
    
    # Etapa 5: Resumen
    print_header("Resumen del Pipeline de CI")
    
    all_passed = all(results.values())
    
    for stage, passed in results.items():
        status = f"{Colors.GREEN}APROBADO{Colors.END}" if passed else f"{Colors.RED}FALLIDO{Colors.END}"
        print(f"  {stage.replace('_', ' ').title()}: {status}")
    
    print()
    if all_passed:
        print_success("¡Todas las etapas aprobaron! El código está listo para hacer commit.")
        print(f"\nCompletado en: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return 0
    else:
        print_error("Algunas etapas fallaron. Por favor revisa la salida anterior.")
        print(f"\nCompletado en: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return 1


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
