#!/usr/bin/env python
"""
Hook de pre-commit para ejecutar pruebas antes de hacer commit
Coloca este archivo en .git/hooks/pre-commit y hazlo ejecutable
"""

import subprocess
import sys
import os


def run_tests():
    """Ejecutar todas las pruebas antes de permitir el commit"""
    print("\n" + "="*70)
    print("Hook de Pre-commit: Ejecutando Pruebas")
    print("="*70 + "\n")
    
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Ejecutar pruebas unitarias
    result = subprocess.run(
        [sys.executable, '-m', 'unittest', 'discover', 'tests'],
        cwd=project_root,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print("❌ Las pruebas FALLARON. Commit abortado.")
        print("\nSalida de pruebas:")
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return False
    
    print("✓ ¡Todas las pruebas pasaron!")
    return True


def check_syntax():
    """Verificar la sintaxis de Python en archivos modificados"""
    print("\nVerificando sintaxis de Python...")
    
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    result = subprocess.run(
        [sys.executable, '-m', 'py_compile', 'main.py',
         'run_tests.py', 'ci.py'],
        cwd=project_root,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print("❌ ¡Se encontraron errores de sintaxis!")
        print(result.stderr)
        return False
    
    print("✓ ¡Sin errores de sintaxis!")
    return True


def main():
    """Lógica principal del hook de pre-commit"""
    if not check_syntax():
        return 1
    
    if not run_tests():
        return 1
    
    print("\n" + "="*70)
    print("✓ Todas las verificaciones pasaron. Procediendo con el commit.")
    print("="*70 + "\n")
    return 0


if __name__ == '__main__':
    sys.exit(main())
