"""
Analisis estatico real de APKs usando androguard
"""
import re
import os
from androguard.core.apk import APK

DANGEROUS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
]

SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']+)["\']', "API Key"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']+)["\']', "Password"),
    (r'(?i)(secret|token)\s*[=:]\s*["\']([^"\']+)["\']', "Secret/Token"),
    (r'(?i)(aws[_-]?access|aws[_-]?secret)', "AWS Credentials"),
]


def analyze_apk(apk_path):
    """Analiza un APK y devuelve vulnerabilidades encontradas"""
    vulnerabilities = []

    try:
        apk = APK(apk_path)
    except Exception as e:
        return [{
            "title": "Error al analizar APK",
            "description": f"No se pudo analizar el archivo: {str(e)}",
            "solution": "Verificar que el archivo APK es valido",
            "file": apk_path,
            "method": "N/A",
            "evidence": str(e),
            "severity": "INFO",
            "category": "config"
        }]

    # 1. Analizar permisos peligrosos
    permissions = apk.get_permissions()
    dangerous_found = [p for p in permissions if p in DANGEROUS_PERMISSIONS]

    if dangerous_found:
        vulnerabilities.append({
            "title": "Permisos peligrosos detectados",
            "description": (
                f"La aplicacion solicita {len(dangerous_found)} permisos considerados "
                "peligrosos que pueden comprometer la privacidad del usuario."
            ),
            "solution": (
                "Revisar si todos los permisos son necesarios. Aplicar el principio "
                "de minimo privilegio."
            ),
            "file": "AndroidManifest.xml",
            "method": "<uses-permission>",
            "evidence": ", ".join([p.split(".")[-1] for p in dangerous_found]),
            "severity": "HIGH" if len(dangerous_found) > 3 else "MEDIUM",
            "category": "permissions"
        })

    # 2. Verificar modo debug
    debuggable = apk.get_attribute_value("application", "debuggable")
    if debuggable == "true":
        vulnerabilities.append({
            "title": "Aplicacion en modo debug",
            "description": (
                "La aplicacion tiene el flag debuggable activado, permitiendo "
                "a atacantes depurar y extraer informacion sensible."
            ),
            "solution": "Establecer android:debuggable='false' en el manifest.",
            "file": "AndroidManifest.xml",
            "method": "<application>",
            "evidence": "android:debuggable='true'",
            "severity": "HIGH",
            "category": "config"
        })

    # 3. Verificar backup permitido
    allow_backup = apk.get_attribute_value("application", "allowBackup")
    if allow_backup is None or allow_backup == "true":
        vulnerabilities.append({
            "title": "Backup de datos permitido",
            "description": (
                "La aplicacion permite backup de datos, lo que puede exponer "
                "informacion sensible si el dispositivo es comprometido."
            ),
            "solution": "Establecer android:allowBackup='false' o implementar reglas de backup.",
            "file": "AndroidManifest.xml",
            "method": "<application>",
            "evidence": "android:allowBackup='true'",
            "severity": "MEDIUM",
            "category": "config"
        })

    # 4. Buscar URLs HTTP inseguras
    try:
        files = apk.get_files()
        http_urls = set()

        for f in files:
            if f.endswith(".dex"):
                try:
                    content = apk.get_file(f)
                    urls = re.findall(rb'http://[^\s\x00"\'<>]+', content)
                    for url in urls:
                        decoded = url.decode('utf-8', errors='ignore')
                        if not decoded.startswith("http://schemas.android.com"):
                            http_urls.add(decoded[:60])
                except:
                    pass

        if http_urls:
            vulnerabilities.append({
                "title": "Comunicacion HTTP sin cifrar",
                "description": (
                    f"Se detectaron {len(http_urls)} URLs usando HTTP sin cifrado, "
                    "exponiendo datos a ataques Man-in-the-Middle."
                ),
                "solution": "Usar HTTPS para todas las comunicaciones.",
                "file": "classes.dex",
                "method": "Network calls",
                "evidence": ", ".join(list(http_urls)[:3]),
                "severity": "HIGH",
                "category": "network"
            })
    except:
        pass

    # 5. Verificar componentes exportados
    exported_activities = []
    exported_services = []
    exported_receivers = []

    for activity in apk.get_activities():
        if is_exported(apk, activity, "activity"):
            exported_activities.append(activity.split(".")[-1])

    for service in apk.get_services():
        if is_exported(apk, service, "service"):
            exported_services.append(service.split(".")[-1])

    for receiver in apk.get_receivers():
        if is_exported(apk, receiver, "receiver"):
            exported_receivers.append(receiver.split(".")[-1])

    total_exported = len(exported_activities) + len(exported_services) + len(exported_receivers)

    if total_exported > 0:
        evidence_parts = []
        if exported_activities:
            evidence_parts.append(f"Activities: {', '.join(exported_activities[:2])}")
        if exported_services:
            evidence_parts.append(f"Services: {', '.join(exported_services[:2])}")
        if exported_receivers:
            evidence_parts.append(f"Receivers: {', '.join(exported_receivers[:2])}")

        vulnerabilities.append({
            "title": "Componentes exportados sin proteccion",
            "description": (
                f"Se encontraron {total_exported} componentes exportados que podrian "
                "ser accedidos por otras aplicaciones maliciosas."
            ),
            "solution": (
                "Agregar permisos personalizados o establecer exported='false' "
                "si no es necesario."
            ),
            "file": "AndroidManifest.xml",
            "method": "Components",
            "evidence": "; ".join(evidence_parts),
            "severity": "MEDIUM" if total_exported < 5 else "HIGH",
            "category": "components"
        })

    # 6. Buscar posibles secretos hardcodeados
    try:
        for f in apk.get_files():
            if f.endswith((".xml", ".json", ".properties")):
                try:
                    content = apk.get_file(f).decode('utf-8', errors='ignore')
                    for pattern, secret_type in SECRET_PATTERNS:
                        if re.search(pattern, content):
                            vulnerabilities.append({
                                "title": f"Posible {secret_type} hardcodeado",
                                "description": (
                                    f"Se detecto un posible {secret_type} en el codigo fuente. "
                                    "Esto puede exponer credenciales sensibles."
                                ),
                                "solution": "Usar variables de entorno o almacenamiento seguro.",
                                "file": f,
                                "method": "Hardcoded value",
                                "evidence": f"Patron detectado: {secret_type}",
                                "severity": "HIGH",
                                "category": "secrets"
                            })
                            break
                except:
                    pass
    except:
        pass

    # 7. Verificar version minima de SDK
    min_sdk = apk.get_min_sdk_version()
    if min_sdk and int(min_sdk) < 21:
        vulnerabilities.append({
            "title": "SDK minimo obsoleto",
            "description": (
                f"La aplicacion soporta Android SDK {min_sdk}, que tiene vulnerabilidades "
                "de seguridad conocidas."
            ),
            "solution": "Aumentar minSdkVersion a 21 o superior.",
            "file": "AndroidManifest.xml",
            "method": "<uses-sdk>",
            "evidence": f"minSdkVersion={min_sdk}",
            "severity": "LOW",
            "category": "config"
        })

    # Si no se encontraron vulnerabilidades
    if not vulnerabilities:
        vulnerabilities.append({
            "title": "Analisis completado",
            "description": "No se detectaron vulnerabilidades obvias en el analisis estatico.",
            "solution": "Considerar analisis dinamico para una evaluacion mas completa.",
            "file": "N/A",
            "method": "N/A",
            "evidence": "Ninguna vulnerabilidad detectada",
            "severity": "INFO",
            "category": "config"
        })

    return vulnerabilities


def is_exported(apk, component, comp_type):
    """Verifica si un componente esta exportado"""
    try:
        exported = apk.get_attribute_value(comp_type, "exported", name=component)
        if exported == "true":
            return True
        if exported == "false":
            return False
        return False
    except:
        return False


def get_apk_metadata(apk_path):
    """Extrae metadata del APK"""
    try:
        apk = APK(apk_path)

        permissions = apk.get_permissions()
        dangerous = [p for p in permissions if p in DANGEROUS_PERMISSIONS]

        # Tamaño del archivo
        file_size = os.path.getsize(apk_path)
        if file_size > 1024 * 1024:
            size_str = f"{file_size / (1024 * 1024):.1f} MB"
        else:
            size_str = f"{file_size / 1024:.1f} KB"

        return {
            "app_name": apk.get_app_name() or "Desconocido",
            "package": apk.get_package() or "Desconocido",
            "version_name": apk.get_androidversion_name() or "N/A",
            "version_code": apk.get_androidversion_code() or "N/A",
            "min_sdk": apk.get_min_sdk_version() or "N/A",
            "target_sdk": apk.get_target_sdk_version() or "N/A",
            "permissions_total": len(permissions),
            "permissions_dangerous": len(dangerous),
            "activities": len(apk.get_activities()),
            "services": len(apk.get_services()),
            "receivers": len(apk.get_receivers()),
            "file_size": size_str
        }
    except Exception as e:
        return {
            "app_name": "Error",
            "package": str(e),
            "version_name": "N/A",
            "version_code": "N/A",
            "min_sdk": "N/A",
            "target_sdk": "N/A",
            "permissions_total": 0,
            "permissions_dangerous": 0,
            "activities": 0,
            "services": 0,
            "receivers": 0,
            "file_size": "N/A"
        }
