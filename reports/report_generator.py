def generate_report(filename, vulnerabilities, risk):
    report = []
    report.append("INFORME DE SEGURIDAD - DROIDSECANALYZER")
    report.append("=" * 60)
    report.append(f"Aplicacion analizada: {filename}")
    report.append(f"Nivel de riesgo global: {risk}")
    report.append(f"Vulnerabilidades encontradas: {len(vulnerabilities)}")
    report.append("")

    # Contar por severidad
    high = sum(1 for v in vulnerabilities if v.get("severity") == "HIGH")
    medium = sum(1 for v in vulnerabilities if v.get("severity") == "MEDIUM")
    low = sum(1 for v in vulnerabilities if v.get("severity") == "LOW")

    report.append(f"Resumen: {high} ALTA | {medium} MEDIA | {low} BAJA")
    report.append("=" * 60)
    report.append("")

    for idx, v in enumerate(vulnerabilities, start=1):
        severity = v.get("severity", "MEDIUM")
        report.append(f"{idx}. [{severity}] {v['title']}")
        report.append("-" * 60)
        report.append("Descripcion:")
        report.append(f"  {v['description']}")
        report.append("")
        report.append("Ubicacion:")
        report.append(f"  Fichero: {v['file']}")
        report.append(f"  Metodo:  {v['method']}")
        report.append("")
        report.append("Evidencia:")
        report.append(f"  {v['evidence']}")
        report.append("")
        report.append("Recomendacion:")
        report.append(f"  {v['solution']}")
        report.append("")

    report.append("=" * 60)
    report.append("Generado por DroidSecAnalyzer (DSA)")

    return "\n".join(report)
