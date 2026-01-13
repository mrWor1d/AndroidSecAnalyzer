"""
Aplicacion principal Flask - DroidSecAnalyzer
Analiza vulnerabilidades en aplicaciones Android (APK)
"""

import os
import json
from datetime import datetime
from flask import Flask, render_template, request, Response
from analisis.analisis_estatico import analyze_apk, get_apk_metadata
from analisis.ai_classifier import classify_risk
from reports.report_generator import generate_report

UPLOAD_FOLDER = "uploads"
HISTORY_FILE = "history.json"

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

last_report = {"content": "", "filename": ""}


def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def save_history(entry):
    history = load_history()
    history.insert(0, entry)  # Mas reciente primero
    history = history[:50]  # Maximo 50 entradas
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)


@app.route("/", methods=["GET", "POST"])
def index():
    global last_report

    if request.method == "POST":
        apk_file = request.files["apk"]

        if not apk_file or not apk_file.filename.endswith(".apk"):
            return "Archivo no valido. Debe ser un APK."

        apk_path = os.path.join(app.config["UPLOAD_FOLDER"], apk_file.filename)
        apk_file.save(apk_path)

        # Extraer metadata
        metadata = get_apk_metadata(apk_path)

        # Analisis estatico
        static_results = analyze_apk(apk_path)

        # Clasificacion de riesgo
        risk_level = classify_risk(static_results)

        # Generacion de informe
        report = generate_report(apk_file.filename, static_results, risk_level)

        # Guardar para descarga
        last_report = {
            "content": report,
            "filename": apk_file.filename.replace(".apk", "_report.txt")
        }

        # Contar por severidad
        high_count = sum(1 for v in static_results if v.get("severity") == "HIGH")
        medium_count = sum(1 for v in static_results if v.get("severity") == "MEDIUM")
        low_count = sum(1 for v in static_results if v.get("severity") == "LOW")

        # Guardar en historial
        save_history({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "filename": apk_file.filename,
            "app_name": metadata["app_name"],
            "package": metadata["package"],
            "version": metadata["version_name"],
            "risk": risk_level,
            "vulns_total": len(static_results),
            "vulns_high": high_count,
            "vulns_medium": medium_count,
            "vulns_low": low_count
        })

        return render_template(
            "result.html",
            results=static_results,
            risk=risk_level,
            report=report,
            metadata=metadata
        )

    return render_template("index.html")


@app.route("/history")
def history():
    return render_template("history.html", history=load_history())


@app.route("/download")
def download():
    if not last_report["content"]:
        return "No hay informe disponible", 404

    return Response(
        last_report["content"],
        mimetype="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename={last_report['filename']}"
        }
    )


if __name__ == "__main__":
    app.run(debug=True)
