#!/bin/bash
# Navegar al directorio raiz del proyecto:
cd ../
#Construir la imagen:
docker build -t androidsecanalyzer .
#Ejecutar el contenedor (puerto 8000 expuesto por Flask dentro del contenedor):
docker run --rm -p 8000:8000 androidsecanalyzer
# Con la opcion de montar volumenes para persistencia de datos:
# docker run --rm -p 8000:8000 \
# 	-v ${PWD}/uploads:/app/uploads \
# 	-v ${PWD}/history.json:/app/history.json \
# 	androidsecanalyzer
# Ahora la aplicacion sera accesible en http://localhost:8000
echo "Aplicación Docker de AndroidSecAnalyzer en ejecución en http://localhost:8000"