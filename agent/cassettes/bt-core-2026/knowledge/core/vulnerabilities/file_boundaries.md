---
id: VULN_FILE_BOUNDARIES
type: vulnerabilities
title: Límites de lectura, inclusión y carga de archivos
tags: [file, upload, inclusion, path, execution]
priority: 8
layer: core
---
# Límites de lectura, inclusión y carga de archivos
Lectura, inclusión, almacenamiento y ejecución son propiedades distintas. El análisis debe separar qué capacidad fue observada y evitar elevar una evidencia de almacenamiento a ejecución o una lectura parcial a control completo.
