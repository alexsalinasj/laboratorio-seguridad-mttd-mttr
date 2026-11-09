# Laboratorio de ciberseguridad: MTTD y MTTR

Práctica académica de la Unidad 3, **Código Seguro y Modelo OWASP**, cotejada con la guía `Práctica de Seguridad MTTD y MTTR.pdf`. Una aplicación Flask registra usuarios ficticios, valida entradas, protege contraseñas y registra eventos de autenticación. Un detector analiza tres fallos consecutivos por usuario, muestra una alerta y registra una respuesta de bloqueo **simulado**.

> El archivo original `REAME.md` o `README.md` del Aula Virtual mencionado en el material existente no está disponible en esta carpeta. Falta incorporarlo si la docente lo exige. No se incluyen datos académicos ni de matrícula inventados.

## Objetivos

1. Practicar validación del lado del servidor, consultas parametrizadas y hash de contraseñas.
2. Registrar intentos de autenticación sin guardar contraseñas en los logs.
3. Detectar incidentes y medir MTTD y MTTR con marcas de tiempo reales.
4. Conservar evidencia reproducible sin publicar bases de datos ni logs locales.

## Tecnologías y estructura

Python 3, Flask 3, Werkzeug, SQLite, HTML y CSS propio. Las pruebas usan `unittest` de la biblioteca estándar.

```text
practica-mttd-mttr/
├── README.md
├── .gitignore
├── requirements.txt
├── laboratorio-ciberseguridad/
│   ├── app.py
│   ├── crearDB.py
│   ├── detector.py
│   ├── requirements.txt
│   ├── static/estilos.css
│   └── templates/{base,inicio,registro,login}.html
├── tests/
│   ├── test_laboratorio.py
│   └── medir_escenarios.py
└── evidencias/resultados.md
```

`usuarios.db`, `eventos.log`, `respuesta.log`, `detecciones.json` y `resultados.csv` se generan localmente dentro de `laboratorio-ciberseguridad/`. Están excluidos por `.gitignore`.

## Requisitos previos e instalación en Windows

Instala Python 3 y Git. Desde PowerShell en la raíz de este repositorio:

```powershell
cd laboratorio-ciberseguridad
py -3 -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe crearDB.py
.\venv\Scripts\python.exe app.py
```

Si no tienes `py`, sustituye la primera orden por `python -m venv venv`. El entorno virtual queda dentro de la carpeta del laboratorio. Flask escucha solo en `127.0.0.1:5000` y no arranca en modo de depuración.

Visita `http://127.0.0.1:5000/`, `/registro` y `/login`. Registra un usuario ficticio con nombre de 4 a 20 caracteres ASCII (letras, números o guion bajo), correo válido y contraseña de al menos 8 caracteres. El formulario muestra mensajes de validación; también se validan todos los datos en el servidor. Los espacios al inicio y final de usuario y correo se eliminan. La contraseña se conserva íntegra, incluidos sus espacios internos.

Para cerrar la aplicación, pulsa `Ctrl+C`.

## Detector y mediciones

Después de tres intentos fallidos para el mismo usuario, ejecuta en otra terminal:

```powershell
cd laboratorio-ciberseguridad
.\venv\Scripts\python.exe detector.py
```

El detector muestra el primer intento, la detección, el MTTD y la cantidad de fallos. Pulsa Enter para registrar el bloqueo simulado; después muestra la hora de respuesta y el MTTR. La base de datos no bloquea la cuenta. Los resultados se guardan en `resultados.csv` y los incidentes procesados en `detecciones.json`, de modo que una segunda ejecución no los contabiliza de nuevo. Un login correcto reinicia la secuencia de fallos de ese usuario. Para una nueva práctica aislada, usa un directorio de datos nuevo o elimina los archivos de eventos y estado locales una vez que ya no los necesites.

Las marcas se guardan como ISO 8601 en UTC con microsegundos:

```text
MTTD = momento de detección − momento del primer intento fallido
MTTR = momento de respuesta − momento de detección
promedio = suma de los tres tiempos / 3
```

El MTTR representa el tiempo hasta registrar la **respuesta simulada**, no la recuperación de una cuenta real. En la prueba automatizada, la confirmación ocurre de inmediato; por eso los MTTR son muy pequeños. En una práctica manual, el tiempo incluye la espera hasta pulsar Enter.

## Pruebas y evidencia

Desde la raíz del repositorio:

```powershell
.\laboratorio-ciberseguridad\venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
.\laboratorio-ciberseguridad\venv\Scripts\python.exe tests\medir_escenarios.py
```

Las pruebas cubren el registro de dos usuarios ficticios, usuario/correo/contraseña inválidos, duplicados, normalización, hash verificable, login correcto e incorrecto, intento de inyección SQL, eventos, tres incidentes independientes, respuesta y fórmulas. `medir_escenarios.py` usa una base y logs temporales, ejecuta tres grupos de tres solicitudes HTTP fallidas y escribe la salida real en [evidencias/resultados.md](evidencias/resultados.md). Cada grupo se separa mediante un login correcto y se comprueba que el detector no vuelve a procesar el incidente.

Mediciones observadas en esta ejecución (UTC 2026-11-09; hora local de El Salvador: 2026-11-08):

| Prueba | MTTD (segundos) | MTTR (segundos) |
| --- | ---: | ---: |
| 1 | 0.302679 | 0.000029 |
| 2 | 0.336643 | 0.000025 |
| 3 | 0.315760 | 0.000023 |
| **Promedio** | **0.318361** | **0.000026** |

Los promedios son `(0.302679 + 0.336643 + 0.315760) / 3` y `(0.000029 + 0.000025 + 0.000023) / 3`, redondeados a seis decimales. Una nueva ejecución producirá tiempos distintos. No se publican capturas de pantalla porque no se generaron durante esta ejecución; el reporte conserva estados HTTP y salidas verificables del detector.

## Controles de seguridad

- Validación y normalización del lado del servidor.
- Restricciones `UNIQUE` en usuario y correo; rechazo de duplicados.
- Consultas SQLite con parámetros `?` para evitar inyección SQL.
- Hash de contraseñas con Werkzeug y comparación con `check_password_hash`.
- Errores de servicio genéricos para el navegador; no se exponen rutas internas ni credenciales.
- Logs de autenticación sin contraseñas, con usuario saneado y horas UTC.
- Base de datos, logs, estado y entorno virtual excluidos de Git.

## Conclusión

El laboratorio demuestra el ciclo de prevención, detección y respuesta mediante una aplicación local pequeña y pruebas reproducibles. Los tiempos dependen de cuándo se producen los fallos, cuándo se ejecuta el detector y cuándo se confirma la respuesta; las cifras de esta entrega describen solo la ejecución registrada en `evidencias/resultados.md`.
