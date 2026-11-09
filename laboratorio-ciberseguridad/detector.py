"""Detección de tres fallos consecutivos y respuesta simulada.

Los tiempos se miden con marcas UTC de microsegundos. El bloqueo es solo un
evento de laboratorio: no modifica la cuenta en SQLite.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
EVENTOS_PATH = BASE_DIR / "eventos.log"
RESPUESTA_PATH = BASE_DIR / "respuesta.log"
ESTADO_PATH = BASE_DIR / "detecciones.json"
RESULTADOS_PATH = BASE_DIR / "resultados.csv"
CAMPOS = ("id", "prueba", "usuario", "intentos", "primer_intento", "deteccion",
          "respuesta", "mttd_segundos", "mttr_segundos")


def instante(texto):
    """Acepta eventos actuales ISO UTC y registros antiguos sin zona horaria."""
    try:
        fecha = datetime.fromisoformat(texto)
    except ValueError:
        return None
    return fecha.replace(tzinfo=timezone.utc) if fecha.tzinfo is None else fecha


def leer_eventos(ruta=EVENTOS_PATH):
    if not ruta.exists():
        return []
    eventos = []
    with ruta.open(encoding="utf-8") as archivo:
        for numero, linea in enumerate(archivo, 1):
            partes = linea.rstrip("\n").split(",", 2)
            if len(partes) != 3:
                continue
            fecha, tipo, usuario = partes
            momento = instante(fecha)
            if momento and tipo in {"LOGIN_CORRECTO", "LOGIN_FALLIDO"} and usuario:
                eventos.append({"linea": numero, "fecha": momento, "tipo": tipo, "usuario": usuario})
    return eventos


def identificar_incidentes(eventos):
    """Tres fallos seguidos del mismo usuario constituyen un incidente."""
    secuencias = {}
    incidentes = []
    for evento in eventos:
        usuario = evento["usuario"]
        if evento["tipo"] == "LOGIN_CORRECTO":
            secuencias.pop(usuario, None)
            continue
        grupo = secuencias.setdefault(usuario, [])
        grupo.append(evento)
        if len(grupo) == 3:
            identidad = "|".join(
                f'{x["linea"]}:{x["fecha"].isoformat()}:{x["usuario"]}' for x in grupo
            )
            incidentes.append({
                "id": hashlib.sha256(identidad.encode("utf-8")).hexdigest(),
                "usuario": usuario,
                "inicio": grupo[0]["fecha"],
                "cantidad": len(grupo),
            })
            secuencias[usuario] = []
    return incidentes


def leer_resultados(ruta=RESULTADOS_PATH):
    if not ruta.exists():
        return []
    with ruta.open(encoding="utf-8", newline="") as archivo:
        return list(csv.DictReader(archivo))


def leer_procesados(ruta=ESTADO_PATH):
    if not ruta.exists():
        return set()
    with ruta.open(encoding="utf-8") as archivo:
        estado = json.load(archivo)
    return set(estado.get("ids_procesados", []))


def guardar_procesados(ids, ruta=ESTADO_PATH):
    temporal = ruta.with_suffix(".tmp")
    with temporal.open("w", encoding="utf-8") as archivo:
        json.dump({"ids_procesados": sorted(ids)}, archivo, ensure_ascii=False, indent=2)
    temporal.replace(ruta)


def registrar_respuesta(usuario, momento, ruta=RESPUESTA_PATH):
    with ruta.open("a", encoding="utf-8") as archivo:
        archivo.write(f"{momento.isoformat(timespec='microseconds')},USUARIO_BLOQUEADO,{usuario}\n")


def guardar_resultado(fila, ruta=RESULTADOS_PATH):
    nuevo = not ruta.exists() or ruta.stat().st_size == 0
    with ruta.open("a", encoding="utf-8", newline="") as archivo:
        escritor = csv.DictWriter(archivo, fieldnames=CAMPOS)
        if nuevo:
            escritor.writeheader()
        escritor.writerow(fila)


def mostrar_resumen(resultados):
    if not resultados:
        return
    print("\nRESUMEN DE PRUEBAS")
    print(f'{"Prueba":<9} {"MTTD (s)":>12} {"MTTR (s)":>12}')
    for fila in resultados:
        print(f'{fila["prueba"]:<9} {fila["mttd_segundos"]:>12} {fila["mttr_segundos"]:>12}')
    promedio_mttd = sum(float(fila["mttd_segundos"]) for fila in resultados) / len(resultados)
    promedio_mttr = sum(float(fila["mttr_segundos"]) for fila in resultados) / len(resultados)
    print(f"MTTD promedio: {promedio_mttd:.6f} segundos")
    print(f"MTTR promedio: {promedio_mttr:.6f} segundos")


def ejecutar(directorio=BASE_DIR, confirmar=input):
    """Procesa incidentes nuevos. confirmar permite automatizar la prueba."""
    directorio = Path(directorio)
    eventos = leer_eventos(directorio / "eventos.log")
    if not eventos:
        print("No hay eventos. Realiza intentos de inicio de sesión en /login.")
        return []
    ruta_estado = directorio / "detecciones.json"
    ruta_resultados = directorio / "resultados.csv"
    resultados = leer_resultados(ruta_resultados)
    procesados = leer_procesados(ruta_estado) | {fila["id"] for fila in resultados if fila.get("id")}
    pendientes = [i for i in identificar_incidentes(eventos) if i["id"] not in procesados]
    nuevas = []
    if not pendientes:
        print("No hay incidentes nuevos con tres intentos fallidos.")
    for incidente in pendientes:
        deteccion = datetime.now(timezone.utc)
        inicio = incidente["inicio"]
        mttd = (deteccion - inicio).total_seconds()
        usuario = incidente["usuario"]
        print("\n=== ALERTA DE SEGURIDAD ===")
        print(f"Usuario afectado: {usuario}")
        print(f'Intentos fallidos: {incidente["cantidad"]}')
        print(f"Primer intento fallido: {inicio.isoformat(timespec='microseconds')}")
        print(f"Momento de detección: {deteccion.isoformat(timespec='microseconds')}")
        print(f"MTTD: {mttd:.6f} segundos")
        confirmar("Pulsa Enter para registrar el bloqueo simulado: ")
        respuesta = datetime.now(timezone.utc)
        mttr = (respuesta - deteccion).total_seconds()
        fila = {
            "id": incidente["id"],
            "prueba": str(len(resultados) + len(nuevas) + 1),
            "usuario": usuario,
            "intentos": str(incidente["cantidad"]),
            "primer_intento": inicio.isoformat(timespec="microseconds"),
            "deteccion": deteccion.isoformat(timespec="microseconds"),
            "respuesta": respuesta.isoformat(timespec="microseconds"),
            "mttd_segundos": f"{mttd:.6f}",
            "mttr_segundos": f"{mttr:.6f}",
        }
        registrar_respuesta(usuario, respuesta, directorio / "respuesta.log")
        guardar_resultado(fila, ruta_resultados)
        procesados.add(incidente["id"])
        guardar_procesados(procesados, ruta_estado)
        nuevas.append(fila)
        print("Acción de respuesta: USUARIO_BLOQUEADO (simulado)")
        print(f"Momento de respuesta: {respuesta.isoformat(timespec='microseconds')}")
        print(f"MTTR: {mttr:.6f} segundos")
    mostrar_resumen(resultados + nuevas)
    return nuevas


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detector de incidentes del laboratorio")
    parser.add_argument("--datos", type=Path, default=BASE_DIR, help="Directorio de logs de prueba")
    argumentos = parser.parse_args()
    try:
        ejecutar(argumentos.datos)
    except KeyboardInterrupt:
        print("\nRespuesta interrumpida; ejecuta de nuevo el detector.")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(1, f"Error al procesar los registros: {error}\n")
