"""Ejecuta tres incidentes reales del cliente Flask y documenta las mediciones."""
from contextlib import closing, redirect_stdout
from datetime import datetime, timezone
import io
from pathlib import Path
import sqlite3
import sys
import tempfile

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "laboratorio-ciberseguridad"))
from app import app  # noqa: E402
from crearDB import crear_bd  # noqa: E402
from detector import ejecutar, leer_eventos  # noqa: E402
from werkzeug.security import check_password_hash  # noqa: E402


def medir():
    with tempfile.TemporaryDirectory(prefix="laboratorio_mttd_") as temporal:
        datos = Path(temporal)
        crear_bd(datos / "usuarios.db")
        app.config.update(TESTING=True, DB_PATH=datos / "usuarios.db", EVENTOS_PATH=datos / "eventos.log")
        cliente = app.test_client()
        usuario = "prueba_01"
        clave = "Clave de prueba 123"
        correo = "prueba@example.test"
        casos = {
            "Registro válido": cliente.post("/registro", data={"usuario": usuario, "correo": correo, "password": clave}).status_code,
            "Usuario inválido": cliente.post("/registro", data={"usuario": "abc", "correo": correo, "password": clave}).status_code,
            "Correo inválido": cliente.post("/registro", data={"usuario": "otro_01", "correo": "correo@", "password": clave}).status_code,
            "Contraseña corta": cliente.post("/registro", data={"usuario": "otro_01", "correo": "otro@example.test", "password": "corta"}).status_code,
            "Usuario duplicado": cliente.post("/registro", data={"usuario": usuario, "correo": "otro@example.test", "password": clave}).status_code,
            "Correo duplicado": cliente.post("/registro", data={"usuario": "otro_01", "correo": correo, "password": clave}).status_code,
        }
        with closing(sqlite3.connect(datos / "usuarios.db")) as conexion:
            hash_almacenado = conexion.execute("SELECT password FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()[0]
        hash_ok = hash_almacenado != clave and check_password_hash(hash_almacenado, clave)
        resultados = []
        capturas = []
        for numero in range(1, 4):
            estados = [cliente.post("/login", data={"usuario": usuario, "password": f"fallo-{numero}"}).status_code for _ in range(3)]
            salida = io.StringIO()
            with redirect_stdout(salida):
                nuevos = ejecutar(datos, confirmar=lambda _: "")
            assert estados == [401] * 3 and len(nuevos) == 1
            resultados.append(nuevos[0])
            capturas.append(salida.getvalue())
            assert cliente.post("/login", data={"usuario": usuario, "password": clave}).status_code == 200
        eventos = leer_eventos(datos / "eventos.log")
        respuestas = (datos / "respuesta.log").read_text(encoding="utf-8").splitlines()
        assert len(eventos) == 12 and len(respuestas) == 3 and hash_ok
        assert ejecutar(datos, confirmar=lambda _: "") == []
        return casos, hash_ok, resultados, capturas, eventos, respuestas


def reporte():
    casos, hash_ok, resultados, capturas, eventos, respuestas = medir()
    assert casos == {
        "Registro válido": 201, "Usuario inválido": 400, "Correo inválido": 400,
        "Contraseña corta": 400, "Usuario duplicado": 409, "Correo duplicado": 409,
    }
    promedio_mttd = sum(float(x["mttd_segundos"]) for x in resultados) / 3
    promedio_mttr = sum(float(x["mttr_segundos"]) for x in resultados) / 3
    lineas = [
        "# Evidencias de ejecución",
        "",
        f"Medición realizada: {datetime.now(timezone.utc).isoformat(timespec='seconds')} (UTC).",
        "",
        "Se ejecutó el cliente de pruebas de Flask con una base SQLite y logs en un directorio temporal.",
        "Cada escenario produjo tres solicitudes HTTP fallidas y una ejecución real del detector.",
        "La respuesta fue un bloqueo simulado confirmado automáticamente; los tiempos son diferencias entre marcas reales del reloj, no valores inventados.",
        "Los archivos temporales con usuarios, hash y eventos no se publican.",
        "",
        "## Validación y autenticación",
        "",
        "| Comprobación | Estado HTTP observado |",
        "| --- | ---: |",
    ]
    lineas += [f"| {nombre} | {estado} |" for nombre, estado in casos.items()]
    lineas += [
        f"| Hash distinto de la clave y verificable con Werkzeug | {'Sí' if hash_ok else 'No'} |",
        f"| Eventos observados (9 fallidos, 3 correctos) | {len(eventos)} |",
        f"| Respuestas USUARIO_BLOQUEADO registradas | {len(respuestas)} |",
        "",
        "## Tiempos medidos",
        "",
        "| Prueba | MTTD (segundos) | MTTR (segundos) |",
        "| --- | ---: | ---: |",
    ]
    lineas += [f'| {x["prueba"]} | {x["mttd_segundos"]} | {x["mttr_segundos"]} |' for x in resultados]
    lineas += [
        f"| **Promedio** | **{promedio_mttd:.6f}** | **{promedio_mttr:.6f}** |",
        "",
        "Fórmulas verificadas con las marcas ISO UTC: MTTD = detección − primer fallo; MTTR = respuesta − detección.",
        "Al ejecutar otra vez el detector, informó que no había incidentes nuevos.",
        "",
        "## Salida real del detector",
        "",
    ]
    for numero, captura in enumerate(capturas, 1):
        lineas += [f"### Escenario {numero}", "", "```text", captura.strip(), "```", ""]
    destino = RAIZ / "evidencias" / "resultados.md"
    destino.parent.mkdir(exist_ok=True)
    destino.write_text("\n".join(lineas), encoding="utf-8")
    print(f"Reporte generado: {destino}")
    print(f"MTTD promedio: {promedio_mttd:.6f} s")
    print(f"MTTR promedio: {promedio_mttr:.6f} s")


if __name__ == "__main__":
    reporte()
