"""Pruebas funcionales del registro, login y detector con datos temporales."""
import csv
from contextlib import closing
from datetime import datetime
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

PROYECTO = Path(__file__).resolve().parents[1] / "laboratorio-ciberseguridad"
sys.path.insert(0, str(PROYECTO))
from app import app  # noqa: E402
from crearDB import crear_bd  # noqa: E402
from detector import ejecutar, leer_eventos  # noqa: E402
from werkzeug.security import check_password_hash  # noqa: E402


class LaboratorioTest(unittest.TestCase):
    def setUp(self):
        self.temporal = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporal.cleanup)
        self.datos = Path(self.temporal.name)
        self.bd = self.datos / "usuarios.db"
        crear_bd(self.bd)
        app.config.update(TESTING=True, DB_PATH=self.bd, EVENTOS_PATH=self.datos / "eventos.log")
        self.cliente = app.test_client()

    def registrar(self, usuario="usuario_01", correo="u01@example.test", password="Clave con espacio 123"):
        return self.cliente.post("/registro", data={"usuario": usuario, "correo": correo, "password": password})

    def login(self, usuario="usuario_01", password="Clave con espacio 123"):
        return self.cliente.post("/login", data={"usuario": usuario, "password": password})

    def test_rutas_y_registro_hash(self):
        for ruta in ("/", "/registro", "/login"):
            self.assertEqual(self.cliente.get(ruta).status_code, 200)
        self.assertEqual(self.registrar().status_code, 201)
        with closing(sqlite3.connect(self.bd)) as conexion:
            fila = conexion.execute("SELECT id, usuario, correo, password FROM usuarios").fetchone()
        self.assertIsInstance(fila[0], int)
        self.assertEqual(fila[1:3], ("usuario_01", "u01@example.test"))
        self.assertNotEqual(fila[3], "Clave con espacio 123")
        self.assertTrue(check_password_hash(fila[3], "Clave con espacio 123"))

    def test_validaciones_duplicados_y_normalizacion(self):
        for usuario in ("abc", "nombre con espacio", "usuario#01", "x" * 21):
            self.assertEqual(self.registrar(usuario=usuario).status_code, 400)
        self.assertEqual(self.registrar(correo="usuario@").status_code, 400)
        self.assertEqual(self.registrar(password="abc123").status_code, 400)
        self.assertEqual(self.registrar(usuario="  usuario_01  ", correo="  u01@example.test  ").status_code, 201)
        self.assertEqual(self.registrar().status_code, 409)
        self.assertEqual(self.registrar(usuario="otro_01").status_code, 409)
        self.assertEqual(self.login(password="Claveconespacio123").status_code, 401)
        self.assertEqual(self.login(usuario="  usuario_01  ").status_code, 200)

    def test_login_eventos_e_inyeccion(self):
        self.assertEqual(self.registrar().status_code, 201)
        self.assertEqual(self.login().status_code, 200)
        self.assertEqual(self.login(password="incorrecta").status_code, 401)
        self.assertEqual(self.login(usuario="' OR 1=1 --", password="incorrecta").status_code, 401)
        eventos = leer_eventos(self.datos / "eventos.log")
        self.assertEqual([x["tipo"] for x in eventos], ["LOGIN_CORRECTO", "LOGIN_FALLIDO", "LOGIN_FALLIDO"])
        self.assertTrue(all(x["fecha"].tzinfo is not None for x in eventos))
        self.assertNotIn("incorrecta", (self.datos / "eventos.log").read_text(encoding="utf-8"))

    def test_tres_incidentes_independientes_y_metricas(self):
        self.assertEqual(self.registrar().status_code, 201)
        resultados = []
        for numero in range(3):
            for _ in range(3):
                self.assertEqual(self.login(password=f"error-{numero}").status_code, 401)
            nuevos = ejecutar(self.datos, confirmar=lambda _: "")
            self.assertEqual(len(nuevos), 1)
            resultados.extend(nuevos)
            self.assertEqual(ejecutar(self.datos, confirmar=lambda _: ""), [])
            # El login correcto reinicia la secuencia entre escenarios.
            self.assertEqual(self.login().status_code, 200)
        self.assertEqual(len(resultados), 3)
        with (self.datos / "resultados.csv").open(encoding="utf-8", newline="") as archivo:
            self.assertEqual(len(list(csv.DictReader(archivo))), 3)
        respuestas = (self.datos / "respuesta.log").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(respuestas), 3)
        self.assertTrue(all(",USUARIO_BLOQUEADO,usuario_01" in x for x in respuestas))
        for fila in resultados:
            self.assertEqual(fila["intentos"], "3")
            inicio = datetime.fromisoformat(fila["primer_intento"])
            deteccion = datetime.fromisoformat(fila["deteccion"])
            respuesta = datetime.fromisoformat(fila["respuesta"])
            self.assertAlmostEqual(float(fila["mttd_segundos"]), (deteccion - inicio).total_seconds(), places=6)
            self.assertAlmostEqual(float(fila["mttr_segundos"]), (respuesta - deteccion).total_seconds(), places=6)


if __name__ == "__main__":
    unittest.main()
