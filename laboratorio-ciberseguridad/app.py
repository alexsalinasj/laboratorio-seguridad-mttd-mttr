"""Aplicación de laboratorio: validación, hash, autenticación y eventos."""
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import re
import sqlite3

from flask import Flask, current_app, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "usuarios.db"
EVENTOS_PATH = BASE_DIR / "eventos.log"

app = Flask(__name__)
app.config.update(DB_PATH=DB_PATH, EVENTOS_PATH=EVENTOS_PATH)


def validar_usuario(usuario):
    """Entre 4 y 20 caracteres; solo letras, numeros o guion bajo."""
    return re.fullmatch(r"[A-Za-z0-9_]{4,20}", usuario) is not None


def validar_correo(correo):
    """Comprobacion basica del formato de correo electronico."""
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", correo) is not None


def validar_password(password):
    return len(password) >= 8


def registrar_evento(tipo, usuario):
    """Registra el evento sin guardar nunca una contrasena en el log."""
    usuario_log = re.sub(r"[^A-Za-z0-9_]", "_", usuario)[:20] or "desconocido"
    fecha = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    with Path(current_app.config["EVENTOS_PATH"]).open("a", encoding="utf-8") as archivo:
        archivo.write(f"{fecha},{tipo},{usuario_log}\n")


def conectar_bd():
    ruta = Path(current_app.config["DB_PATH"])
    if not ruta.exists():
        raise FileNotFoundError("Falta la base de datos")
    return sqlite3.connect(ruta)


def mostrar_error(plantilla, mensaje, estado, **datos):
    return render_template(plantilla, error=mensaje, **datos), estado


@app.route("/")
def inicio():
    return render_template("inicio.html")


@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        correo = request.form.get("correo", "").strip()
        # No se modifica la contrasena; sus espacios internos son significativos.
        password = request.form.get("password", "")

        if not validar_usuario(usuario):
            return mostrar_error("registro.html", "Usuario inválido: usa 4 a 20 letras, números o guion bajo.", 400, usuario=usuario, correo=correo)
        if not validar_correo(correo):
            return mostrar_error("registro.html", "Correo electrónico inválido.", 400, usuario=usuario, correo=correo)
        if not validar_password(password):
            return mostrar_error("registro.html", "La contraseña debe contener al menos 8 caracteres.", 400, usuario=usuario, correo=correo)

        try:
            with closing(conectar_bd()) as conexion:
                cursor = conexion.cursor()
                cursor.execute(
                    "SELECT id FROM usuarios WHERE usuario = ? OR correo = ?",
                    (usuario, correo),
                )
                if cursor.fetchone():
                    return mostrar_error("registro.html", "El usuario o correo ya está registrado.", 409, usuario=usuario, correo=correo)

                password_hash = generate_password_hash(password)
                cursor.execute(
                    "INSERT INTO usuarios (usuario, correo, password) VALUES (?, ?, ?)",
                    (usuario, correo, password_hash),
                )
                conexion.commit()
        except sqlite3.IntegrityError:
            return mostrar_error("registro.html", "El usuario o correo ya está registrado.", 409, usuario=usuario, correo=correo)
        except (FileNotFoundError, sqlite3.Error):
            current_app.logger.exception("No se pudo completar el registro")
            return mostrar_error("registro.html", "Servicio no disponible. Inténtalo más tarde.", 503, usuario=usuario, correo=correo)
        return render_template("registro.html", exito="Usuario registrado. Ya puedes iniciar sesión."), 201

    return render_template("registro.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        password = request.form.get("password", "")
        try:
            with closing(conectar_bd()) as conexion:
                cursor = conexion.cursor()
                cursor.execute(
                    "SELECT id, usuario, password FROM usuarios WHERE usuario = ?",
                    (usuario,),
                )
                resultado = cursor.fetchone()
        except (FileNotFoundError, sqlite3.Error):
            current_app.logger.exception("No se pudo consultar la base de datos")
            return mostrar_error("login.html", "Servicio no disponible. Inténtalo más tarde.", 503, usuario=usuario)

        if resultado and check_password_hash(resultado[2], password):
            try:
                registrar_evento("LOGIN_CORRECTO", usuario)
            except OSError:
                current_app.logger.exception("No se pudo registrar el evento")
                return mostrar_error("login.html", "Servicio no disponible. Inténtalo más tarde.", 503, usuario=usuario)
            return render_template("login.html", exito="Inicio de sesión correcto."), 200

        try:
            registrar_evento("LOGIN_FALLIDO", usuario)
        except OSError:
            current_app.logger.exception("No se pudo registrar el evento")
            return mostrar_error("login.html", "Servicio no disponible. Inténtalo más tarde.", 503, usuario=usuario)
        return mostrar_error("login.html", "Credenciales incorrectas.", 401, usuario=usuario)

    return render_template("login.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
