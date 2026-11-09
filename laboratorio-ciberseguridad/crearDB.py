"""Crea la base de datos SQLite del laboratorio."""
import sqlite3
from contextlib import closing
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "usuarios.db"


def crear_bd(ruta=DB_PATH):
    with closing(sqlite3.connect(ruta)) as conexion:
        with conexion:
            conexion.execute("""
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario TEXT NOT NULL UNIQUE,
                    correo TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL
                )
            """)
    print(f"Base de datos y tabla creadas correctamente: {ruta}")


if __name__ == "__main__":
    crear_bd()
