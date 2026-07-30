"""
database.py — Configuración de la base de datos SQLite con SQLAlchemy.

Crea el engine, la sesión y la función para obtener una sesión por request.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# Base de datos SQLite local — fácil de usar en desarrollo/demo
DATABASE_URL = "sqlite:///./mfa_secure.db"

engine = create_engine(
    DATABASE_URL,
    # check_same_thread=False es necesario para SQLite con FastAPI
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Clase base de la que heredan todos los modelos."""
    pass


def get_db():
    """
    Generador de sesión de base de datos.
    Se usa como dependencia en FastAPI (Depends(get_db)).
    Garantiza que la sesión se cierre al terminar el request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
