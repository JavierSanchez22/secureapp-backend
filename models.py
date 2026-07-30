"""
models.py — Modelos de base de datos (SQLAlchemy ORM).

Define la tabla de usuarios con todos los campos necesarios para MFA.
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class User(Base):
    """
    Tabla `users` — almacena todo lo necesario para el flujo MFA de 3 factores.

    Campos de seguridad:
    - password_hash     : hash Argon2id de la contraseña (nunca en texto plano)
    - totp_secret_enc   : secreto TOTP cifrado con AES-256-GCM
    - face_encoding_enc : codificación facial cifrada con AES-256-GCM

    Campos de bloqueo (rate-limiting):
    - failed_attempts   : contador de intentos fallidos consecutivos
    - locked_until      : timestamp hasta el que la cuenta está bloqueada
    - is_suspended      : True si la cuenta fue suspendida permanentemente

    Campos de estado MFA por sesión:
    - mfa_step          : paso actual del flujo ('password', 'totp', 'facial', 'done')
    - mfa_session_token : token temporal para validar que los pasos son consecutivos
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)

    # ── Factor 1: Contraseña (Argon2id hash) ──────────────────────────────────
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    # ── Factor 2: TOTP (secreto cifrado AES-256-GCM) ─────────────────────────
    totp_secret_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=True)

    # ── Factor 3: Cara (encoding numpy cifrado AES-256-GCM) ──────────────────
    face_encoding_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=True)

    # ── Estado del registro ───────────────────────────────────────────────────
    is_registered: Mapped[bool] = mapped_column(Boolean, default=False)

    # ── Control de intentos fallidos (bloqueo) ────────────────────────────────
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_suspended: Mapped[bool] = mapped_column(Boolean, default=False)

    # ── Sesión MFA temporal (para validar pasos en orden) ────────────────────
    mfa_session_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_session_expires: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
