"""
security.py — JWT, cifrado AES-256-GCM y lógica de bloqueo de cuentas.

═══════════════════════════════════════════════════════════════════════════════
CIFRADO DE DATOS SENSIBLES — AES-256-GCM
═══════════════════════════════════════════════════════════════════════════════
Para proteger datos sensibles en la base de datos (secreto TOTP, encoding
facial), se usa AES-256-GCM con las siguientes características:

  • AES-256        : clave de 256 bits (32 bytes) — el más fuerte de AES
  • GCM (Galois/Counter Mode): cifrado AUTENTICADO
    - Garantiza CONFIDENCIALIDAD (nadie puede leer los datos)
    - Garantiza INTEGRIDAD (detecta si los datos fueron alterados)
    - Incluye un tag de autenticación de 128 bits (16 bytes)
  • Nonce de 12 bytes aleatorio por cada cifrado (nunca se reutiliza)
  • Formato almacenado: [nonce 12 bytes] + [ciphertext] + [tag 16 bytes]

La clave maestra se deriva de una variable de entorno o se genera automáticamente.
En producción SIEMPRE debe estar en una variable de entorno segura.

═══════════════════════════════════════════════════════════════════════════════
JWT — JSON Web Tokens (Autorización)
═══════════════════════════════════════════════════════════════════════════════
Después de completar los 3 factores MFA, se emite un JWT firmado con HS256.
El JWT contiene el user_id y expira en 24 horas.

═══════════════════════════════════════════════════════════════════════════════
LÓGICA DE BLOQUEO (Rate Limiting por cuenta)
═══════════════════════════════════════════════════════════════════════════════
  Intento 1-3: Normal
  Intento 4+:  Bloqueo temporal de 5 minutos
  Si falla DESPUÉS del desbloqueo: Suspensión permanente de la cuenta
"""

import os
import secrets
from base64 import b64decode, b64encode
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from models import User

# ── Configuración JWT ─────────────────────────────────────────────────────────
JWT_SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "CAMBIA_ESTO_EN_PRODUCCION_usa_openssl_rand_hex_32",
)
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24

# ── Clave maestra AES-256 ─────────────────────────────────────────────────────
# En producción: variable de entorno AES_MASTER_KEY con 32 bytes en hex
_raw_key = os.getenv("AES_MASTER_KEY", "")
if _raw_key:
    # ── Producción (Railway): clave desde variable de entorno ─────────────────
    AES_MASTER_KEY = bytes.fromhex(_raw_key)
    assert len(AES_MASTER_KEY) == 32, "AES_MASTER_KEY debe ser 32 bytes (64 hex chars)"
    print("[SECURITY] AES_MASTER_KEY cargada desde variable de entorno.")
else:
    # ── Desarrollo local: generar clave persistente en archivo ────────────────
    KEY_FILE = "aes_master.key"
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            AES_MASTER_KEY = bytes.fromhex(f.read().strip().decode())
        print("[SECURITY] AES_MASTER_KEY cargada desde aes_master.key")
    else:
        AES_MASTER_KEY = AESGCM.generate_key(bit_length=256)
        with open(KEY_FILE, "w") as f:
            f.write(AES_MASTER_KEY.hex())
        print(f"[SECURITY] ⚠️  Nueva AES_MASTER_KEY generada → aes_master.key")
        print(f"[SECURITY] Para Railway, copia este valor como variable de entorno:")
        print(f"[SECURITY] AES_MASTER_KEY={AES_MASTER_KEY.hex()}")

# Instancia del cifrador AES-256-GCM
_aesgcm = AESGCM(AES_MASTER_KEY)

# ── Configuración de bloqueo ──────────────────────────────────────────────────
MAX_ATTEMPTS_BEFORE_LOCK = 3     # Intentos antes del primer bloqueo
LOCKOUT_DURATION_MINUTES = 5     # Minutos de bloqueo temporal


# ═════════════════════════════════════════════════════════════════════════════
# CIFRADO AES-256-GCM
# ═════════════════════════════════════════════════════════════════════════════

def encrypt_data(plaintext: bytes) -> bytes:
    """
    Cifra datos con AES-256-GCM.

    Formato del resultado (bytes):
        [nonce: 12 bytes] + [ciphertext + auth_tag: N+16 bytes]

    El nonce es aleatorio y único por cada llamada a esta función.
    En GCM, NUNCA se debe reutilizar un nonce con la misma clave.

    Args:
        plaintext: Datos a cifrar en bytes.

    Returns:
        bytes: Nonce + ciphertext + tag autenticado.
    """
    nonce = os.urandom(12)  # 96 bits — recomendado por NIST para GCM
    ciphertext = _aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ciphertext  # El tag de 16 bytes ya está incluido al final


def decrypt_data(encrypted: bytes) -> bytes:
    """
    Descifra y verifica datos cifrados con AES-256-GCM.

    Lanza una excepción si:
    - Los datos fueron alterados (tag de autenticación inválido)
    - La clave es incorrecta
    - El nonce o datos están corruptos

    Args:
        encrypted: Nonce (12 bytes) + ciphertext + tag de autenticación.

    Returns:
        bytes: Datos originales descifrados.

    Raises:
        cryptography.exceptions.InvalidTag: Si los datos fueron alterados.
    """
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    return _aesgcm.decrypt(nonce, ciphertext, associated_data=None)


# ═════════════════════════════════════════════════════════════════════════════
# JWT — Autorización
# ═════════════════════════════════════════════════════════════════════════════

def create_access_token(user_id: int, email: str) -> str:
    """
    Crea un JWT de acceso firmado con HS256.

    El JWT contiene:
        - sub: ID del usuario
        - email: Email del usuario
        - exp: Tiempo de expiración (24 horas desde ahora)
        - iat: Tiempo de emisión

    Args:
        user_id: ID del usuario en la base de datos.
        email: Email del usuario.

    Returns:
        str: Token JWT firmado.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    """
    Decodifica y verifica un JWT de acceso.

    Args:
        token: Token JWT a verificar.

    Returns:
        dict | None: Payload del token si es válido, None si es inválido o expirado.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


# ═════════════════════════════════════════════════════════════════════════════
# TOKEN DE SESIÓN MFA (vincula los 3 pasos del flujo)
# ═════════════════════════════════════════════════════════════════════════════

def create_mfa_session_token() -> str:
    """
    Genera un token de sesión MFA temporal de 32 bytes (256 bits).

    Este token se emite al completar el Factor 1 y debe presentarse
    en los Factores 2 y 3 para garantizar que todos los pasos
    los realiza la misma sesión.

    Returns:
        str: Token hexadecimal de 64 caracteres.
    """
    return secrets.token_hex(32)


# ═════════════════════════════════════════════════════════════════════════════
# LÓGICA DE BLOQUEO DE CUENTAS
# ═════════════════════════════════════════════════════════════════════════════

def check_account_lockout(user: User) -> tuple[bool, str]:
    """
    Verifica si una cuenta está bloqueada o suspendida.

    Reglas:
        1. Si is_suspended = True → bloqueada permanentemente.
        2. Si locked_until > ahora → bloqueada temporalmente.
        3. Si locked_until <= ahora → bloqueo expirado, puede intentar.

    Args:
        user: Objeto User de la base de datos.

    Returns:
        tuple[bool, str]:
            - bool: True si la cuenta puede intentar autenticarse.
            - str: Mensaje de error si está bloqueada, "" si puede continuar.
    """
    now = datetime.now(timezone.utc)

    if user.is_suspended:
        return False, "Cuenta suspendida permanentemente. Contacta al administrador."

    if user.locked_until:
        locked_until_aware = user.locked_until.replace(tzinfo=timezone.utc)
        if locked_until_aware > now:
            remaining = int((locked_until_aware - now).total_seconds())
            return False, f"Cuenta bloqueada. Espera {remaining} segundos."

    return True, ""


def register_failed_attempt(user: User, db: Session) -> dict:
    """
    Registra un intento fallido de autenticación y aplica la política de bloqueo.

    Política:
        - Intentos 1-3: Muestra intentos restantes.
        - Al llegar a 3 (y si ya estaba bloqueado antes): Suspende la cuenta.
        - Al llegar a 3 (primera vez): Bloquea por LOCKOUT_DURATION_MINUTES minutos.

    Args:
        user: Objeto User.
        db: Sesión de base de datos.

    Returns:
        dict con 'action' ('warning' | 'locked' | 'suspended') y 'message'.
    """
    user.failed_attempts += 1

    if user.failed_attempts >= MAX_ATTEMPTS_BEFORE_LOCK:
        # ¿Ya había sido bloqueado antes? (reincidente) → suspender
        if user.locked_until is not None:
            user.is_suspended = True
            db.commit()
            return {
                "action": "suspended",
                "message": "Cuenta suspendida permanentemente por múltiples intentos fallidos.",
            }

        # Primera vez que llega al límite → bloquear temporalmente
        user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        user.failed_attempts = 0  # Reiniciar contador para el siguiente ciclo
        db.commit()
        return {
            "action": "locked",
            "message": f"Demasiados intentos fallidos. Cuenta bloqueada por {LOCKOUT_DURATION_MINUTES} minutos.",
        }

    remaining = MAX_ATTEMPTS_BEFORE_LOCK - user.failed_attempts
    db.commit()
    return {
        "action": "warning",
        "message": f"Credenciales incorrectas. Te quedan {remaining} intento(s) antes del bloqueo.",
    }


def reset_failed_attempts(user: User, db: Session) -> None:
    """
    Reinicia el contador de intentos fallidos después de un login exitoso.

    Args:
        user: Objeto User.
        db: Sesión de base de datos.
    """
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()
