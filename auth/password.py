"""
auth/password.py — Factor 1: Gestión segura de contraseñas con Argon2id.

¿Por qué Argon2id y no bcrypt/SHA-256?
───────────────────────────────────────
• Argon2id ganó el Password Hashing Competition (PHC) en 2015.
• Es resistente a ataques de GPU porque usa MEMORIA RAM configurable.
  Un hash bcrypt con una GPU moderna puede probarse millones de veces
  por segundo. Argon2id con 64 MB de RAM lo reduce a cientos por segundo.
• Es resistente a ataques de side-channel (variante 'id' combina 'i' y 'd').
• El hash resultante incluye el SALT de 128 bits y los parámetros embebidos:
  $argon2id$v=19$m=65536,t=3,p=4$<salt_base64>$<hash_base64>
  Esto significa que no hay que almacenar el salt por separado.

Parámetros según recomendación OWASP 2024:
  - memory_cost = 65536  (64 MB de RAM por operación)
  - time_cost   = 3      (3 iteraciones)
  - parallelism = 4      (4 hilos)
  - hash_len    = 32     (256 bits de output)
  - salt_len    = 16     (128 bits de salt aleatorio)
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# ── Configuración del hasher (parámetros OWASP 2024) ─────────────────────────
_ph = PasswordHasher(
    time_cost=3,       # Número de iteraciones
    memory_cost=65536, # 64 MB de RAM — dificulta ataques con GPU/ASIC
    parallelism=4,     # Hilos paralelos
    hash_len=32,       # 256 bits de output
    salt_len=16,       # 128 bits de salt aleatorio por usuario
)


def hash_password(plain_password: str) -> str:
    """
    Genera un hash Argon2id de la contraseña en texto plano.

    El salt aleatorio de 128 bits es generado automáticamente y embebido
    en el hash resultante. Nunca necesitas almacenar el salt por separado.

    Args:
        plain_password: Contraseña en texto plano del usuario.

    Returns:
        str: Hash Argon2id con salt y parámetros embebidos.
             Formato: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    """
    return _ph.hash(plain_password)


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """
    Verifica si una contraseña en texto plano coincide con el hash almacenado.

    La verificación es resistente a timing attacks (tiempo constante).

    Args:
        plain_password: Contraseña ingresada por el usuario.
        stored_hash: Hash Argon2id almacenado en la base de datos.

    Returns:
        bool: True si la contraseña es correcta, False en caso contrario.
    """
    try:
        return _ph.verify(stored_hash, plain_password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """
    Verifica si el hash necesita ser re-generado con parámetros actualizados.

    Útil para migración cuando se endurecen los parámetros en el futuro.

    Args:
        stored_hash: Hash almacenado en la base de datos.

    Returns:
        bool: True si los parámetros del hash son más débiles que los actuales.
    """
    return _ph.check_needs_rehash(stored_hash)
