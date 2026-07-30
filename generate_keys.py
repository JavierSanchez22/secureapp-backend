#!/usr/bin/env python3
"""
generate_keys.py — Genera las claves de seguridad para Railway.

Ejecutar UNA SOLA VEZ antes de desplegar:
  python3 generate_keys.py

Copia los valores generados como variables de entorno en Railway.
"""

import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

aes_key = AESGCM.generate_key(bit_length=256)
jwt_secret = secrets.token_hex(32)

print("=" * 60)
print("  Variables de entorno para Railway")
print("  Cópialas en: Railway Dashboard → Variables")
print("=" * 60)
print(f"AES_MASTER_KEY={aes_key.hex()}")
print(f"JWT_SECRET_KEY={jwt_secret}")
print("=" * 60)
print("⚠️  GUARDA ESTAS CLAVES EN UN LUGAR SEGURO.")
print("   Si las pierdes, los datos cifrados quedan ilegibles.")
