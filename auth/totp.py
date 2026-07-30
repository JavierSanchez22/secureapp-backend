"""
auth/totp.py — Factor 2: TOTP (Time-based One-Time Password).

Usa la librería `pyotp` que implementa el estándar RFC 6238 (TOTP).
Compatible con Google Authenticator, Authy, Microsoft Authenticator, etc.

Flujo:
  1. Al registrarse: generar secreto → mostrar QR → usuario escanea con app
  2. Al hacer login: usuario ve el código de 6 dígitos en su app → lo ingresa
  3. Backend verifica con pyotp.TOTP(secret).verify(code)

El secreto TOTP NO se almacena en texto plano; se cifra con AES-256-GCM
antes de guardarlo (ver security.py → encrypt_data / decrypt_data).
"""

import io

import pyotp
import qrcode
import qrcode.image.pil


APP_NAME = "SecureApp MFA"


def generate_totp_secret() -> str:
    """
    Genera un secreto aleatorio de 32 caracteres en Base32.

    Retorna:
        str: Secreto Base32 (160 bits de entropía).
    """
    return pyotp.random_base32()


def get_totp_uri(email: str, secret: str) -> str:
    """
    Construye la URI TOTP estándar (otpauth://) para generar el QR code.

    La URI sigue el formato estándar de Google Authenticator:
    otpauth://totp/<app>:<email>?secret=<secret>&issuer=<app>

    Args:
        email: Email del usuario (aparece en la app autenticadora).
        secret: Secreto Base32 del usuario.

    Returns:
        str: URI otpauth:// lista para codificar en QR.
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=APP_NAME)


def get_qr_bytes(email: str, secret: str) -> bytes:
    """
    Genera una imagen PNG del QR code para escanear con la app autenticadora.

    Args:
        email: Email del usuario.
        secret: Secreto Base32 del usuario.

    Returns:
        bytes: Imagen PNG del QR code lista para enviar como respuesta HTTP.
    """
    uri = get_totp_uri(email, secret)

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf.read()


def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verifica si el código TOTP de 6 dígitos es válido.

    Acepta una ventana de ±1 intervalo (30 segundos) para compensar
    diferencias de reloj entre el servidor y el dispositivo del usuario.

    Args:
        secret: Secreto Base32 del usuario (en texto plano, ya desencriptado).
        code: Código de 6 dígitos ingresado por el usuario.

    Returns:
        bool: True si el código es válido en la ventana temporal actual.
    """
    totp = pyotp.TOTP(secret)
    # valid_window=1 → acepta el código del intervalo anterior y siguiente
    # (compensa hasta 30 segundos de diferencia de reloj)
    return totp.verify(code, valid_window=1)
