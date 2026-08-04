"""
main.py — FastAPI: todos los endpoints del sistema MFA.

═══════════════════════════════════════════════════════════════════════════════
ENDPOINTS
═══════════════════════════════════════════════════════════════════════════════

REGISTRO:
  POST /api/register/start        — Paso 1: email + contraseña
  GET  /api/register/totp-qr      — Obtener QR para Google Authenticator
  POST /api/register/totp-verify  — Confirmar que el TOTP fue configurado
  POST /api/register/face         — Subir foto facial para registro

AUTENTICACIÓN MFA:
  POST /api/auth/password         — Factor 1: verificar contraseña
  POST /api/auth/totp             — Factor 2: verificar código TOTP
  POST /api/auth/facial           — Factor 3: verificar cara (sube foto)

AUTORIZACIÓN:
  GET  /api/dashboard             — Recurso protegido (requiere JWT)
  GET  /api/health                — Health check

═══════════════════════════════════════════════════════════════════════════════
SEGURIDAD EN TRÁNSITO
═══════════════════════════════════════════════════════════════════════════════
• En producción: HTTPS obligatorio
• En desarrollo (Expo Go en red local): HTTP está bien para demostración
• Las fotos viajan como multipart/form-data
• Los tokens viajan en el header Authorization: Bearer <token>
"""

import io
import base64
import traceback
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from auth.facial import (
    bytes_to_encoding,
    encode_face_from_bytes,
    encoding_to_bytes,
    verify_face,
)
from auth.password import hash_password, verify_password
from auth.totp import generate_totp_secret, get_qr_bytes, verify_totp_code
from database import Base, engine, get_db
from models import User
from security import (
    check_account_lockout,
    create_access_token,
    create_mfa_session_token,
    decode_access_token,
    decrypt_data,
    encrypt_data,
    register_failed_attempt,
    reset_failed_attempts,
)

# ── Crear tablas en la DB ─────────────────────────────────────────────────────
Base.metadata.create_all(bind=engine)

# ── FastAPI App ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="SecureApp MFA API",
    description="Sistema de autenticación multi-factor con Argon2id + TOTP + Reconocimiento Facial",
    version="1.0.0",
)

# ── CORS (permite peticiones desde la app Expo) ───────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción: especifica tu dominio
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Manejador global de excepciones ─────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Captura cualquier excepción no manejada y devuelve JSON (nunca HTML)."""
    tb = traceback.format_exc()
    print(f"[ERROR] {request.url}\n{tb}")
    return JSONResponse(
        status_code=500,
        content={"detail": f"Error interno: {type(exc).__name__}: {str(exc)}"},
    )


# ═════════════════════════════════════════════════════════════════════════════
# SCHEMAS Pydantic (validación de entrada)
# ═════════════════════════════════════════════════════════════════════════════

class RegisterStartRequest(BaseModel):
    email: str
    password: str


class TOTPVerifyRequest(BaseModel):
    email: str
    code: str


class PasswordLoginRequest(BaseModel):
    email: str
    password: str


class TOTPLoginRequest(BaseModel):
    email: str
    code: str
    session_token: str


class FaceRegisterRequest(BaseModel):
    """Registro facial: foto enviada como base64 (evita error FormData en RN)."""
    email: str
    photo_base64: str


class FaceAuthRequest(BaseModel):
    """Verificación facial: foto + session token como base64."""
    email: str
    session_token: str
    photo_base64: str


# ═════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/health")
def health_check():
    """Verifica que el servidor está corriendo."""
    return {"status": "ok", "message": "SecureApp MFA API funcionando"}


@app.get("/api/debug/facial")
def debug_facial():
    """
    Diagnóstico: prueba la importación de face_recognition y dlib.
    Útil para detectar errores de instalación en Railway.
    """
    results = {}
    try:
        import numpy as np
        results["numpy"] = np.__version__
    except Exception as e:
        results["numpy"] = f"ERROR: {e}"

    try:
        import dlib
        results["dlib"] = str(dlib.DLIB_VERSION)
    except Exception as e:
        results["dlib"] = f"ERROR: {e}"

    try:
        import face_recognition
        results["face_recognition"] = "ok"
    except Exception as e:
        results["face_recognition"] = f"ERROR: {e}"

    try:
        from PIL import Image
        results["PIL"] = "ok"
    except Exception as e:
        results["PIL"] = f"ERROR: {e}"

    all_ok = all("ERROR" not in str(v) for v in results.values())
    return {"all_ok": all_ok, "libraries": results}


# ═════════════════════════════════════════════════════════════════════════════
# REGISTRO — Paso 1: Email + Contraseña
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/register/start")
def register_start(body: RegisterStartRequest, db: Session = Depends(get_db)):
    """
    Inicia el proceso de registro.
    Almacena email y hash Argon2id de la contraseña.
    Genera y guarda el secreto TOTP cifrado.

    Returns:
        email: para identificar al usuario en los siguientes pasos.
    """
    # Verificar si el email ya existe
    existing = db.query(User).filter(User.email == body.email).first()
    if existing and existing.is_registered:
        raise HTTPException(status_code=400, detail="El email ya está registrado.")

    # Hash Argon2id de la contraseña (NUNCA en texto plano)
    password_hash = hash_password(body.password)

    # Generar secreto TOTP y cifrarlo con AES-256-GCM
    totp_secret = generate_totp_secret()
    totp_secret_enc = encrypt_data(totp_secret.encode())

    if existing:
        # Actualizar registro incompleto
        existing.password_hash = password_hash
        existing.totp_secret_enc = totp_secret_enc
        existing.is_registered = False
        db.commit()
        user = existing
    else:
        # Crear nuevo usuario
        user = User(
            email=body.email,
            password_hash=password_hash,
            totp_secret_enc=totp_secret_enc,
            is_registered=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    return {"message": "Paso 1 completado. Configura tu TOTP.", "email": body.email}


# ═════════════════════════════════════════════════════════════════════════════
# REGISTRO — Paso 2: QR Code TOTP
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/register/totp-qr")
def get_totp_qr(email: str, db: Session = Depends(get_db)):
    """
    Devuelve el QR code PNG para que el usuario lo escanee con Google Authenticator.

    Query param: email
    Returns: imagen PNG del QR code
    """
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.totp_secret_enc:
        raise HTTPException(status_code=404, detail="Usuario no encontrado. Completa el paso 1.")

    # Descifrar el secreto TOTP
    totp_secret = decrypt_data(user.totp_secret_enc).decode()

    qr_bytes = get_qr_bytes(email, totp_secret)

    return Response(content=qr_bytes, media_type="image/png")


# ═════════════════════════════════════════════════════════════════════════════
# REGISTRO — Paso 3: Verificar TOTP configurado
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/register/totp-verify")
def register_totp_verify(body: TOTPVerifyRequest, db: Session = Depends(get_db)):
    """
    Verifica que el usuario configuró correctamente Google Authenticator.
    Necesita un código válido del TOTP para confirmar el setup.
    """
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not user.totp_secret_enc:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    totp_secret = decrypt_data(user.totp_secret_enc).decode()

    if not verify_totp_code(totp_secret, body.code):
        raise HTTPException(status_code=400, detail="Código TOTP incorrecto. Vuelve a escanear el QR.")

    return {"message": "TOTP configurado correctamente. Ahora registra tu cara.", "email": body.email}


# ═════════════════════════════════════════════════════════════════════════════
# REGISTRO — Paso 4: Foto facial
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/register/face")
def register_face(body: FaceRegisterRequest, db: Session = Depends(get_db)):
    """
    Registra el encoding facial del usuario.
    Recibe la foto como base64 en JSON, extrae el encoding,
    lo cifra con AES-256-GCM y lo guarda en la DB.
    """
    user = db.query(User).filter(User.email == body.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    # Decodificar base64 → bytes de imagen
    # Limpiar prefijo data URL si el cliente lo incluyó (ej: "data:image/jpeg;base64,...")
    try:
        photo_b64 = body.photo_base64
        if "," in photo_b64:
            photo_b64 = photo_b64.split(",", 1)[1]
        image_bytes = base64.b64decode(photo_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Imagen base64 inválida.")

    # Extraer encoding facial (128 características)
    encoding = encode_face_from_bytes(image_bytes)
    if encoding is None:
        raise HTTPException(
            status_code=400,
            detail="No se detectó ningún rostro en la foto. Asegúrate de que tu cara sea visible.",
        )

    # Serializar encoding a bytes, cifrar con AES-256-GCM y guardar
    encoding_bytes = encoding_to_bytes(encoding)
    user.face_encoding_enc = encrypt_data(encoding_bytes)
    user.is_registered = True  # Registro completo
    db.commit()

    return {"message": "Registro completado exitosamente. Ya puedes iniciar sesión.", "email": body.email}


# ═════════════════════════════════════════════════════════════════════════════
# AUTENTICACIÓN MFA — Factor 1: Contraseña
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/auth/password")
def auth_password(body: PasswordLoginRequest, db: Session = Depends(get_db)):
    """
    Factor 1 — AUTENTICACIÓN por contraseña.

    IDENTIFICACIÓN: el email identifica al usuario.
    AUTENTICACIÓN: la contraseña demuestra quién es.

    Si la contraseña es correcta, emite un session_token MFA temporal
    que debe usarse en los pasos 2 y 3.

    Aplica política de bloqueo: 3 intentos → 5 min → suspensión.
    """
    # Buscar usuario
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not user.is_registered:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas.")

    # Verificar bloqueo
    can_attempt, lockout_msg = check_account_lockout(user)
    if not can_attempt:
        raise HTTPException(status_code=429, detail=lockout_msg)

    # Verificar contraseña con Argon2id
    if not verify_password(body.password, user.password_hash):
        result = register_failed_attempt(user, db)
        raise HTTPException(status_code=401, detail=result["message"])

    # Contraseña correcta: reset intentos + emitir session token
    reset_failed_attempts(user, db)

    from datetime import timedelta
    session_token = create_mfa_session_token()
    user.mfa_session_token = session_token
    user.mfa_session_expires = datetime.utcnow() + timedelta(minutes=10)
    db.commit()

    return {
        "message": "Factor 1 superado. Ingresa tu código TOTP.",
        "session_token": session_token,
        "email": body.email,
    }


# ═════════════════════════════════════════════════════════════════════════════
# AUTENTICACIÓN MFA — Factor 2: TOTP
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/auth/totp")
def auth_totp(body: TOTPLoginRequest, db: Session = Depends(get_db)):
    """
    Factor 2 — AUTENTICACIÓN por TOTP.

    Requiere el session_token emitido en el paso anterior.
    Si el código TOTP es correcto, emite un nuevo session_token para el paso 3.
    """
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not user.is_registered:
        raise HTTPException(status_code=401, detail="Usuario no encontrado.")

    # Verificar bloqueo
    can_attempt, lockout_msg = check_account_lockout(user)
    if not can_attempt:
        raise HTTPException(status_code=429, detail=lockout_msg)

    # Verificar session token MFA
    now = datetime.now(timezone.utc)
    if (
        not user.mfa_session_token
        or user.mfa_session_token != body.session_token
        or not user.mfa_session_expires
        or user.mfa_session_expires.replace(tzinfo=timezone.utc) < now
    ):
        raise HTTPException(status_code=401, detail="Sesión MFA inválida o expirada. Reinicia el login.")

    # Descifrar secreto TOTP y verificar código
    totp_secret = decrypt_data(user.totp_secret_enc).decode()
    if not verify_totp_code(totp_secret, body.code):
        result = register_failed_attempt(user, db)
        raise HTTPException(status_code=401, detail=result["message"])

    # Código correcto: emitir nuevo session token para Factor 3
    reset_failed_attempts(user, db)
    from datetime import timedelta
    new_session_token = create_mfa_session_token()
    user.mfa_session_token = new_session_token
    user.mfa_session_expires = datetime.utcnow() + timedelta(minutes=10)
    db.commit()

    return {
        "message": "Factor 2 superado. Verifica tu identidad con tu cara.",
        "session_token": new_session_token,
        "email": body.email,
    }


# ═════════════════════════════════════════════════════════════════════════════
# AUTENTICACIÓN MFA — Factor 3: Reconocimiento Facial
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/auth/facial")
def auth_facial(body: FaceAuthRequest, db: Session = Depends(get_db)):
    """
    Factor 3 — AUTENTICACIÓN por reconocimiento facial.

    Recibe la foto como base64 en JSON, la compara con el encoding guardado.
    Si coincide, emite el JWT de acceso final (AUTORIZACIÓN).
    """
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not user.is_registered:
        raise HTTPException(status_code=401, detail="Usuario no encontrado.")

    # Verificar bloqueo
    can_attempt, lockout_msg = check_account_lockout(user)
    if not can_attempt:
        raise HTTPException(status_code=429, detail=lockout_msg)

    # Verificar session token MFA
    now = datetime.now(timezone.utc)
    if (
        not user.mfa_session_token
        or user.mfa_session_token != body.session_token
        or not user.mfa_session_expires
        or user.mfa_session_expires.replace(tzinfo=timezone.utc) < now
    ):
        raise HTTPException(status_code=401, detail="Sesión MFA inválida o expirada. Reinicia el login.")

    # Decodificar base64 → bytes de imagen (limpiando prefijo data URL si existe)
    try:
        photo_b64 = body.photo_base64
        if "," in photo_b64:
            photo_b64 = photo_b64.split(",", 1)[1]
        image_bytes = base64.b64decode(photo_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Imagen base64 inválida.")

    # Descifrar encoding facial almacenado
    if not user.face_encoding_enc:
        raise HTTPException(status_code=500, detail="No hay encoding facial registrado.")

    stored_encoding_bytes = decrypt_data(user.face_encoding_enc)
    stored_encoding = bytes_to_encoding(stored_encoding_bytes)

    # Comparar con la foto recibida
    match, distance = verify_face(stored_encoding, image_bytes)

    if not match:
        result = register_failed_attempt(user, db)
        raise HTTPException(
            status_code=401,
            detail=f"Rostro no reconocido (distancia: {distance:.3f}). {result['message']}",
        )

    # ¡Todos los factores superados! Emitir JWT de acceso
    reset_failed_attempts(user, db)
    user.mfa_session_token = None
    user.mfa_session_expires = None
    user.last_login = datetime.utcnow()
    db.commit()

    access_token = create_access_token(user_id=user.id, email=user.email)

    return {
        "message": "Autenticación MFA completada. Acceso concedido.",
        "access_token": access_token,
        "token_type": "bearer",
        "face_distance": round(distance, 3),
        "email": user.email,
    }


# ═════════════════════════════════════════════════════════════════════════════
# AUTORIZACIÓN — Dashboard protegido con JWT
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/dashboard")
def get_dashboard(authorization: str = Header(None), db: Session = Depends(get_db)):
    """
    Recurso protegido — requiere JWT válido en el header Authorization.

    Header: Authorization: Bearer <token>

    Demuestra la capa de AUTORIZACIÓN del sistema MFA:
    - Identifica quién eres (sub/email del JWT)
    - Verifica que el token es válido y no ha expirado
    - Retorna datos personalizados del usuario
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token de acceso requerido.")

    token = authorization.split(" ")[1]
    payload = decode_access_token(token)

    if payload is None:
        raise HTTPException(status_code=401, detail="Token inválido o expirado.")

    user_id = int(payload["sub"])
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    return {
        "message": f"Bienvenido, {user.email}",
        "user_id": user.id,
        "email": user.email,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "mfa_factors": {
            "password": True,
            "totp": user.totp_secret_enc is not None,
            "facial": user.face_encoding_enc is not None,
        },
    }
