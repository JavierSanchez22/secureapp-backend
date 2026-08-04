"""
auth/facial.py — Factor 3: Reconocimiento facial con OpenCV.

Por qué OpenCV en lugar de face_recognition/dlib:
  - face_recognition usa dlib (C++) que necesita compilarse → puede fallar en Railway
  - opencv-python-headless tiene wheels pre-compilados → instala en segundos, sin cmake
  - Usa ~10x menos RAM que dlib en servidor

Técnica usada:
  - Detección de cara: Haar Cascade (haarcascade_frontalface_default.xml)
  - Encoding: parche 64×64 px + ecualización de histograma + normalización
  - Comparación: distancia coseno (umbral: 0.25)

Flujo:
  1. Registro: foto → detecta cara → extrae vector 4096-dim → cifra AES → guarda en DB
  2. Login: foto → extrae vector → compara coseno con el guardado → acepta/rechaza

El encoding facial se almacena cifrado con AES-256-GCM en la base de datos.
"""

import io
import cv2
import numpy as np


# ── Umbral de distancia coseno ────────────────────────────────────────────────
# 0.0 = idéntico, 1.0 = completamente diferente
# < 0.08 = misma persona (se redujo el umbral para evitar aceptar rostros incorrectos)
FACE_TOLERANCE = 0.08

# ── Singleton del detector Haar Cascade ──────────────────────────────────────
_cascade = None


def _get_cascade() -> cv2.CascadeClassifier:
    """Carga el detector Haar Cascade una sola vez (lazy singleton)."""
    global _cascade
    if _cascade is None:
        # haarcascade_frontalface_default.xml viene incluido en opencv-python-headless
        path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        _cascade = cv2.CascadeClassifier(path)
    return _cascade


def _image_bytes_to_gray(image_bytes: bytes):
    """
    Convierte bytes de imagen (JPEG/PNG) a array numpy en escala de grises.

    Returns:
        numpy.ndarray | None: Imagen en grises, o None si falla la decodificación.
    """
    nparr = np.frombuffer(image_bytes, np.uint8)
    img_color = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img_color is None:
        return None
    return cv2.cvtColor(img_color, cv2.COLOR_BGR2GRAY)


def encode_face_from_bytes(image_bytes: bytes) -> list[float] | None:
    """
    Detecta la cara en la imagen y extrae un vector de características facial.

    Proceso:
      1. Decodificar imagen → escala de grises
      2. Haar Cascade detecta caras
      3. ROI de la cara más grande → resize 64×64
      4. Ecualización de histograma (invariante a iluminación)
      5. Desenfoque gaussiano (reduce ruido)
      6. Normalizar [0,1] y aplanar → vector 4096 floats

    Args:
        image_bytes: Imagen en bytes (JPEG, PNG, etc.)

    Returns:
        list[float] | None: Vector de 4096 floats si detectó cara, None si no.
    """
    gray = _image_bytes_to_gray(image_bytes)
    if gray is None:
        return None

    cascade = _get_cascade()
    faces = cascade.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=4,
        minSize=(50, 50),
    )

    if len(faces) == 0:
        # Intentar con parámetros más permisivos (caras pequeñas o mala iluminación)
        faces = cascade.detectMultiScale(
            gray,
            scaleFactor=1.05,
            minNeighbors=2,
            minSize=(30, 30),
        )

    if len(faces) == 0:
        return None

    # Seleccionar la cara más grande detectada
    x, y, w, h = max(faces, key=lambda f: f[2] * f[3])
    face_roi = gray[y : y + h, x : x + w]

    # Normalización del parche
    face_resized = cv2.resize(face_roi, (64, 64))
    face_equalized = cv2.equalizeHist(face_resized)   # Invariante a iluminación
    face_blurred = cv2.GaussianBlur(face_equalized, (3, 3), 0)  # Reduce ruido

    # Vector normalizado en [0, 1]
    features = face_blurred.astype(np.float32) / 255.0
    return features.flatten().tolist()


def verify_face(
    stored_encoding: list[float],
    new_image_bytes: bytes,
) -> tuple[bool, float]:
    """
    Compara un nuevo rostro contra el encoding guardado usando distancia coseno.

    Distancia coseno = 1 - (A·B / |A||B|)
      0.0 = idéntico
      1.0 = completamente diferente
      < 0.25 = misma persona (umbral para demo)

    Args:
        stored_encoding: Vector facial almacenado (4096 floats).
        new_image_bytes: Nueva foto del usuario en bytes.

    Returns:
        tuple[bool, float]:
            - bool: True si el rostro coincide.
            - float: Distancia coseno resultante.
    """
    new_encoding = encode_face_from_bytes(new_image_bytes)

    if new_encoding is None:
        return False, 1.0

    known = np.array(stored_encoding, dtype=np.float32)
    unknown = np.array(new_encoding, dtype=np.float32)

    # Distancia coseno
    dot = np.dot(known, unknown)
    norm_k = np.linalg.norm(known)
    norm_u = np.linalg.norm(unknown)

    if norm_k == 0 or norm_u == 0:
        return False, 1.0

    cosine_similarity = dot / (norm_k * norm_u)
    distance = float(1.0 - cosine_similarity)

    match = distance < FACE_TOLERANCE
    return match, distance


def encoding_to_bytes(encoding: list[float]) -> bytes:
    """
    Serializa el encoding facial (lista de floats) a bytes para almacenar.

    Usa numpy's binary format (.npy) para preservar precisión float32.
    """
    buf = io.BytesIO()
    np.save(buf, np.array(encoding, dtype=np.float32))
    buf.seek(0)
    return buf.read()


def bytes_to_encoding(data: bytes) -> list[float]:
    """
    Deserializa bytes a encoding facial (lista de floats).
    """
    buf = io.BytesIO(data)
    arr = np.load(buf)
    return arr.tolist()
