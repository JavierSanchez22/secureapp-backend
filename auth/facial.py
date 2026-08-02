"""
auth/facial.py — Factor 3: Reconocimiento facial con face_recognition.

Librería `face_recognition` (basada en dlib con deep learning):
  - Modelo HOG + SVM para detección rápida de caras
  - Red neuronal ResNet-34 para extraer 128 características faciales únicas
  - Comparación por distancia euclidiana (umbral: 0.6 por defecto)

Flujo:
  1. Registro: captura foto → extrae encoding (128 números) → cifra → guarda en DB
  2. Login: captura foto → extrae encoding → compara con el guardado → acepta/rechaza

El encoding facial se almacena cifrado con AES-256-GCM en la base de datos.
"""

import io
from PIL import Image

# ── Imports lazy de face_recognition y numpy ──────────────────────────────────
# NO importamos al nivel de módulo porque face_recognition carga los modelos
# de dlib al importar, lo que tarda 2-3 minutos y hace fallar el healthcheck
# de Railway. En su lugar, importamos solo cuando se necesitan.


# Umbral de similitud facial.
# 0.55 = más estricto (menos falsos positivos), 0.65 = más tolerante.
# 0.6 es el valor por defecto recomendado por la librería.
FACE_TOLERANCE = 0.55


def encode_face_from_bytes(image_bytes: bytes) -> list[float] | None:
    """
    Extrae el encoding facial (128 características) de una imagen.

    El encoding es un vector de 128 números float64 que representa
    de forma única las características del rostro detectado.

    Args:
        image_bytes: Imagen en bytes (JPEG, PNG, etc.)

    Returns:
        list[float] | None: Lista de 128 floats si se detectó una cara,
                            None si no se encontró ninguna cara en la imagen.
    """
    # Importar aquí (lazy) para no bloquear el arranque del servidor
    import numpy as np  # noqa: PLC0415
    import face_recognition  # noqa: PLC0415

    # Convertir bytes a array numpy RGB (face_recognition lo necesita en RGB)
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    img_array = np.array(img)

    # Detectar caras y extraer encodings
    # num_jitters=2 → re-muestrea 2 veces para mayor precisión
    encodings = face_recognition.face_encodings(img_array, num_jitters=2)

    if not encodings:
        return None  # No se detectó ninguna cara

    # Retornar el encoding de la primera cara detectada
    return encodings[0].tolist()


def verify_face(
    stored_encoding: list[float],
    new_image_bytes: bytes,
) -> tuple[bool, float]:
    """
    Compara un nuevo rostro contra el encoding guardado en la base de datos.

    Args:
        stored_encoding: Encoding facial almacenado (lista de 128 floats).
        new_image_bytes: Nueva foto del usuario en bytes.

    Returns:
        tuple[bool, float]:
            - bool: True si el rostro coincide con el almacenado.
            - float: Distancia euclidiana (0.0 = idéntico, 1.0 = muy diferente).
                     Valores < FACE_TOLERANCE (0.55) son considerados coincidencias.
    """
    # Importar aquí (lazy)
    import numpy as np  # noqa: PLC0415
    import face_recognition  # noqa: PLC0415

    new_encoding = encode_face_from_bytes(new_image_bytes)

    if new_encoding is None:
        # No se detectó cara en la nueva imagen
        return False, 1.0

    known = np.array([stored_encoding])
    unknown = np.array(new_encoding)

    # face_distance devuelve la distancia euclidiana
    distances = face_recognition.face_distance(known, unknown)
    distance = float(distances[0])

    # Comparar contra el umbral
    match = bool(face_recognition.compare_faces(
        [np.array(stored_encoding)],
        unknown,
        tolerance=FACE_TOLERANCE,
    )[0])

    return match, distance


def encoding_to_bytes(encoding: list[float]) -> bytes:
    """
    Serializa el encoding facial (lista de floats) a bytes para almacenar.

    Usa numpy's binary format (.npy) para preservar la precisión float64.

    Args:
        encoding: Lista de 128 floats.

    Returns:
        bytes: Encoding serializado en formato numpy binario.
    """
    import numpy as np  # noqa: PLC0415
    buf = io.BytesIO()
    np.save(buf, np.array(encoding, dtype=np.float64))
    buf.seek(0)
    return buf.read()


def bytes_to_encoding(data: bytes) -> list[float]:
    """
    Deserializa bytes a encoding facial (lista de floats).

    Args:
        data: Bytes en formato numpy binario.

    Returns:
        list[float]: Lista de 128 floats del encoding facial.
    """
    import numpy as np  # noqa: PLC0415
    buf = io.BytesIO(data)
    arr = np.load(buf)
    return arr.tolist()
