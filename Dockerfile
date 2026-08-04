# ── Base: Python 3.12 slim ────────────────────────────────────────────────────
FROM python:3.12-slim

# ── Dependencias mínimas de runtime para OpenCV headless ─────────────────────
# (NO se necesita cmake, build-essential ni dlib — todo es wheel pre-compilado)
RUN apt-get update && apt-get install -y \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# ── Directorio de trabajo ─────────────────────────────────────────────────────
WORKDIR /app

# ── Instalar dependencias Python ──────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --upgrade pip --quiet
RUN pip install -r requirements.txt --quiet

# ── Copiar código fuente ──────────────────────────────────────────────────────
COPY . .

EXPOSE 8000

# Railway asigna $PORT dinámicamente
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
