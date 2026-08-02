# ── Base: Python 3.12 slim (Debian) ──────────────────────────────────────────
FROM python:3.12-slim

# ── Dependencias del sistema para compilar dlib ───────────────────────────────
RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    libopenblas-dev \
    liblapack-dev \
    libx11-dev \
    libgtk2.0-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Directorio de trabajo ─────────────────────────────────────────────────────
WORKDIR /app

# ── Instalar dependencias Python (en capas separadas para cache) ──────────────
COPY requirements.txt .
RUN pip install --upgrade pip --quiet
RUN pip install cmake --quiet
RUN pip install dlib --quiet
RUN pip install -r requirements.txt --quiet

# ── Copiar código fuente ──────────────────────────────────────────────────────
COPY . .

# ── Puerto por defecto ────────────────────────────────────────────────────────
EXPOSE 8000

# ── Inicio: Railway asigna $PORT dinámicamente ────────────────────────────────
# Usamos sh -c para que $PORT se expanda correctamente
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
