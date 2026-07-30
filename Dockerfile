# ── Base: Python 3.12 slim (Debian) ──────────────────────────────────────────
FROM python:3.12-slim

# ── Dependencias del sistema para compilar dlib ───────────────────────────────
# dlib usa C++ y necesita estas herramientas de compilación
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

# ── Instalar dependencias Python ──────────────────────────────────────────────
# Primero cmake y dlib por separado (tardan más — cacheo de capas de Docker)
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install cmake
RUN pip install dlib
RUN pip install -r requirements.txt

# ── Copiar código fuente ──────────────────────────────────────────────────────
COPY . .

# ── Puerto expuesto (Railway asigna $PORT dinámicamente) ─────────────────────
EXPOSE 8000

# ── Comando de inicio ─────────────────────────────────────────────────────────
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
