#!/bin/bash
# setup.sh — Instala todas las dependencias del backend MFA
# Ejecutar: bash setup.sh

set -e  # Salir si cualquier comando falla

echo "════════════════════════════════════════════════════════"
echo "  SecureApp MFA — Configuración del Backend Python"
echo "════════════════════════════════════════════════════════"

# Verificar Python 3.10+
python3 --version

# Instalar dependencias del sistema para face_recognition (dlib)
echo ""
echo "📦 Instalando dependencias del sistema para dlib/face_recognition..."
sudo apt-get update -qq
sudo apt-get install -y cmake build-essential libopenblas-dev liblapack-dev \
    libx11-dev libgtk-3-dev python3-dev python3-pip python3-venv

# Crear entorno virtual
echo ""
echo "🐍 Creando entorno virtual Python..."
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias Python
echo ""
echo "📦 Instalando dependencias Python (esto puede tomar varios minutos por dlib)..."
pip install --upgrade pip
pip install cmake  # cmake Python wrapper primero
pip install dlib   # dlib antes que face_recognition
pip install -r requirements.txt

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅ Instalación completada."
echo ""
echo "  Para iniciar el servidor:"
echo "  source venv/bin/activate"
echo "  python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
echo ""
echo "  La IP de tu computadora (para configurar la app Expo):"
hostname -I | awk '{print $1}'
echo "════════════════════════════════════════════════════════"
