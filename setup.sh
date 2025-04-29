#!/bin/bash

set -e  # Exit on error
ENV_NAME="WS-PSI-ENV"

echo "### PSI Suite - Instalador de dependencias ###"
echo "→ Verificando entorno"
command -v python3.11 >/dev/null 2>&1 || { echo >&2 "❌ Python 3.11 no está instalado. Aborta."; exit 1; }

PYTHON_VERSION=$(python3.11 --version)
echo "→ Python version: $PYTHON_VERSION"
echo "→ Nombre del entorno virtual: $ENV_NAME"

# Crear entorno virtual
echo "→ Creando entorno virtual..."
python3.11 -m venv $ENV_NAME

# Activar entorno virtual
echo "→ Activando entorno virtual..."
source $ENV_NAME/bin/activate

# Confirmar entorno activado
echo "→ Entorno activado. Python usado: $(which python)"

# Actualizar pip y herramientas necesarias
echo "→ Actualizando pip, setuptools, wheel..."
pip install --no-cache-dir --upgrade pip setuptools wheel

# Instalar requirements principales
echo "→ Instalando dependencias desde requirements.txt..."
pip install --no-cache-dir -r requirements.txt

# Instalar py-fhe
echo "→ Instalando librería local: py-fhe..."
cd Crypto/py-fhe
pip install .

cd ../../  # Volver a la raíz del proyecto
echo "Instalación completada con éxito"
echo "Entorno virtual creado y dependencias instaladas en '$ENV_NAME'"
echo "Para activarlo más adelante: source $ENV_NAME/bin/activate"
