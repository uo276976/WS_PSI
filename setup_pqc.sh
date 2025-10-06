#!/bin/bash
set -e

echo "============================================"
echo "PSI Suite - Instalador de liboqs y liboqs-python"
echo "============================================"

# 1. Verificar entorno virtual
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "No hay entorno virtual activo. Actívalo antes de ejecutar este script."
    echo "Ejemplo:"
    echo "    source WS-PSI-ENV/bin/activate"
    exit 1
fi

echo "→ Entorno virtual detectado: $VIRTUAL_ENV"

# 2. Instalar dependencias necesarias
echo "→ Instalando dependencias del sistema..."
sudo apt-get update && sudo apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git libssl-dev libgmp-dev

# 3. Eliminar instalaciones antiguas conflictivas
echo "→ Eliminando instalaciones previas de liboqs-python (si existen)..."
pip uninstall -y liboqs-python || true

# 4. Clonar liboqs
if [ ! -d "Crypto/liboqs" ]; then
    echo "→ Clonando liboqs..."
    git clone --branch 0.12.0 --depth 1 https://github.com/open-quantum-safe/liboqs.git Crypto/liboqs
else
    echo "→ liboqs ya está clonado, actualizando..."
    cd Crypto/liboqs && git fetch && git checkout 0.12.0 && git pull && cd ../../
fi

# 5. Compilar e instalar liboqs
echo "→ Compilando liboqs..."
cd Crypto/liboqs
mkdir -p build && cd build

cmake -GNinja .. \
  -DCMAKE_INSTALL_PREFIX=$HOME/.local/oqs \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_ENABLE_KEM_BIKE=ON \
  -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=ON \
  -DOQS_ENABLE_KEM_HQC=ON \
  -DOQS_ENABLE_KEM_KYBER=ON \
  -DOQS_ENABLE_KEM_NTRU=ON \
  -DOQS_ENABLE_KEM_NTRUPRIME=ON \
  -DOQS_ENABLE_KEM_FRODOKEM=ON \
  -DOQS_ENABLE_SIGS=OFF

ninja install
cd ../../..

# 6. Configurar LD_LIBRARY_PATH
echo "→ Exportando LD_LIBRARY_PATH temporalmente..."
export LD_LIBRARY_PATH=$HOME/.local/oqs/lib:$LD_LIBRARY_PATH
echo "   Añade esta línea a tu ~/.bashrc para que sea permanente:"
echo "   export LD_LIBRARY_PATH=\$HOME/.local/oqs/lib:\$LD_LIBRARY_PATH"

# 7. Clonar e instalar liboqs-python
if [ ! -d "Crypto/liboqs-python" ]; then
    echo "→ Clonando liboqs-python..."
    git clone --branch 0.12.0 --depth 1 https://github.com/open-quantum-safe/liboqs-python.git Crypto/liboqs-python
else
    echo "→ liboqs-python ya está clonado, actualizando..."
    cd Crypto/liboqs-python && git fetch && git checkout 0.12.0 && git pull && cd ../..
fi

echo "→ Instalando liboqs-python..."
cd Crypto/liboqs-python
pip install .
cd ../..

# 8. Verificación
echo "→ Verificando instalación..."
python -c "import oqs; print('Versión liboqs-python:', oqs.__version__); print('KEMs disponibles:', oqs.get_enabled_kem_mechanisms())"

echo "============================================"
echo "Instalación completada con éxito."
echo "   Si ves una lista de algoritmos arriba, la integración PQC está lista."
echo "============================================"
