@echo off
setlocal EnableDelayedExpansion

echo ============================================
echo PSI Suite - Instalador de liboqs y liboqs-python (Windows)
echo ============================================

:: 1. Comprobar entorno virtual
if "%VIRTUAL_ENV%"=="" (
    echo [ERROR] No hay entorno virtual activo.
    echo Activa tu entorno virtual antes de continuar:
    echo     call WS-PSI-ENV\Scripts\activate
    pause
    exit /b
)

:: 2. Comprobar herramientas necesarias
where git >nul 2>nul
if errorlevel 1 (
    echo [ERROR] git no está instalado o no está en PATH.
    echo Descárgalo desde: https://git-scm.com/download/win
    pause
    exit /b
)

where cmake >nul 2>nul
if errorlevel 1 (
    echo [ERROR] CMake no está instalado o no está en PATH.
    echo Descárgalo desde: https://cmake.org/download/
    pause
    exit /b
)

where nmake >nul 2>nul
if errorlevel 1 (
    echo [ERROR] nmake no está disponible. 
    echo Asegúrate de ejecutar esto desde la "Developer Command Prompt for VS".
    pause
    exit /b
)

:: 3. Eliminar liboqs-python si hay conflictos
echo → Eliminando versiones previas de liboqs-python...
pip uninstall -y liboqs-python >nul 2>&1

:: 4. Clonar liboqs
if not exist Crypto\liboqs (
    echo → Clonando liboqs...
    git clone --branch 0.12.0 --depth 1 https://github.com/open-quantum-safe/liboqs.git Crypto\liboqs
) else (
    echo → liboqs ya está clonado. Actualizando...
    cd Crypto\liboqs
    git fetch
    git checkout 0.12.0
    git pull
    cd ..\..
)

:: 5. Compilar liboqs
echo → Configurando y compilando liboqs...
cd Crypto\liboqs
if not exist build mkdir build
cd build

cmake -G "NMake Makefiles" .. ^
  -DCMAKE_INSTALL_PREFIX=%USERPROFILE%\oqs ^
  -DBUILD_SHARED_LIBS=ON ^
  -DOQS_ENABLE_KEM_BIKE=ON ^
  -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=ON ^
  -DOQS_ENABLE_KEM_HQC=ON ^
  -DOQS_ENABLE_KEM_KYBER=ON ^
  -DOQS_ENABLE_KEM_NTRU=ON ^
  -DOQS_ENABLE_KEM_NTRUPRIME=ON ^
  -DOQS_ENABLE_KEM_FRODOKEM=ON ^
  -DOQS_ENABLE_SIGS=OFF

if errorlevel 1 (
    echo [ERROR] Error al configurar liboqs con CMake.
    pause
    exit /b
)

nmake install
if errorlevel 1 (
    echo [ERROR] Error durante la compilación o instalación de liboqs.
    pause
    exit /b
)

cd ..\..\..

:: 6. Clonar liboqs-python
if not exist Crypto\liboqs-python (
    echo → Clonando liboqs-python...
    git clone --branch 0.12.0 --depth 1 https://github.com/open-quantum-safe/liboqs-python.git Crypto\liboqs-python
) else (
    echo → liboqs-python ya está clonado. Actualizando...
    cd Crypto\liboqs-python
    git fetch
    git checkout 0.12.0
    git pull
    cd ..\..
)

:: 7. Instalar liboqs-python
echo → Instalando liboqs-python...
cd Crypto\liboqs-python
pip install .
if errorlevel 1 (
    echo [ERROR] Error al instalar liboqs-python.
    pause
    exit /b
)
cd ..\..

:: 8. Configurar PATH
echo ============================================
echo Instalación completada correctamente.
echo Añade esta ruta a tu PATH para que Windows encuentre liboqs:
echo     setx PATH "%%USERPROFILE%%\oqs\lib;%%PATH%%"
echo O bien añádela manualmente desde:
echo     Configuración > Sistema > Información > Configuración avanzada > Variables de entorno
echo ============================================

python -c "import oqs; print('KEMs disponibles:', oqs.get_enabled_kem_mechanisms())"

pause
