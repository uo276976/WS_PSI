@echo off
setlocal EnableDelayedExpansion

SET ENV_NAME=WS-PSI-ENV

echo ============================================
echo PSI Suite - Instalador de dependencias (Windows)
echo Entorno virtual: %ENV_NAME%
echo ============================================

:: Verificar si Python está disponible
where python >nul 2>nul
if errorlevel 1 (
    echo Python no está instalado o no está en PATH.
    pause
    exit /b
)

:: Crear el entorno virtual
echo → Creando el entorno virtual...
python -m venv %ENV_NAME%
if errorlevel 1 (
    echo Error al crear el entorno virtual.
    pause
    exit /b
)

:: Activar entorno virtual
echo → Activando entorno virtual...
call %ENV_NAME%\Scripts\activate
if errorlevel 1 (
    echo Error al activar el entorno virtual.
    pause
    exit /b
)

:: Actualizar pip y herramientas necesarias
echo → Actualizando pip, setuptools, wheel...
pip install --upgrade pip setuptools wheel
if errorlevel 1 (
    echo Error actualizando pip/setuptools/wheel.
    pause
    exit /b
)

:: Instalar dependencias desde requirements.txt
echo → Instalando dependencias desde requirements.txt...
pip install -r requirements.txt
if errorlevel 1 (
    echo Error al instalar las dependencias principales.
    pause
    exit /b
)

:: Instalar py-fhe desde carpeta local
echo → Instalando librería local py-fhe...
cd Crypto\py-fhe
pip install .
if errorlevel 1 (
    echo Error al instalar py-fhe.
    pause
    exit /b
)
cd ..\..\

echo ============================================
echo Instalación completada con éxito.
echo Activa el entorno con:
echo     call %ENV_NAME%\Scripts\activate
echo ============================================

pause
