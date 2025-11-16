# PSI Suite - Python Web Service
Servicio web de Flask que levanata un nodo y expone una API REST y una interfaz gráfica con el objetivo de probar diferentes criptosistemas y protocolos para calcular PSI (Private Set Intersection) o conjuntos de intersecciones privados.

## Requisitos
* **Python 3.11**
* git
* pip

El sistema ha demostrado funcionar en sistemas ARM y x86. Se ha probado su funcionamiento en Windows y en macOS.

## Arrancar el servicio web

Para arrancar el servicio se pueden seguir estos pasos:

1. Clonar el repositorio: `git clone https://github.com/4rius/WS_PSI.git`. También se puede clonar utilizando el soporte gráfico de GitHub Desktop.
2. Navegar a la carpeta del proyecto: `cd WS_PSI`.
3. Instalar las dependencias, por conveniencia se puede utilizar un entorno virtual de Python:
    1. Crear un entorno virtual: `python -m venv WS-PSI-ENV` en Windows o `python3 -m venv WS-PSI-ENV` en Linux. En sistemas UNIX se recomienda comprobar que `python3` es una versión 3.11, esto se puede hacer con `python3 --version`. Si no fuera así, se puede instalar y evitar actualizar variables haciendo `python3.11 -m venv WS-PSI-ENV`.
    2. Activar el entorno virtual: `source WS-PSI-ENV/bin/activate` en Linux o `WS-PSI-ENV\Scripts\activate` en Windows.
    3. Instalar las dependencias: `pip install -r requirements.txt`. Y las dependencias para BFV `py-fhe`: `cd Crypto/py-fhe && pip install .` \
Por conveniencia, existe un archivo `setup.sh` que realiza todos estos pasos (para macOS y Linux). Para ejecutarlo, se debe dar permisos de ejecución: `chmod +x setup.sh` y ejecutarlo: `./setup.sh`. Esto solo funciona con Python 3.11
4. Si no estamos en el entorno virtual (al terminar el script), se debe activar: `source WS-PSI-ENV/bin/activate` en Linux o `WS-PSI-ENV\Scripts\activate` en Windows. Donde `WS-PSI-ENV` es el nombre del entorno virtual.
5. Arrancar el servidor:
   1. Usando el servidor de desarrollo por defecto de Flask: `flask --app flaskr:create_app run`.\
![flaskdefault.png](docs/flaskdefault.png)
   2. Usando un servidor `waitress` (recomendado): `waitress-serve --host 127.0.0.1 --port 8080 --call flaskr:create_app`
      1. Para instalar `waitress`, se puede hacer con el comando: `pip install waitress`.\
![waitressdefault.png](docs/waitressdefault.png) \
Se recomienda usar `waitress` para evaluar las implementaciones, ya que es más rápido y seguro que el servidor de desarrollo de Flask. Simula mejor lo que sería el rendimiento del sistema en producción.

## Activar Criptografía post-cuántica 
Ejecutar el instalador de PQC

Ejecuta el script de instalación:

chmod +x setup_pqc.sh
./setup_pqc.sh


Este script realiza automáticamente los siguientes pasos:

 - Instala dependencias necesarias del sistema.
 - Clona y compila liboqs con soporte para algoritmos post-cuánticos.
 - Instala liboqs-python, la interfaz de Python para liboqs.
 - Configura la variable LD_LIBRARY_PATH (necesaria para que Python encuentre liboqs).
 - Verifica que los algoritmos estén disponibles.

**Servidor por defecto**\
El proyecto utiliza un servidor Flask ejecutado mediante Waitress en cada nodo. Por defecto, cada contenedor expone su API REST en el puerto interno 5000, mientras que el puerto externo asignado depende del nodo definido en el archivo docker-compose.yml. De este modo, por ejemplo, un nodo Workstation puede estar accesible externamente en http://127.0.0.1:5002/api, mientras que un nodo Android puede hacerlo en http://127.0.0.1:5006/api. La interfaz web de cada servicio se encuentra disponible en la misma dirección sin el sufijo /api.

El sistema permite cambiar el puerto interno o externo ajustando las variables definidas en los archivos de composición. Internamente, Flask y Waitress escuchan en el puerto 5000 dentro del contenedor, pero cualquier puerto puede ser redirigido al exterior mediante la sección ports: del docker-compose. Esto permite, por ejemplo, ejecutar múltiples nodos en paralelo en la misma máquina sin que haya conflictos de puertos. El comportamiento de escucha sobre la IP local está preparado para facilitar que otros dispositivos de la misma red puedan conectarse al nodo, aunque en su configuración actual no está pensado para exposición directa a Internet.

Para entornos donde se añadan más nodos, simplemente deben asignarse puertos adicionales en la forma 50XX:5000, y realizarse el correspondiente port forwarding local. Por ejemplo, si se añaden nuevos nodos, será suficiente con mapear los rangos 5000–5010 (o el rango que corresponda con la cantidad de nodos definidos) hacia localhost:50XX. Este mecanismo asegura que cada nodo quede accesible a través de su propio puerto externo sin interferir con el resto del sistema.

Si deseas modificar manualmente la dirección y el puerto, es posible arrancar los servicios Flask o Waitress directamente especificando los parámetros correspondientes. Por ejemplo, Flask puede iniciarse con flask run --port 8000 y Waitress con waitress-serve --host 127.0.0.1 --port 8000 --call flaskr:create_app. Estas variantes son útiles para pruebas locales fuera del entorno Docker.

## Autenticación mediante archivo de credenciales

Para poder mandar registros a la Realtime Database es necesario un archivo de credenciales.\
Para obtenerlo, se debe seguir los siguientes pasos:
1. Acceder a la consola de Firebase: [Firebase Console](https://console.firebase.google.com/).
2. Crear un nuevo proyecto o seleccionar uno existente.
3. Ir a la sección de configuración del proyecto.
4. Descargar el archivo de credenciales en formato JSON desde la sección de *Cuentas de servicio*.\
![serviceaccFB.png](docs/serviceaccFB.png)\
5. Guardar el archivo en la carpeta raíz con el nombre `firebase-credentials.json`. *Este archivo proporciona acceso de administrador al proyecto.* **No se debe subir a ningún repositorio público**. Se debe añadir al `.gitignore` para evitar subirlo por error. \
![authlocation.png](docs/authlocation.png)
6. Actualizar el valor del parámetro `FB_URL` en el archivo `Network/collections/DbConstants.py` con la URL de la Realtime Database.\
![FB_URL.png](docs/FB_URL.png)
7. Volver a arrancar el servidor. En vez de indicar que no se ha encontrado el archivo de credenciales, se mostrará un mensaje de que se ha conectado a la base de datos correctamente y se enviará el primer log con la configuración del dispositivo.\
![authFB.png](docs/authFB.png)
8. Si la Realtime Database está configurada correctamente, se enviarán registros sin problema. Solo es necesario activarla para que funcione.

## API REST

Se incluye en este repositorio una colección de Postman con las peticiones a la API REST.\
Para importarla, se debe seguir los siguientes pasos:
1. Descargar el archivo `PSI Suite.postman_collection.json` desde la carpeta `docs`.
2. Abrir Postman.
3. Ir a la sección de colecciones.
4. Importar la colección descargada.
5. Seleccionar el archivo descargado.
6. La colección se importará correctamente.\
![PostmanAPI.png](docs/PostmanAPI.png)

En el apartado de `Variables` se pueden modificar las variables de entorno para que se ajusten a la configuración del servidor. Por defecto traen la URL y el puerto del servidor de desarrollo de Flask, así como un dispositivo para probar las peticiones. \
Cada petición tiene una descripción detallada de lo que hace y qué espera recibir para funcionar correctamente. \
![PostmanDocs.png](docs/PostmanDocs.png)

## Despliegue Docker
El proyecto incluye toda la infraestructura necesaria para construir una imagen Docker y desplegar distintos nodos simulados que representan varios tipos de dispositivos (Workstation, Android e IoT). El sistema también dispone de un modo adicional denominado UNIQUE, en el que todo el procesamiento se realiza dentro de un único contenedor con el fin de obtener mediciones óptimas sin latencias ni restricciones artificiales.
Para construir la imagen es necesario disponer del demonio de Docker en ejecución. Desde la raíz del repositorio puede generarse la imagen del sistema mediante el comando docker build -t ws-psi .. El Dockerfile se encarga de compilar liboqs, instalar liboqs-python y configurar las dependencias criptográficas y de sistema necesarias, además de incluir el servidor Waitress que ejecuta la API de cada nodo.
Una vez creada la imagen, el sistema puede desplegarse mediante el archivo docker-compose.yml, que levanta seis contenedores independientes bajo una misma red interna de Docker. Cada uno de ellos simula un entorno distinto asignando diferentes restricciones de CPU y memoria: dos nodos equivalentes a estaciones de trabajo, dos nodos de tipo IoT con recursos muy limitados y dos nodos que simulan dispositivos Android. Al ejecutarse todos dentro de la misma red virtual, se comportan como si estuvieran conectados en una red de área local, pudiendo intercambiar mensajes y ejecutar los protocolos sin configuración adicional. Para iniciar el despliegue basta con ejecutar docker compose up en el mismo directorio del archivo.
El proyecto ofrece además un modo de ejecución alternativo a través del archivo docker-compose.unique.yml. En este caso se crea un único contenedor que reúne todas las funcionalidades y realiza todo el procesamiento de manera centralizada. Este modo sirve para obtener mediciones de referencia sin las limitaciones derivadas de la simulación de dispositivos con recursos restringidos, y sin el coste adicional introducido por la comunicación entre nodos independientes. Puede iniciarse mediante docker compose -f docker-compose.unique.yml up.
En cualquier momento es posible detener la ejecución mediante docker compose down. Si se desea eliminar los contenedores para liberar recursos, puede utilizarse el comando docker rm $(docker ps -aq), teniendo en cuenta que este eliminará todos los contenedores existentes en la máquina, no únicamente los asociados al proyecto.
Todos los servicios se ejecutan mediante Waitress, que se inicia automáticamente a través del script dockerstart.sh incluido en cada contenedor. El servidor Flask asociado a cada nodo se expone siempre en el puerto interno 5000, mientras que el puerto externo asignado depende del nodo que se esté ejecutando.

## Licencia
Este proyecto está distribuido bajo la licencia MIT. Para más información, consultar el archivo [LICENSE](LICENSE).
