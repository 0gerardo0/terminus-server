# Terminus 
Un servidor de archivos personal, ligero y seguro con cifrado en reposo lógico, escrito en C y Python.

## Arquitectura del Sistema

![Diagrama de Arquitectura de Terminus](docs/terminus-arq-DAS.svg)

## Características

* **API RESTful:** Endpoints para subir, descargar, listar y borrar archivos.
* **Seguridad:** Cifrado autenticado (ChaCha20-Poly1305 a través de libsodium) para todos los archivos en reposo.
* **Autenticación:** Acceso a la API protegido por Bearer Token. 
* **Alto Rendimiento:** Núcleo de red y criptografía escrito en C para máxima eficiencia.
* **Lógica Flexible:** Toda la lógica de la aplicación reside en Python para un desarrollo y mantenimiento sencillos.

## Prerrequisitos

Para compilar y ejecutar:
* Un compilador de C ('gcc' o 'clang') y 'make'/'cmake'.
* Las bibliotecas de desarrollo de 'libsodium' y 'libmicrohttpd'.
* Python 3.8+ y 'pip'.

**En Arch Linux:**
```bash
sudo pacman -S gcc cmake pkg-config libsodium libmicrohttpd python python-pip
```

 ## Instalación y Compilación 

```bash
git clone <xd aun no tengo el repo>
cd Terminus
```
### Preparar el entorno de Python

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
### Compilación del nucleo de C 
```bash
bash scripts/build.sh 
```

## Configuración 

Antes de ejecutar, debes configuración el servidor y el cliente.

#### Servidor

Crear un archivo con `config.json`

```json
{
  "server_port": 8080,
  "storage_directory": "terminus_storage",
  "api_secret_token": "token_secreto_de_servidor"
}
```
Puedes generar un token seguro con: `python -c 'import secrets; print(secrets.token_urlsafe(32))'` 

#### Cliente

Crear un archivo `client_config.json`  en la raiz del proyecto.

```json
{
  "server_url": "http://127.0.0.1:8080",
  "api_token": "token_secreto_de_servidor"
}
``` 

## Uso 

1. Iniciar el servidor en una terminal:

```bash
python src/python_wrapper/main_server.py
```

2. Usa el cliente en otra terminal:
```bash
#Listar archivos 
python client.py list 

#Subir archivos
python client.py upload /ruta/archivo.txt archivo.txt 

#Descargar un archivo
python client.py download archivo.txt archivo_descargado.txt

#Borrar un archivo
python client.py rm archivo.txt
```

## Referencia de la API

| Método | Endpoint                | Descripción                                                 |
| :----- | :---------------------- | :---------------------------------------------------------- |
| `GET`  | `/files`                | Lista los nombres de los archivos almacenados.                |
| `POST` | `/files/{filename}`     | Sube un archivo. El contenido va en el cuerpo de la petición. |
| `GET`  | `/files/{filename}`     | Descarga el contenido de un archivo.                        |
| `DELETE`| `/files/{filename}`     | Borra un archivo del servidor.                              |
