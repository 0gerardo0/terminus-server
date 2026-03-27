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

## Despliegue con Docker (Recomendado)
La forma más sencilla y recomendada de ejecutar el servidor Terminus es usando Docker y Docker Compose. Esto gestionará automáticamente la compilación, las dependencias y el entorno de ejecución.

1. Contruye e inicia el servidor:
```bash
    docker-compose up --build
```
Esto compilará la imagen de Docker la primera vez y la iniciará. El servidor se ejecutará en primer plano, mostrando los logs en tiempo real.

2. Para iniciar en segundo plano:
```bash
docker-compose up --build -d
```
3. Para detener el servidor:
* Si lo iniciaste en primer plano, detener con `Ctrl+C`.
* Si lo iniciaste en segundo plano, ejecutar:
```bash
docker-compose down
```
## Instalación y Compilación (Manual)

```bash 
git clone git@github.com:0gerardo0/terminus-server.git
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

1. Iniciar el servidor (ya sea con `docker-compose up` o `python src/python_wrapper/main_server.py`):

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
| `GET`  | `/status`                | Verifica el estado y la versión del servidor.             |
| `GET`  | `/files`                | Lista los nombres de los archivos almacenados.                |
| `POST` | `/files/{filename}`     | Sube un archivo. El contenido va en el cuerpo de la petición. |
| `GET`  | `/files/{filename}`     | Descarga el contenido de un archivo.                        |
| `DELETE`| `/files/{filename}`     | Borra un archivo del servidor.                              |
| `GET` |   `/files/{filename}/info` | Obtine los metadatos de un archivo. (tamaño, fecha).     |

---

## 🚀 Roadmap: De servidor de archivos a servicio competitivo

Este roadmap documenta las mejoras necesarias para que Terminus sea comparable con servicios comerciales como Bitwarden, Google Drive, o Nextcloud.

### Estado actual

Terminus actualmente ofrece:
- ✅ Cifrado ChaCha20-Poly1305
- ✅ API REST básica
- ✅ Autenticación con Bearer Token
- ✅ Almacenamiento seguro de archivos
- ✅ Ligero y portable

---

### 📊 Comparativa: Terminus vs Servicios Comerciales

| Característica | Terminus | Bitwarden | Google Drive | Nextcloud |
|----------------|:--------:|:----------:|:------------:|:----------:|
| Cifrado archivos | ✅ | ✅ | ✅ | ✅ |
| API REST | ✅ | ✅ | ✅ | ✅ |
| **Multi-usuario** | ❌ | ✅ | ✅ | ✅ |
| **Web UI** | ❌ | ✅ | ✅ | ✅ |
| **Apps móviles** | ❌ | ✅ | ✅ | ✅ |
| **Extensiones navegador** | ❌ | ✅ | ❌ | ❌ |
| **Sincronización entre dispositivos** | ❌ | ✅ | ✅ | ✅ |
| **2FA** | ❌ | ✅ | ✅ | ❌ |
| **Carpeta compartida** | ❌ | ❌ | ✅ | ✅ |
| **Versiones de archivos** | ❌ | ❌ | ✅ | ✅ |
| **Collab en tiempo real** | ❌ | ❌ | ✅ | ❌ |
| **Recuperación de cuenta** | ❌ | ✅ | ✅ | ✅ |
| **Soporte 24/7** | ❌ | ✅ | ✅ | ✅ |
| **Auditorías seguridad** | ❌ | ✅ | ✅ | ✅ |
| **Redundancia datos** | ❌ | ✅ | ✅ | ✅ |
| **CDN global** | ❌ | ❌ | ✅ | ❌ |

---

### 🎯 Características a implementar (Prioridad)

#### P0 - Crítico (Esenciales para uso básico)

- [ ] **Multi-usuario con permisos**
  - Sistema de usuarios en la base de datos
  - Tokens por usuario
  - Permisos de lectura/escritura/Admin
  - Implementación: Añadir tabla `users` y `permissions` en SQLite

- [ ] **Interfaz Web (Web UI)**
  - Dashboard para subir/descargar archivos
  - Vista de archivos con miniaturas
  - Autenticación web (login/logout)
  - Implementación: Flask/FastAPI + HTML/CSS/JS

- [ ] **Base de datos de usuarios**
  - SQLite para simplicidad (o PostgreSQL para escala)
  - Hash de contraseñas (Argon2 o bcrypt)
  - Sesiones de usuario

#### P1 - Importante (Para competir con servicios básicos)

- [ ] **Aplicación móvil**
  - Android (Kotlin/Java)
  - iOS (Swift) - opcional por costo Mac
  - Sync automático de archivos
  - Subir desde cámara

- [ ] **Extensión de navegador**
  - Guardar contraseñas (opcional)
  - Acceso rápido a archivos
  - Subir archivos desde el navegador

- [ ] **Sistema de compartición**
  - Links públicos con contraseña
  - Fecha de expiración
  - Límite de descargas

- [ ] **Notificaciones**
  - Email al subir/descargar archivos
  - Alertas de seguridad
  - Respaldo completado

#### P2 - Avanzado (Para servicios empresariales)

- [ ] **Versiones de archivos**
  - Guardar historial de cambios
  - Restaurar versión anterior
  - Límite de versiones por archivo

- [ ] **Colaboración en tiempo real**
  - Editores de documento integrados
  - Comentarios en archivos
  - Sistema de tareas

- [ ] **2FA (Autenticación de dos factores)**
  - TOTP (Google Authenticator)
  - Códigos de respaldo
  - WebAuthn/FIDO2 (llaves físicas)

- [ ] **Auditoría de seguridad**
  - Log de todas las acciones
  - Detección de anomalías
  - Reportes de actividad

- [ ] **Backup automático**
  - Redundancia entre servidores
  - Sincronización entre instancias
  - Disaster recovery

#### P3 - Opcional (Diferenciadores)

- [ ] **Integración con Nextcloud/S3**
  - Usar Terminus como frontend
  - Almacenar en S3/Backblaze B2

- [ ] **API GraphQL**
  - Mejor para apps móviles
  - Consultas más eficientes

- [ ] **WebDAV**
  - Montar como unidad de red
  - Compatibilidad con exploradores de archivos

- [ ] **Docker Compose con reverse proxy**
  - Nginx/Caddy integrado
  - SSL automático con Let's Encrypt

---

### 💰 Análisis de costos: Self-hosted vs Comercial

#### Servicios comerciales

| Servicio | Costo/año | Incluye |
|----------|-----------|---------|
| Bitwarden Premium | $20 USD ($360 MXN) | 5GB, 2FA, reportes |
| Google Drive (100GB) | $25 USD ($450 MXN) | Suite completa de Google |
| AWS S3 (1TB) | $276 USD ($5,000 MXN) | Almacenamiento, no más |
| Nextcloud Hub | $96 USD ($1,700 MXN)/año | Todo en uno |

#### Self-hosted (Terminus)

| Componente | Costo inicial | Costo anual |
|------------|--------------|-------------|
| Raspberry Pi 4 (4GB) | $1,500 MXN | - |
| Disco SSD 1TB | $800 MXN | - |
| Electricidad (~10W 24/7) | - | $800 MXN |
| Internet (50Mbps simétrico) | - | $4,800 MXN |
| Tiempo mantenimiento (5 hrs/mes) | - | $6,000 MXN |
| **Total primer año** | **$2,300 MXN** | **$11,600 MXN** |
| **Total años siguientes** | - | **$11,600 MXN** |

#### Conclusiones

| Escenario | Mejor opción |
|-----------|-------------|
| 1 usuario, poco almacenamiento | Self-hosted (Terminus) ✅ |
| 1 usuario, mucho almacenamiento | S3 o Google Drive |
| Múltiples usuarios, colaboración | Nextcloud o Google Drive |
| Necesitas soporte 24/7 | Servicios comerciales |
| Quieres control total | Self-hosted (Terminus) ✅ |

**El break-even point** está aproximadamente en 3-4 años comparado con servicios premium como Bitwarden.

---

### 📋 Plan de implementación sugerido

#### Fase 1: Servidor básico multi-usuario (1-2 meses)
1. Sistema de autenticación con usuarios
2. Web UI básica
3. Gestión de permisos
4. Docker Compose para despliegue fácil

#### Fase 2: Ecosistema (3-6 meses)
1. App móvil Android básica
2. Sistema de compartición
3. Notificaciones por email
4. Dashboard de uso

#### Fase 3: Enterprise features (6-12 meses)
1. 2FA
2. Versiones de archivos
3. Auditoría
4. API GraphQL

---

### 🤝 Contribuir

Este es un proyecto personal creado para aprender. Pull requests son bienvenidos.

Para sugerencia de features, abre un issue.

---

### 📜 Licencia

MIT License - Libre para usar, modificar y distribuir.
