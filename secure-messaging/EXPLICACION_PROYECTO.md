# Proyecto: Mensajería Segura de Extremo a Extremo (E2EE)

Este documento proporciona una explicación detallada del funcionamiento técnico del proyecto de mensajería segura, desglosando cada uno de sus componentes para facilitar su presentación.

---

## 1. Visión General
El objetivo del proyecto es permitir que dos usuarios se comuniquen de forma privada a través de un servidor central, garantizando que **ni siquiera el servidor pueda leer el contenido de los mensajes**. 

### Tecnologías Clave:
- **FastAPI/WebSockets**: Para la comunicación en tiempo real.
- **Criptografía de Curva Elíptica (ECC)**: Específicamente la curva **secp384r1** (P-384), recomendada por el NIST para datos de alta seguridad.
- **AES-256-GCM**: Para el cifrado simétrico de los mensajes, proporcionando confidencialidad e integridad.
- **ECIES (Elliptic Curve Integrated Encryption Scheme)**: El esquema híbrido que combina ECC y AES.

---

## 2. Desglose de Componentes

### 📂 `server/server.py` (El Intermediario Ciego)
El servidor actúa únicamente como un **relevador (relay)** de mensajes. Sus funciones son:
- **Registro de Llaves**: Almacena las llaves públicas de los usuarios asociadas a su nombre de usuario.
- **Distribución de Llaves**: Permite que cualquier usuario consulte la llave pública de otro para poder enviarle un mensaje cifrado.
- **Relay WebSocket**: Mantiene conexiones activas y reenvía los paquetes cifrados al destinatario correcto.
- **Transparencia**: El servidor recibe un JSON con "metadatos" (quién envía a quién) y un "payload" cifrado que no puede descifrar.

### 📂 `client/keygen.py` (Gestión de Identidad)
Encargado de la creación de las credenciales criptográficas locales:
- **Generación de Pares**: Crea una llave privada (secreta) y una pública.
- **Protección**: La llave privada se guarda en disco cifrada con una contraseña (usando PBKDF2 + AES), lo que significa que aunque alguien robe el archivo `.pem`, no podrá usarlo sin la contraseña.
- **Fingerprints**: Genera un identificador único (huella digital) de la llave pública para que los usuarios puedan verificar su identidad fuera de línea.

### 📂 `client/crypto.py` (El Corazón de la Seguridad)
Contiene la lógica matemática para el cifrado híbrido:
1. **Derivación de Claves (HKDF)**: Utiliza un secreto compartido para generar claves AES de 256 bits seguras.
2. **Cifrado ECIES**: 
   - Genera una llave efímera (temporal) para cada mensaje.
   - Realiza un intercambio Diffie-Hellman (ECDH) con la llave del destinatario.
   - Cifra el contenido con AES-GCM.
3. **PFS (Perfect Forward Secrecy)**: Gracias al uso de llaves efímeras por mensaje, si la llave privada de un usuario se ve comprometida en el futuro, los mensajes antiguos interceptados no podrán ser descifrados.

### 📂 `client/client.py` (Interfaz de Usuario)
Es la aplicación CLI (consola) que el usuario utiliza:
- Gestiona el inicio de sesión y la carga de llaves.
- Implementa un bucle asíncrono para recibir mensajes en tiempo real y, al mismo tiempo, permitir que el usuario escriba comandos como `/msg` o `/users`.

---

## 3. Flujo de un Mensaje (Paso a Paso)

1. **Registro**: Alice genera sus llaves y envía su **llave pública** al servidor.
2. **Preparación**: Alice quiere mensajear a Bob. Pide al servidor la llave pública de Bob.
3. **Cifrado (Lado de Alice)**:
   - Alice genera una llave temporal.
   - Calcula un secreto común usando su llave temporal y la llave de Bob.
   - Cifra el texto "Hola" usando ese secreto.
   - Envía el paquete cifrado al servidor dirigido a "Bob".
4. **Relay**: El servidor recibe el paquete y, sin poder leerlo, se lo pasa a Bob.
5. **Descifrado (Lado de Bob)**:
   - Bob usa su **llave privada** y la llave temporal de Alice (que viene en el paquete) para reconstruir el mismo secreto común.
   - Descifra el mensaje y lee "Hola".

---

## 4. Análisis de Seguridad y "Hallazgos" (Reporte de Errores/Mejoras)

Durante el análisis, se han identificado los siguientes puntos que podrías mencionar en la presentación:

### ⚡ Errores y Limitaciones Detectadas:
1. **Almacenamiento Volátil (Memoria)**: El servidor guarda los usuarios y conexiones en diccionarios de Python (`public_key_registry`). Si el servidor se reinicia, todos los datos se pierden. **Mejora**: Usar una base de datos persistente (SQLite/PostgreSQL).
2. **Confianza en el Remitente (Autenticidad)**: Aunque el sistema usa AAD (Additional Authenticated Data) para vincular el nombre del remitente al paquete cifrado, no hay una **firma digital** que demuestre que Alice realmente escribió el mensaje. Un servidor malicioso podría o bien inventar mensajes o reordenarlos si no se tiene cuidado.
3. **Dependencia de Entorno (`setup.sh`)**: El script de configuración está configurado para una ruta muy específica de Python 3.11 en macOS (`/opt/homebrew/bin/python3.11`). En otros sistemas, esto fallará.

### ✅ Fortalezas:
- **ECC P-384**: Uso de estándares criptográficos militares/gubernamentales.
- **Integridad AES-GCM**: El sistema detecta inmediatamente si alguien intenta alterar un solo bit del mensaje cifrado.
- **Protección de Llaves**: El uso de `BestAvailableEncryption` con contraseña para la clave privada local es una excelente práctica.

---

## 5. Conclusión para la Presentación
Este proyecto demuestra cómo la criptografía moderna puede eliminar la necesidad de confiar en el proveedor del servicio (el servidor). El servidor es simplemente un cartero que entrega sobres sellados con herramientas que no posee.
