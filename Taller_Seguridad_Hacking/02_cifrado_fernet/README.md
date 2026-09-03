# Actividad 2: Cifrado y Descifrado Simétrico con Fernet

## Descripción
Este programa implementa un esquema de criptografía simétrica robusto utilizando el estándar **Fernet** de la librería `cryptography`. 

### ¿Cómo funciona Fernet?
Fernet garantiza confidencialidad e integridad utilizando:
- **AES-128 en modo CBC** para cifrado de datos.
- **HMAC con SHA-256** para autenticación e integridad del mensaje (evita ataques de modificación o manipulación en tránsito).
- **PKCS7 padding** y marcas de tiempo (*timestamps*).

Además, este programa incluye una función de derivación de claves mediante **PBKDF2HMAC** (Password-Based Key Derivation Function 2) con algoritmo SHA-256, 480.000 iteraciones y una sal criptográfica (*salt*) de 128 bits generada con `os.urandom`. Esto permite al usuario utilizar cualquier clave o contraseña legible de forma segura.

---

## Requisitos e Instalación

1. Instala la librería `cryptography`:
   ```bash
   pip install -r requirements.txt
   ```

---

## Modos de Uso

### 1. Menú Interactivo
Ejecuta el script sin parámetros para acceder a un menú completo:
```bash
python fernet_crypto.py
```
Opciones disponibles:
- Cifrar / Descifrar texto usando una contraseña o frase secreta.
- Generar llaves Fernet url-safe de 32 bytes y guardarlas en archivos `.key`.
- Cifrar y descifrar archivos de cualquier tipo (.txt, .pdf, .docx, .zip, etc.).

### 2. Uso mediante Línea de Comandos (CLI)

- **Generar una nueva clave Fernet aleatoria:**
  ```bash
  python fernet_crypto.py generate-key
  ```

- **Cifrar texto con contraseña:**
  ```bash
  python fernet_crypto.py encrypt -t "Mensaje secreto de prueba" -p "MiPasswordSuperSeguro123!"
  ```

- **Descifrar texto con contraseña:**
  ```bash
  python fernet_crypto.py decrypt -c "<TOKEN_CIFRADO>" -p "MiPasswordSuperSeguro123!"
  ```

- **Cifrar y descifrar con clave Fernet directa:**
  ```bash
  python fernet_crypto.py encrypt -t "Datos sensibles" -k "X1J...clave_base64...="
  python fernet_crypto.py decrypt -c "<TOKEN_CIFRADO>" -k "X1J...clave_base64...="
  ```
