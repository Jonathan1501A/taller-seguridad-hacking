# Taller de Seguridad en Hacking

Este repositorio contiene las 4 actividades del taller, desarrolladas en Python siguiendo las mejores prácticas de programación (PEP 8, tipado estático, manejo robusto de excepciones, arquitectura modular, interfaz interactiva y por línea de comandos).

---

## Estructura del Taller

Cada actividad se encuentra contenida en su propia carpeta independiente:

```text
C:\Users\degkp\Documents\Taller_Seguridad_Hacking\
│
├── requirements.txt                          # Dependencias globales
├── README.md                                 # Documentación general
│
├── 01_puertos_activos/                       # ACTIVIDAD 1
│   ├── network_ports_monitor.py             # Escáner y monitor de puertos de red
│   ├── requirements.txt                      # psutil
│   └── README.md
│
├── 02_cifrado_fernet/                        # ACTIVIDAD 2
│   ├── fernet_crypto.py                      # Cifrado/descifrado simétrico (Fernet + PBKDF2)
│   ├── requirements.txt                      # cryptography
│   └── README.md
│
├── 03_validador_contrasenas/                 # ACTIVIDAD 3
│   ├── password_auditor.py                   # Auditor de seguridad y entropía de contraseñas
│   ├── common_passwords.txt                  # Diccionario de contraseñas vulnerables conocidas
│   ├── requirements.txt                      # Módulos estándar
│   └── README.md
│
└── 04_monitor_ram/                           # ACTIVIDAD 4
    ├── ram_monitor.py                        # Monitor de procesos por consumo de RAM
    ├── requirements.txt                      # psutil
    └── README.md
```

---

## Instalación Rápida

Instala todas las dependencias necesarias con un solo comando:
```bash
pip install -r requirements.txt
```

---

## Resumen y Ejecución de Actividades

### 1. Puertos de Internet en Uso y Procesos Asociados
- **Ubicación**: `01_puertos_activos/`
- **Ejecutar**:
  ```bash
  cd 01_puertos_activos
  python network_ports_monitor.py
  ```
- **Descripción**: Mapea los puertos TCP/UDP abiertos y en escucha (`LISTEN`, `ESTABLISHED`), identificando el PID, nombre del proceso y ruta del ejecutable.

### 2. Cifrado y Descifrado con Fernet
- **Ubicación**: `02_cifrado_fernet/`
- **Ejecutar**:
  ```bash
  cd 02_cifrado_fernet
  python fernet_crypto.py
  ```
- **Descripción**: Cifra y descifra mensajes o archivos utilizando Fernet (AES-128-CBC + HMAC-SHA256) y derivación de llaves segura con PBKDF2HMAC (480,000 iteraciones).

### 3. Validador de Seguridad de Contraseñas
- **Ubicación**: `03_validador_contrasenas/`
- **Ejecutar**:
  ```bash
  cd 03_validador_contrasenas
  python password_auditor.py
  ```
- **Descripción**: Evalúa la entropía en bits de una contraseña, analiza patrones secuenciales/repeticiones, valida contra diccionario de contraseñas filtradas y ofrece un generador criptográfico seguro.

### 4. Monitor de Procesos por Consumo de RAM
- **Ubicación**: `04_monitor_ram/`
- **Ejecutar**:
  ```bash
  cd 04_monitor_ram
  python ram_monitor.py
  ```
- **Descripción**: Muestra un resumen del estado de la memoria RAM del sistema y el ranking de procesos que más memoria física y virtual están utilizando, con modo en tiempo real y exportación.
