# 🛡️ Taller de Seguridad y Ciberseguridad

Este repositorio reúne las herramientas, scripts y módulos desarrollados para la auditoría de redes, análisis de seguridad, monitoreo de procesos y pruebas de conceptos criptográficos.

---

## 🚀 Módulos e Implementaciones

### 1. 🔌 Monitor de Puertos y Procesos (`01_puertos_activos`)
Herramienta de auditoría para escanear y monitorear sockets de red activos (TCP/UDP) en tiempo real, asociando cada conexión con su PID y nombre de proceso en ejecución.
* **Características:**
  * Filtrado avanzado por protocolo, puerto o estado (`LISTEN`, `ESTABLISHED`).
  * Monitoreo en vivo interactivo en consola.
  * Exportación de reportes estructurados a **JSON** y **CSV**.

---

## 🛠️ Tecnologías y Librerías

* **Lenguaje:** Python 3.x
* **Librerías Principales:** `psutil`, `socket`, `json`, `csv`
* **Entorno de Trabajo:** Windows Subsystem for Linux (WSL) / Windows PowerShell

---

## 📋 Requisitos e Instalación

1. **Clonar el repositorio:**
   ```bash
   git clone [https://github.com/Jonathan1501A/taller-seguridad-hacking.git](https://github.com/Jonathan1501A/taller-seguridad-hacking.git)
   cd taller-seguridad-hacking
