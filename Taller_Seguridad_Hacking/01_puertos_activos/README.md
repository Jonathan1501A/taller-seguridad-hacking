# Actividad 1: Auditoría de Puertos de Red y Detección de Procesos

## Descripción
Este script en Python permite inspeccionar sockets de red abiertos en el sistema operativo (tanto TCP como UDP), determinando qué puertos locales y remotos se encuentran en uso, su estado de conexión (`LISTEN`, `ESTABLISHED`, `TIME_WAIT`, etc.) y el proceso exacto que los está utilizando (Nombre de proceso, PID y ruta del ejecutable).

En seguridad ofensiva y defensiva (Hacking Ético), este análisis es fundamental para:
- Detectar servicios no autorizados o vulnerables en ejecución.
- Identificar posibles puertas traseras (*backdoors*), troyanos o conexiones de comando y control (*C2*).
- Realizar auditorías de superficie de ataque (*Attack Surface Management*).

---

## Requisitos e Instalación

1. Asegúrate de tener Python 3.8+ instalado.
2. Instala la librería `psutil`:
   ```bash
   pip install -r requirements.txt
   ```

---

## Modos de Uso

### 1. Modo Interactivo (Recomendado)
Ejecuta el script directamente sin argumentos para abrir el menú interactivo con opciones de escaneo, filtros, monitor en tiempo real y exportación:
```bash
python network_ports_monitor.py
```

### 2. Modo Línea de Comandos (CLI)

- **Ver solo puertos en escucha (servidores locales / servicios expuestos):**
  ```bash
  python network_ports_monitor.py --listening
  ```

- **Filtrar por conexiones establecidas (tráfico activo hacia internet):**
  ```bash
  python network_ports_monitor.py -s ESTABLISHED
  ```

- **Buscar un puerto específico (ej. puerto 80 o 443):**
  ```bash
  python network_ports_monitor.py --port 443
  ```

- **Exportar auditoría a archivo JSON o CSV:**
  ```bash
  python network_ports_monitor.py --export json -o auditoria_puertos.json
  python network_ports_monitor.py --export csv -o auditoria_puertos.csv
  ```

---

## Nota de Privilegios
Para ver la información de procesos del sistema pertenecientes a otros usuarios o servicios de Windows/Linux, es recomendable ejecutar la consola de comandos con **permisos de Administrador / root**.
