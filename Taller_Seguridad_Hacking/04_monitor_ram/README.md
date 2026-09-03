# Actividad 4: Monitor de Consumo de Memoria RAM por Procesos

## Descripción
Este script en Python analiza el uso de memoria física (RAM) y memoria de intercambio (Swap/Virtual) en el sistema operativo, permitiendo ordenar e identificar qué procesos y servicios consumen la mayor cantidad de recursos.

### Importancia en Seguridad y Administración
- **Detección de Fugas de Memoria (*Memory Leaks*) y DoS**: Identifica procesos anómalos que intenten agotar los recursos de la máquina.
- **Detección de Minería Ilegal de Criptomonedas (*Cryptojacking*) o Malware**: Programas maliciosos suelen registrar un consumo atípico y desmedido de memoria RAM y CPU en segundo plano.
- **Análisis Forense y de Rendimiento**: Determina la carga del sistema en escenarios de auditoría.

---

## Requisitos e Instalación

1. Instala la librería `psutil`:
   ```bash
   pip install -r requirements.txt
   ```

---

## Modos de Uso

### 1. Menú Interactivo (Recomendado)
Ejecuta el script directamente sin argumentos:
```bash
python ram_monitor.py
```
Opciones:
- Ver Top 10 o Top 25 procesos con mayor consumo.
- Filtrar procesos por nombre (ej. `chrome`, `antigravity`, `python`).
- Monitor interactivo en tiempo real con refresco configurable.
- Exportar auditoría a JSON y CSV.

### 2. Línea de Comandos (CLI)

- **Ver el Top 10 procesos con mayor RAM:**
  ```bash
  python ram_monitor.py --top 10
  ```

- **Filtrar por procesos específicos (ej. python):**
  ```bash
  python ram_monitor.py --top 15 --filter python
  ```

- **Monitoreo en tiempo real (refresco cada 3 segundos):**
  ```bash
  python ram_monitor.py --live --interval 3
  ```

- **Exportar reporte a JSON o CSV:**
  ```bash
  python ram_monitor.py --top 20 --export json -o reporte_ram.json
  python ram_monitor.py --top 20 --export csv -o reporte_ram.csv
  ```
