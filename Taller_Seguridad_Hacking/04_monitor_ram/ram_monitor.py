#!/usr/bin/env python3
"""
Taller de Seguridad en Hacking - Actividad 4
Monitor de Consumo de Memoria RAM por Procesos.

Este programa identifica qué procesos están consumiendo mayor cantidad de memoria RAM
en el sistema, calculando el uso en Megabytes/Gigabytes y el porcentaje relativo
respecto a la memoria física total instalada.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, List, Optional

try:
    import psutil
except ImportError:
    print("[!] Error: El paquete 'psutil' no está instalado.")
    print("    Instálalo ejecutando: pip install psutil")
    sys.exit(1)

# Configuración de salida segura para consolas Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


@dataclass
class ProcessRAMInfo:
    """Estructura para almacenar las métricas de memoria de un proceso."""
    pid: int
    name: str
    rss_mb: float
    vms_mb: float
    memory_percent: float
    cpu_percent: float
    status: str
    username: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RAMMonitor:
    """Clase principal para la recolección y análisis de consumo de memoria RAM."""

    @staticmethod
    def get_system_ram_summary() -> dict[str, Any]:
        """Retorna un resumen global de la memoria física y virtual del sistema."""
        vmem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        return {
            "total_gb": round(vmem.total / (1024 ** 3), 2),
            "used_gb": round(vmem.used / (1024 ** 3), 2),
            "available_gb": round(vmem.available / (1024 ** 3), 2),
            "percent_used": vmem.percent,
            "swap_total_gb": round(swap.total / (1024 ** 3), 2),
            "swap_used_gb": round(swap.used / (1024 ** 3), 2),
            "swap_percent": swap.percent,
        }

    @staticmethod
    def get_top_processes(
        top_n: int = 10,
        filter_name: Optional[str] = None,
    ) -> List[ProcessRAMInfo]:
        """
        Obtiene los N procesos con mayor consumo de memoria RAM física (RSS).

        :param top_n: Cantidad de procesos a retornar.
        :param filter_name: Filtro opcional por nombre o subcadena.
        :return: Lista de objetos ProcessRAMInfo ordenados descendentemente.
        """
        process_list: List[ProcessRAMInfo] = []

        for proc in psutil.process_iter(
            attrs=["pid", "name", "memory_info", "memory_percent", "cpu_percent", "status", "username"]
        ):
            try:
                info = proc.info
                mem_info = info.get("memory_info")
                if not mem_info:
                    continue

                rss_mb = round(mem_info.rss / (1024 ** 2), 2)
                vms_mb = round(mem_info.vms / (1024 ** 2), 2)
                mem_pct = round(info.get("memory_percent") or 0.0, 2)
                name = info.get("name") or "Desconocido"
                pid = info.get("pid") or 0
                status = info.get("status") or "N/A"
                user = info.get("username") or "N/A"
                cpu = round(info.get("cpu_percent") or 0.0, 1)

                if filter_name and filter_name.lower() not in name.lower():
                    continue

                process_list.append(
                    ProcessRAMInfo(
                        pid=pid,
                        name=name,
                        rss_mb=rss_mb,
                        vms_mb=vms_mb,
                        memory_percent=mem_pct,
                        cpu_percent=cpu,
                        status=status,
                        username=user,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        # Ordenar por consumo de memoria física (RSS) descendente
        process_list.sort(key=lambda x: x.rss_mb, reverse=True)
        return process_list[:top_n]


def print_system_summary(summary: dict[str, Any]) -> None:
    """Imprime el estado general de la memoria del sistema."""
    pct = summary["percent_used"]
    bar_len = 30
    filled = int((pct / 100) * bar_len)
    bar = "#" * filled + "-" * (bar_len - filled)

    print("\n" + "=" * 80)
    print("                      ESTADO GENERAL DE LA MEMORIA RAM")
    print("=" * 80)
    print(f"Memoria Total   : {summary['total_gb']} GB")
    print(f"Memoria en Uso  : {summary['used_gb']} GB ({pct}%) [{bar}]")
    print(f"Memoria Libre   : {summary['available_gb']} GB")
    print(f"Memoria Swap    : {summary['swap_used_gb']} GB / {summary['swap_total_gb']} GB ({summary['swap_percent']}%)")
    print("-" * 80)


def print_processes_table(processes: List[ProcessRAMInfo]) -> None:
    """Imprime la tabla de los procesos con mayor consumo."""
    if not processes:
        print("[i] No se encontraron procesos que coincidan con los criterios.")
        return

    headers = [
        ("RANK", 5),
        ("PID", 8),
        ("NOMBRE PROCESO", 28),
        ("RAM (MB)", 12),
        ("% RAM", 8),
        ("VIRT (MB)", 12),
        ("ESTADO", 12),
    ]

    header_line = " | ".join(h.ljust(w) for h, w in headers)
    separator = "-+-".join("-" * w for _, w in headers)

    print(separator)
    print(header_line)
    print(separator)

    for idx, proc in enumerate(processes, 1):
        row = [
            f"#{idx}".ljust(5),
            str(proc.pid).ljust(8),
            proc.name[:28].ljust(28),
            f"{proc.rss_mb:,.2f}".rjust(12),
            f"{proc.memory_percent:.2f}%".rjust(8),
            f"{proc.vms_mb:,.2f}".rjust(12),
            proc.status[:12].ljust(12),
        ]
        print(" | ".join(row))

    print(separator)
    print()


def export_report(processes: List[ProcessRAMInfo], summary: dict[str, Any], file_path: str, fmt: str) -> None:
    """Exporta el reporte a JSON o CSV."""
    if fmt == "json":
        data = {
            "timestamp": datetime.now().isoformat(),
            "system_summary": summary,
            "top_processes": [p.to_dict() for p in processes],
        }
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"[+] Reporte exportado a JSON: {file_path}")

    elif fmt == "csv":
        fieldnames = [
            "pid",
            "name",
            "rss_mb",
            "vms_mb",
            "memory_percent",
            "cpu_percent",
            "status",
            "username",
        ]
        with open(file_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for p in processes:
                writer.writerow(p.to_dict())
        print(f"[+] Reporte exportado a CSV: {file_path}")


def interactive_menu(monitor: RAMMonitor) -> None:
    """Menú interactivo por consola."""
    while True:
        print("\n" + "=" * 60)
        print("      TALLER SEGURIDAD - MONITOR DE CONSUMO DE RAM")
        print("=" * 60)
        print("1. Ver Top 10 procesos con mayor consumo de RAM")
        print("2. Ver Top 25 procesos con mayor consumo de RAM")
        print("3. Filtrar procesos por nombre (ej. chrome, python)")
        print("4. Monitoreo en vivo (refresco automático)")
        print("5. Exportar reporte a JSON")
        print("6. Exportar reporte a CSV")
        print("0. Salir")
        print("=" * 60)

        opc = input("Selecciona una opción [0-6]: ").strip()

        if opc == "1":
            summary = monitor.get_system_ram_summary()
            procs = monitor.get_top_processes(top_n=10)
            print_system_summary(summary)
            print_processes_table(procs)

        elif opc == "2":
            summary = monitor.get_system_ram_summary()
            procs = monitor.get_top_processes(top_n=25)
            print_system_summary(summary)
            print_processes_table(procs)

        elif opc == "3":
            query = input("Ingresa el nombre o parte del proceso a buscar: ").strip()
            if query:
                summary = monitor.get_system_ram_summary()
                procs = monitor.get_top_processes(top_n=50, filter_name=query)
                print_system_summary(summary)
                print_processes_table(procs)

        elif opc == "4":
            interval_str = input("Intervalo de refresco en segundos (Enter para 2s): ").strip()
            interval = int(interval_str) if interval_str.isdigit() and int(interval_str) > 0 else 2
            print(f"\n[i] Iniciando monitor en vivo cada {interval}s. Presiona Ctrl+C para salir.\n")
            try:
                while True:
                    os.system("cls" if os.name == "nt" else "clear")
                    summary = monitor.get_system_ram_summary()
                    procs = monitor.get_top_processes(top_n=15)
                    print(f"[*] Monitor en Tiempo Real - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    print_system_summary(summary)
                    print_processes_table(procs)
                    time.sleep(interval)
            except KeyboardInterrupt:
                print("\n[+] Monitor en tiempo real detenido.")

        elif opc == "5":
            filename = input("Nombre de archivo (ej. reporte_ram.json): ").strip() or f"reporte_ram_{int(time.time())}.json"
            summary = monitor.get_system_ram_summary()
            procs = monitor.get_top_processes(top_n=50)
            export_report(procs, summary, filename, "json")

        elif opc == "6":
            filename = input("Nombre de archivo (ej. reporte_ram.csv): ").strip() or f"reporte_ram_{int(time.time())}.csv"
            summary = monitor.get_system_ram_summary()
            procs = monitor.get_top_processes(top_n=50)
            export_report(procs, summary, filename, "csv")

        elif opc == "0":
            print("\n[+] Saliendo del monitor de RAM. ¡Hasta pronto!\n")
            break
        else:
            print("[!] Opción inválida.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor de consumo de memoria RAM por procesos en el sistema."
    )
    parser.add_argument(
        "-n", "--top",
        type=int,
        default=10,
        help="Número de procesos a mostrar (default: 10)",
    )
    parser.add_argument(
        "-f", "--filter",
        type=str,
        default=None,
        help="Filtrar por nombre de proceso",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Ejecutar en modo monitor en tiempo real",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=2,
        help="Intervalo de actualización en segundos para modo en vivo (default: 2)",
    )
    parser.add_argument(
        "--export",
        choices=["json", "csv"],
        default=None,
        help="Exportar resultados a json o csv",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Nombre de archivo para el reporte exportado",
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Abrir el menú interactivo",
    )

    args = parser.parse_args()
    monitor = RAMMonitor()

    if args.interactive or (len(sys.argv) == 1):
        interactive_menu(monitor)
        return

    if args.live:
        print(f"[i] Iniciando monitor en vivo cada {args.interval}s. Presiona Ctrl+C para salir.")
        try:
            while True:
                os.system("cls" if os.name == "nt" else "clear")
                summary = monitor.get_system_ram_summary()
                procs = monitor.get_top_processes(top_n=args.top, filter_name=args.filter)
                print(f"[*] Monitor en Tiempo Real - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print_system_summary(summary)
                print_processes_table(procs)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[+] Monitor detenido.")
            return

    summary = monitor.get_system_ram_summary()
    procs = monitor.get_top_processes(top_n=args.top, filter_name=args.filter)
    print_system_summary(summary)
    print_processes_table(procs)

    if args.export:
        default_out = f"reporte_ram.{args.export}"
        out_file = args.output or default_out
        export_report(procs, summary, out_file, args.export)


if __name__ == "__main__":
    main()
