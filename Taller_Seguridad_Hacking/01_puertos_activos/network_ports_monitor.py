#!/usr/bin/env python3
"""
Auditoría y Monitoreo de Puertos de Red y Procesos.
"""

import csv
import json
import os
import sys
import time
from datetime import datetime

try:
    import psutil
except ImportError:
    print("[!] Ejecuta: pip install psutil")
    sys.exit(1)


def get_connections(proto="all", status=None, port=None):
    """Escanea y filtra las conexiones de red activas."""
    kind = {"tcp": "tcp", "udp": "udp"}.get(proto.lower(), "inet")
    try:
        raw = psutil.net_connections(kind=kind)
    except psutil.AccessDenied:
        print("[!] Ejecuta como administrador para ver todos los procesos.")
        raw = []

    conns = []
    for c in raw:
        l_ip, l_port = (c.laddr.ip, c.laddr.port) if c.laddr else ("*", 0)
        r_ip, r_port = (c.raddr.ip, c.raddr.port) if c.raddr else ("*", "*")
        st = c.status or ("EN_USO" if c.type == 2 else "N/A")

        # Filtros
        if status and st.upper() != status.upper():
            continue
        if port and port not in (l_port, r_port):
            continue

        # Proceso
        proc_name = "Desconocido"
        if c.pid:
            try:
                proc_name = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "Acceso Denegado / Finalizado"

        conns.append({
            "proto": "TCP" if c.type == 1 else "UDP",
            "local": f"{l_ip}:{l_port}",
            "remote": f"{r_ip}:{r_port}",
            "status": st,
            "pid": c.pid or "-",
            "process": proc_name,
        })

    return sorted(conns, key=lambda x: (x["proto"], x["local"]))


def print_table(conns):
    """Muestra la tabla de conexiones en consola."""
    if not conns:
        return print("\n[i] No se encontraron conexiones.\n")

    fmt = "{:<6} | {:<22} | {:<22} | {:<12} | {:<8} | {:<25}"
    sep = "-" * 105
    print(f"\nTotal: {len(conns)}\n{sep}")
    print(fmt.format("PROTO", "LOCAL", "REMOTA", "ESTADO", "PID", "PROCESO"))
    print(sep)
    for c in conns:
        print(fmt.format(c["proto"], c["local"][:22], c["remote"][:22], c["status"][:12], str(c["pid"])[:8], c["process"][:25]))
    print(f"{sep}\n")


def export_data(conns, fmt):
    """Exporta los datos a CSV o JSON."""
    fname = input(f"Nombre de archivo (def: reporte.{fmt}): ").strip() or f"reporte.{fmt}"
    if fmt == "json":
        with open(fname, "w", encoding="utf-8") as f:
            json.dump({"timestamp": datetime.now().isoformat(), "connections": conns}, f, indent=4)
    else:
        with open(fname, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=conns[0].keys())
            writer.writeheader()
            writer.writerows(conns)
    print(f"[+] Exportado a {fname}")


def main():
    while True:
        print("=" * 50 + "\n MONITOR DE PUERTOS Y PROCESOS\n" + "=" * 50)
        print("1. Ver todas las conexiones\n2. Ver puertos en ESCUCHA (LISTEN)")
        print("3. Ver conexiones ESTABLECIDAS\n4. Buscar por puerto")
        print("5. Exportar JSON\n6. Exportar CSV\n7. Monitor en vivo\n0. Salir")
        
        opt = input("\nOpción [0-7]: ").strip()
        if opt == "1":
            print_table(get_connections())
        elif opt == "2":
            print_table(get_connections(proto="tcp", status="LISTEN"))
        elif opt == "3":
            print_table(get_connections(proto="tcp", status="ESTABLISHED"))
        elif opt == "4":
            try:
                p = int(input("Puerto: "))
                print_table(get_connections(port=p))
            except ValueError:
                print("[!] Puerto inválido.")
        elif opt in ("5", "6"):
            export_data(get_connections(), "json" if opt == "5" else "csv")
        elif opt == "7":
            try:
                while True:
                    os.system("cls" if os.name == "nt" else "clear")
                    print(f"[*] Monitor en vivo - {datetime.now().strftime('%H:%M:%S')} (Ctrl+C para salir)")
                    print_table(get_connections()[:20])
                    time.sleep(3)
            except KeyboardInterrupt:
                pass
        elif opt == "0":
            break


if __name__ == "__main__":
    main()