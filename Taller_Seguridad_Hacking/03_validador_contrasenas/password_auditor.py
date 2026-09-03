#!/usr/bin/env python3
"""
Taller de Seguridad en Hacking - Actividad 3
Auditor de Seguridad y Entropía de Contraseñas.

Este programa analiza la robustez de una contraseña basándose en:
1. Longitud y diversidad de caracteres (mayúsculas, minúsculas, dígitos, símbolos).
2. Cálculo de entropía de la información de Shannon/NIST (en bits).
3. Detección de patrones secuenciales y repeticiones simples.
4. Comparación contra lista negra de contraseñas débiles y comunes filtradas.
5. Estimación de tiempo de ruptura por fuerza bruta.
6. Generación de contraseñas criptográficamente seguras con la librería 'secrets'.
"""

from __future__ import annotations

import argparse
import getpass
import math
import re
import secrets
import string
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set


@dataclass
class AuditReport:
    """Estructura que almacena el resultado completo de la auditoría."""
    password_length: int
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_symbols: bool
    entropy_bits: float
    pool_size: int
    is_common: bool
    has_sequential: bool
    has_repeated: bool
    score: int  # 0 a 100
    classification: str
    estimated_crack_time: str
    vulnerabilities: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class PasswordAuditor:
    """Clase principal para la evaluación y generación de contraseñas seguras."""

    # Secuencias comunes de teclado o números
    SEQUENCES = [
        "1234567890",
        "0987654321",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "abcdefghijklmnopqrstuvwxyz",
    ]

    def __init__(self, dictionary_path: str | Path | None = None) -> None:
        self.common_passwords: Set[str] = set()
        self._load_dictionary(dictionary_path)

    def _load_dictionary(self, dict_path: str | Path | None) -> None:
        """Carga el diccionario de contraseñas comunes."""
        default_file = Path(__file__).parent / "common_passwords.txt"
        target = Path(dict_path) if dict_path else default_file

        if target.exists() and target.is_file():
            try:
                with open(target, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        cleaned = line.strip().lower()
                        if cleaned:
                            self.common_passwords.add(cleaned)
            except Exception:
                pass

    def _calculate_pool_size(self, has_lower: bool, has_upper: bool, has_digit: bool, has_symbol: bool) -> int:
        """Calcula el tamaño del espacio de caracteres (pool size)."""
        pool = 0
        if has_lower:
            pool += 26
        if has_upper:
            pool += 26
        if has_digit:
            pool += 10
        if has_symbol:
            pool += 32  # Símbolos estándar ASCII
        return pool or 1

    def _calculate_entropy(self, length: int, pool_size: int) -> float:
        """Calcula la entropía de la contraseña en bits: E = L * log2(R)."""
        if length == 0 or pool_size <= 1:
            return 0.0
        return length * math.log2(pool_size)

    def _check_sequences(self, pwd_lower: str) -> bool:
        """Detecta si contiene secuencias de más de 3 caracteres continuos."""
        for seq in self.SEQUENCES:
            for i in range(len(seq) - 2):
                sub = seq[i : i + 3]
                if sub in pwd_lower:
                    return True
        return False

    def _check_repetitions(self, password: str) -> bool:
        """Detecta repeticiones consecutivas (ej. 'aaa', '111')."""
        return bool(re.search(r"(.)\1{2,}", password))

    def _estimate_crack_time(self, entropy_bits: float) -> str:
        """
        Estima el tiempo necesario para romper la contraseña mediante un ataque de fuerza bruta
        asumiendo un clúster de GPUs moderno (100 mil millones de intentos / seg = 10^11 h/s).
        """
        if entropy_bits <= 0:
            return "Instantáneo"

        combinations = 2 ** entropy_bits
        guesses_per_sec = 100_000_000_000  # 100 GH/s

        seconds = combinations / (2 * guesses_per_sec)  # Promedio: mitad del espacio de búsqueda

        if seconds < 0.001:
            return "Instantáneo (< 1 milisegundo)"
        if seconds < 1:
            return f"Menos de 1 segundo ({seconds:.3f} s)"
        if seconds < 60:
            return f"{seconds:.1f} segundos"
        if seconds < 3600:
            return f"{seconds / 60:.1f} minutos"
        if seconds < 86400:
            return f"{seconds / 3600:.1f} horas"
        if seconds < 86400 * 365:
            return f"{seconds / 86400:.1f} días"
        if seconds < 86400 * 365 * 1000:
            return f"{seconds / (86400 * 365):.1f} años"
        if seconds < 86400 * 365 * 1_000_000:
            return f"{seconds / (86400 * 365 * 1000):.1f} milenios"
        return "Varios millones de años (Prácticamente inquebrantable)"

    def audit(self, password: str) -> AuditReport:
        """Ejecuta una auditoría completa sobre la contraseña dada."""
        length = len(password)
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digits = bool(re.search(r"[0-9]", password))
        has_symbols = bool(re.search(r"[^a-zA-Z0-9]", password))

        pool = self._calculate_pool_size(has_lower, has_upper, has_digits, has_symbols)
        entropy = self._calculate_entropy(length, pool)

        pwd_lower = password.lower()
        is_common = pwd_lower in self.common_passwords
        has_seq = self._check_sequences(pwd_lower)
        has_rep = self._check_repetitions(password)

        vulnerabilities: List[str] = []
        recommendations: List[str] = []

        # Puntuación base a partir de entropía y longitud
        score = min(100, int((entropy / 80.0) * 100))

        # Evaluaciones y penalizaciones
        if length < 8:
            vulnerabilities.append("Longitud crítica: Menor a 8 caracteres.")
            recommendations.append("Aumenta la longitud a mínimo 12 - 16 caracteres.")
            score = min(score, 25)
        elif length < 12:
            recommendations.append("Aumenta la longitud a 14 o más caracteres para mayor seguridad.")

        if not has_lower:
            recommendations.append("Incluye letras minúsculas (a-z).")
        if not has_upper:
            recommendations.append("Incluye letras mayúsculas (A-Z).")
        if not has_digits:
            recommendations.append("Incluye números (0-9).")
        if not has_symbols:
            recommendations.append("Incluye caracteres especiales o símbolos (!@#$%^&*...).")

        if is_common:
            vulnerabilities.append("Contraseña conocida: Se encuentra en listas de contraseñas filtradas.")
            recommendations.append("Nunca uses palabras comunes, nombres propios o secuencias estándar.")
            score = min(score, 10)

        if has_seq:
            vulnerabilities.append("Patrón secuencial detectado (ej. 123, abc, qwe).")
            score = max(0, score - 15)

        if has_rep:
            vulnerabilities.append("Caracteres repetidos consecutivos (ej. aaa, 111).")
            score = max(0, score - 10)

        # Clasificación
        if score < 25 or is_common or length < 6:
            classification = "MUY DÉBIL (INSEGURA)"
        elif score < 50:
            classification = "DÉBIL (VULNERABLE)"
        elif score < 75:
            classification = "MODERADA (ACEPTABLE)"
        elif score < 90:
            classification = "FUERTE (SEGURA)"
        else:
            classification = "MUY FUERTE (ALTAMENTE SEGURA)"

        crack_time = self._estimate_crack_time(entropy if not is_common else 5.0)

        return AuditReport(
            password_length=length,
            has_lowercase=has_lower,
            has_uppercase=has_upper,
            has_digits=has_digits,
            has_symbols=has_symbols,
            entropy_bits=round(entropy, 2),
            pool_size=pool,
            is_common=is_common,
            has_sequential=has_seq,
            has_repeated=has_rep,
            score=score,
            classification=classification,
            estimated_crack_time=crack_time,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
        )

    @staticmethod
    def generate_secure_password(length: int = 16, use_symbols: bool = True) -> str:
        """
        Genera una contraseña criptográficamente segura utilizando el módulo 'secrets'.
        Garantiza al menos 1 mayúscula, 1 minúscula, 1 dígito y 1 símbolo.
        """
        if length < 8:
            length = 8

        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        if use_symbols:
            chars += symbols

        while True:
            pwd = "".join(secrets.choice(chars) for _ in range(length))
            # Garantizar diversidad
            if (
                any(c in string.ascii_lowercase for c in pwd)
                and any(c in string.ascii_uppercase for c in pwd)
                and any(c in string.digits for c in pwd)
                and (not use_symbols or any(c in symbols for c in pwd))
            ):
                return pwd


# Configuración de salida segura para consolas Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def display_report(report: AuditReport, masked: bool = False) -> None:
    """Muestra el reporte de auditoría con formato visual."""
    print("\n" + "=" * 65)
    print("        RESULTADO DE LA AUDITORIA DE SEGURIDAD")
    print("=" * 65)

    # Barra visual de progreso ASCII compatible
    bar_length = 30
    filled = int((report.score / 100) * bar_length)
    bar = "#" * filled + "-" * (bar_length - filled)

    print(f"Puntuacion de Seguridad : [{bar}] {report.score}/100")
    print(f"Nivel de Seguridad      : {report.classification}")
    print(f"Longitud de Contrasena  : {report.password_length} caracteres")
    print(f"Entropia Estimada       : {report.entropy_bits} bits (Espacio: {report.pool_size} caracteres)")
    print(f"Tiempo Estimado Crack   : {report.estimated_crack_time}")
    print("-" * 65)
    print("COMPOSICION:")
    print(f"  [ {'OK' if report.has_lowercase else ' X '} ] Minusculas (a-z)")
    print(f"  [ {'OK' if report.has_uppercase else ' X '} ] Mayusculas (A-Z)")
    print(f"  [ {'OK' if report.has_digits else ' X '} ] Numeros (0-9)")
    print(f"  [ {'OK' if report.has_symbols else ' X '} ] Simbolos especiales")
    print("-" * 65)

    if report.vulnerabilities:
        print("VULNERABILIDADES DETECTADAS:")
        for vuln in report.vulnerabilities:
            print(f"  [!] {vuln}")
        print("-" * 65)

    if report.recommendations:
        print("RECOMENDACIONES PARA MEJORAR:")
        for rec in report.recommendations:
            print(f"  [+] {rec}")
    else:
        print("[+] ¡Excelente! La contrasena cumple con los estandares modernos de seguridad.")

    print("=" * 65 + "\n")



def interactive_menu(auditor: PasswordAuditor) -> None:
    """Menú interactivo."""
    while True:
        print("\n" + "=" * 60)
        print("    TALLER SEGURIDAD - VALIDADOR DE CONTRASEÑAS")
        print("=" * 60)
        print("1. Evaluar una contraseña (oculta al escribir / getpass)")
        print("2. Evaluar una contraseña (visible en pantalla)")
        print("3. Generar una contraseña segura aleatoria")
        print("0. Salir")
        print("=" * 60)

        opc = input("Selecciona una opción [0-3]: ").strip()

        if opc == "1":
            pwd = getpass.getpass("Ingresa la contraseña a evaluar (no se mostrará): ")
            if not pwd:
                print("[!] Contraseña vacía.")
                continue
            rep = auditor.audit(pwd)
            display_report(rep)

        elif opc == "2":
            pwd = input("Ingresa la contraseña a evaluar: ")
            if not pwd:
                print("[!] Contraseña vacía.")
                continue
            rep = auditor.audit(pwd)
            display_report(rep)

        elif opc == "3":
            try:
                length_str = input("Longitud deseada (Enter para 16): ").strip()
                length = int(length_str) if length_str else 16
                gen_pwd = auditor.generate_secure_password(length=length)
                print(f"\n[+] CONTRASEÑA SEGURA GENERADA:")
                print(f"    {gen_pwd}\n")
                rep = auditor.audit(gen_pwd)
                display_report(rep)
            except ValueError:
                print("[!] Longitud inválida.")

        elif opc == "0":
            print("\n[+] Saliendo del validador de contraseñas. ¡Hasta pronto!\n")
            break
        else:
            print("[!] Opción no válida.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auditor de robustez, entropía y vulnerabilidades en contraseñas."
    )
    parser.add_argument(
        "-p", "--password",
        type=str,
        help="Contraseña a auditar directamente desde CLI",
    )
    parser.add_argument(
        "-g", "--generate",
        action="store_true",
        help="Generar una contraseña criptográficamente segura",
    )
    parser.add_argument(
        "-l", "--length",
        type=int,
        default=16,
        help="Longitud para la contraseña generada (default: 16)",
    )
    parser.add_argument(
        "-d", "--dict",
        type=str,
        default=None,
        help="Ruta personalizada a un archivo de contraseñas comunes",
    )

    args = parser.parse_args()
    auditor = PasswordAuditor(dictionary_path=args.dict)

    if args.generate:
        pwd = auditor.generate_secure_password(length=args.length)
        print(f"[+] Contraseña generada: {pwd}")
        rep = auditor.audit(pwd)
        display_report(rep)
        return

    if args.password:
        rep = auditor.audit(args.password)
        display_report(rep)
        return

    interactive_menu(auditor)


if __name__ == "__main__":
    main()
