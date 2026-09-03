#!/usr/bin/env python3
"""
Taller de Seguridad en Hacking - Actividad 2
Sistema Criptográfico Simétrico con Fernet (AES-128-CBC + HMAC-SHA256).

Este programa permite:
1. Generar claves aleatorias seguras de Fernet o derivar claves a partir de una contraseña usando PBKDF2HMAC.
2. Cifrar mensajes de texto y archivos.
3. Descifrar mensajes de texto y archivos con la clave o contraseña correspondiente.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path
from typing import Optional, Tuple

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("[!] Error: El paquete 'cryptography' no está instalado.")
    print("    Instálalo ejecutando: pip install cryptography")
    sys.exit(1)

# Configuración de salida segura para consolas Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass



# Constantes para la derivación de llaves segura con PBKDF2
PBKDF2_ITERATIONS = 480_000
SALT_SIZE = 16  # 128 bits


class FernetCryptoManager:
    """Administrador de cifrado y descifrado simétrico basado en Fernet."""

    @staticmethod
    def generate_random_key() -> bytes:
        """Genera una clave Fernet url-safe base64 aleatoria de 32 bytes."""
        return Fernet.generate_key()

    @staticmethod
    def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Deriva una clave compatible con Fernet a partir de una contraseña
        utilizando PBKDF2-HMAC-SHA256 con 480,000 iteraciones.

        :param password: Texto plano de la contraseña.
        :param salt: Sal criptográfica de 16 bytes. Si es None, se genera una nueva.
        :return: Tupla (fernet_key, salt).
        """
        if salt is None:
            salt = os.urandom(SALT_SIZE)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        derived_raw = kdf.derive(password.encode("utf-8"))
        fernet_key = base64.urlsafe_b64encode(derived_raw)
        return fernet_key, salt

    @staticmethod
    def encrypt_text_with_key(plain_text: str, key: bytes) -> str:
        """Cifra un texto plano utilizando una clave Fernet."""
        f = Fernet(key)
        encrypted_bytes = f.encrypt(plain_text.encode("utf-8"))
        return encrypted_bytes.decode("utf-8")

    @staticmethod
    def decrypt_text_with_key(cipher_text: str, key: bytes) -> str:
        """Descifra un texto cifrado con Fernet utilizando la clave."""
        try:
            f = Fernet(key)
            decrypted_bytes = f.decrypt(cipher_text.strip().encode("utf-8"))
            return decrypted_bytes.decode("utf-8")
        except (InvalidToken, InvalidSignature) as exc:
            raise ValueError("Error de descifrado: Clave incorrecta o mensaje alterado/corrupto.") from exc

    @classmethod
    def encrypt_text_with_password(cls, plain_text: str, password: str) -> str:
        """
        Cifra texto derivando la clave de una contraseña.
        Empaqueta la sal (16 bytes) al inicio del payload en formato base64.
        """
        key, salt = cls.derive_key_from_password(password)
        f = Fernet(key)
        encrypted_bytes = f.encrypt(plain_text.encode("utf-8"))
        # Estructura: salt (16 bytes) + ciphertext bytes -> codificado en base64 para transportabilidad
        payload = salt + encrypted_bytes
        return base64.urlsafe_b64encode(payload).decode("utf-8")

    @classmethod
    def decrypt_text_with_password(cls, payload_b64: str, password: str) -> str:
        """
        Descifra un payload con sal integrada utilizando una contraseña.
        """
        try:
            raw_payload = base64.urlsafe_b64decode(payload_b64.strip().encode("utf-8"))
            if len(raw_payload) < SALT_SIZE:
                raise ValueError("El formato del texto cifrado es inválido o está truncado.")

            salt = raw_payload[:SALT_SIZE]
            ciphertext = raw_payload[SALT_SIZE:]

            key, _ = cls.derive_key_from_password(password, salt=salt)
            f = Fernet(key)
            decrypted_bytes = f.decrypt(ciphertext)
            return decrypted_bytes.decode("utf-8")
        except (InvalidToken, InvalidSignature, base64.binascii.Error) as exc:
            raise ValueError("Error de descifrado: Contraseña incorrecta o datos corruptos.") from exc

    @classmethod
    def encrypt_file(cls, input_path: Path, output_path: Path, key: bytes) -> None:
        """Cifra el contenido binario de un archivo."""
        f = Fernet(key)
        data = input_path.read_bytes()
        encrypted_data = f.encrypt(data)
        output_path.write_bytes(encrypted_data)

    @classmethod
    def decrypt_file(cls, input_path: Path, output_path: Path, key: bytes) -> None:
        """Descifra el contenido binario de un archivo."""
        try:
            f = Fernet(key)
            encrypted_data = input_path.read_bytes()
            decrypted_data = f.decrypt(encrypted_data)
            output_path.write_bytes(decrypted_data)
        except (InvalidToken, InvalidSignature) as exc:
            raise ValueError("Error al descifrar el archivo: Clave incorrecta o archivo dañado.") from exc


def interactive_menu() -> None:
    """Menú interactivo por consola."""
    manager = FernetCryptoManager()

    while True:
        print("\n" + "=" * 60)
        print("    TALLER SEGURIDAD - CIFRADO Y DESCIFRADO FERNET")
        print("=" * 60)
        print("1. Cifrar texto usando una CONTRASEÑA / CLAVE personal")
        print("2. Descifrar texto usando una CONTRASEÑA / CLAVE personal")
        print("3. Generar una nueva Clave Fernet aleatoria (Base64)")
        print("4. Cifrar texto con Clave Fernet directa")
        print("5. Descifrar texto con Clave Fernet directa")
        print("6. Cifrar un archivo")
        print("7. Descifrar un archivo")
        print("0. Salir")
        print("=" * 60)

        opc = input("Selecciona una opción [0-7]: ").strip()

        if opc == "1":
            text = input("\nIngresa el texto a cifrar: ").strip()
            password = input("Ingresa la clave/contraseña secreta: ").strip()
            if not text or not password:
                print("[!] El texto y la contraseña no pueden estar vacíos.")
                continue
            token = manager.encrypt_text_with_password(text, password)
            print("\n[+] TEXTO CIFRADO EXITOSAMENTE:")
            print("-" * 60)
            print(token)
            print("-" * 60)

        elif opc == "2":
            token = input("\nIngresa el texto cifrado (token): ").strip()
            password = input("Ingresa la clave/contraseña secreta: ").strip()
            try:
                decrypted = manager.decrypt_text_with_password(token, password)
                print("\n[+] TEXTO DESCIFRADO:")
                print("-" * 60)
                print(decrypted)
                print("-" * 60)
            except ValueError as err:
                print(f"\n[!] {err}")

        elif opc == "3":
            key = manager.generate_random_key().decode("utf-8")
            print("\n[+] CLAVE FERNET GENERADA (32 bytes url-safe base64):")
            print("-" * 60)
            print(key)
            print("-" * 60)
            save = input("¿Deseas guardar esta clave en un archivo? (s/n): ").strip().lower()
            if save == "s":
                path = input("Nombre del archivo (ej. clave_secreta.key): ").strip() or "clave_secreta.key"
                Path(path).write_text(key, encoding="utf-8")
                print(f"[+] Clave guardada en: {path}")

        elif opc == "4":
            key_str = input("\nIngresa la clave Fernet (base64): ").strip()
            text = input("Ingresa el texto a cifrar: ").strip()
            try:
                encrypted = manager.encrypt_text_with_key(text, key_str.encode("utf-8"))
                print("\n[+] TEXTO CIFRADO:")
                print("-" * 60)
                print(encrypted)
                print("-" * 60)
            except Exception as err:
                print(f"[!] Error: {err}")

        elif opc == "5":
            key_str = input("\nIngresa la clave Fernet (base64): ").strip()
            cipher_str = input("Ingresa el texto cifrado: ").strip()
            try:
                decrypted = manager.decrypt_text_with_key(cipher_str, key_str.encode("utf-8"))
                print("\n[+] TEXTO DESCIFRADO:")
                print("-" * 60)
                print(decrypted)
                print("-" * 60)
            except ValueError as err:
                print(f"[!] {err}")

        elif opc == "6":
            file_in = input("\nRuta del archivo a cifrar: ").strip()
            in_path = Path(file_in)
            if not in_path.exists() or not in_path.is_file():
                print(f"[!] El archivo '{file_in}' no existe.")
                continue

            pwd = input("Ingresa la contraseña para cifrar el archivo: ").strip()
            key, salt = manager.derive_key_from_password(pwd)
            out_file = input(f"Ruta de salida (Enter para '{file_in}.enc'): ").strip() or f"{file_in}.enc"
            salt_file = f"{out_file}.salt"

            manager.encrypt_file(in_path, Path(out_file), key)
            Path(salt_file).write_bytes(salt)
            print(f"[+] Archivo cifrado guardado en: {out_file}")
            print(f"[+] Sal criptográfica guardada en: {salt_file} (necesaria para descifrar)")

        elif opc == "7":
            file_in = input("\nRuta del archivo cifrado (.enc): ").strip()
            in_path = Path(file_in)
            if not in_path.exists() or not in_path.is_file():
                print(f"[!] El archivo '{file_in}' no existe.")
                continue

            pwd = input("Ingresa la contraseña para descifrar: ").strip()
            salt_default = f"{file_in}.salt"
            salt_input = input(f"Ruta del archivo .salt (Enter para '{salt_default}'): ").strip() or salt_default
            salt_path = Path(salt_input)
            if not salt_path.exists():
                print(f"[!] Archivo de sal '{salt_input}' no encontrado.")
                continue

            salt = salt_path.read_bytes()
            key, _ = manager.derive_key_from_password(pwd, salt=salt)

            default_out = file_in.replace(".enc", ".dec") if file_in.endswith(".enc") else f"{file_in}.dec"
            out_file = input(f"Ruta de salida (Enter para '{default_out}'): ").strip() or default_out

            try:
                manager.decrypt_file(in_path, Path(out_file), key)
                print(f"[+] Archivo descifrado exitosamente en: {out_file}")
            except ValueError as err:
                print(f"[!] {err}")

        elif opc == "0":
            print("\n[+] Saliendo de la herramienta de cifrado. ¡Hasta luego!\n")
            break
        else:
            print("[!] Opción no reconocida.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Herramienta de cifrado y descifrado simétrico con Fernet y derivación PBKDF2."
    )
    subparsers = parser.add_subparsers(dest="command", help="Comando a ejecutar")

    # Subcomando: generate-key
    subparsers.add_parser("generate-key", help="Generar una clave Fernet aleatoria segura")

    # Subcomando: encrypt
    enc_parser = subparsers.add_parser("encrypt", help="Cifrar texto")
    enc_parser.add_argument("-t", "--text", required=True, help="Texto a cifrar")
    enc_parser.add_argument("-p", "--password", help="Contraseña para derivar la clave")
    enc_parser.add_argument("-k", "--key", help="Clave Fernet directa en Base64")

    # Subcomando: decrypt
    dec_parser = subparsers.add_parser("decrypt", help="Descifrar texto")
    dec_parser.add_argument("-c", "--ciphertext", required=True, help="Texto cifrado (token)")
    dec_parser.add_argument("-p", "--password", help="Contraseña utilizada para cifrar")
    dec_parser.add_argument("-k", "--key", help="Clave Fernet directa en Base64")

    args = parser.parse_args()
    manager = FernetCryptoManager()

    if args.command is None:
        interactive_menu()
        return

    if args.command == "generate-key":
        key = manager.generate_random_key().decode("utf-8")
        print(f"[+] Clave Fernet generada: {key}")

    elif args.command == "encrypt":
        if args.password:
            token = manager.encrypt_text_with_password(args.text, args.password)
            print(f"[+] Texto cifrado:\n{token}")
        elif args.key:
            token = manager.encrypt_text_with_key(args.text, args.key.encode("utf-8"))
            print(f"[+] Texto cifrado:\n{token}")
        else:
            print("[!] Debes proporcionar --password o --key.")

    elif args.command == "decrypt":
        if args.password:
            try:
                plain = manager.decrypt_text_with_password(args.ciphertext, args.password)
                print(f"[+] Texto descifrado:\n{plain}")
            except ValueError as err:
                print(f"[!] {err}")
        elif args.key:
            try:
                plain = manager.decrypt_text_with_key(args.ciphertext, args.key.encode("utf-8"))
                print(f"[+] Texto descifrado:\n{plain}")
            except ValueError as err:
                print(f"[!] {err}")
        else:
            print("[!] Debes proporcionar --password o --key.")


if __name__ == "__main__":
    main()
