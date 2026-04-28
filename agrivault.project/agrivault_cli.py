"""
AgriVault CLI — Command-line encryption/decryption tool
Usage:
  python agrivault_cli.py encrypt <file> --password <pwd>
  python agrivault_cli.py decrypt <file.agv> --password <pwd>
  python agrivault_cli.py info <file.agv>
"""

import argparse
import getpass
import sys
import os
import time
from crypto_engine import encrypt_file, decrypt_file, get_file_metadata


def format_bytes(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def print_banner():
    print("\n" + "=" * 60)
    print("  🌿 AgriVault — Secure Agriculture Data Encryption")
    print("  Hardened Cloud Infrastructure | AES-256-CBC")
    print("=" * 60 + "\n")


def cmd_encrypt(args):
    print_banner()
    print(f"[+] File      : {args.file}")
    print(f"[+] Algorithm : AES-256-CBC")
    print(f"[+] KDF       : PBKDF2-HMAC-SHA256 (310,000 iterations)")

    password = args.password or getpass.getpass("[?] Enter encryption password: ")
    confirm  = args.password or getpass.getpass("[?] Confirm password: ")

    if password != confirm:
        print("\n[✗] Passwords do not match. Aborting.")
        sys.exit(1)

    if len(password) < 8:
        print("\n[⚠] Warning: Password is shorter than 8 characters.")

    print("\n[~] Encrypting...")
    start = time.time()

    try:
        result = encrypt_file(args.file, password)
        elapsed = time.time() - start

        print(f"\n[✓] Encryption complete in {elapsed:.2f}s")
        print(f"    Original  : {format_bytes(result['original_size'])}")
        print(f"    Encrypted : {format_bytes(result['encrypted_size'])}")
        print(f"    Saved to  : {result['encrypted_path']}")
        print(f"    Integrity : {result['integrity']}")
        print()
    except FileNotFoundError as e:
        print(f"\n[✗] {e}")
        sys.exit(1)


def cmd_decrypt(args):
    print_banner()
    print(f"[+] File      : {args.file}")

    password = args.password or getpass.getpass("[?] Enter decryption password: ")

    print("\n[~] Verifying HMAC and decrypting...")
    start = time.time()

    try:
        result = decrypt_file(args.file, password, args.output)
        elapsed = time.time() - start

        print(f"\n[✓] Decryption complete in {elapsed:.2f}s")
        print(f"    Restored  : {result['original_filename']}")
        print(f"    Size      : {format_bytes(result['size'])}")
        print(f"    Saved to  : {result['decrypted_path']}")
        print()
    except ValueError as e:
        print(f"\n[✗] {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"\n[✗] {e}")
        sys.exit(1)


def cmd_info(args):
    print_banner()
    try:
        meta = get_file_metadata(args.file)
        print(f"  File Format : {meta['format']}")
        print(f"  Original    : {meta['original_filename']}")
        print(f"  Cipher Size : {format_bytes(meta['encrypted_size'])}")
        print(f"  Encrypted   : {time.ctime(meta['timestamp'])}")
        print()
    except Exception as e:
        print(f"[✗] {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="AgriVault — AES-256-CBC file encryption for agriculture data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agrivault_cli.py encrypt soil_report.csv
  python agrivault_cli.py encrypt soil_report.csv --password mySecret123
  python agrivault_cli.py decrypt soil_report.csv.agv
  python agrivault_cli.py decrypt soil_report.csv.agv --output ./restored/
  python agrivault_cli.py info soil_report.csv.agv
        """
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("file", help="Path to file to encrypt")
    enc.add_argument("--password", help="Encryption password (prompted if not provided)")

    dec = sub.add_parser("decrypt", help="Decrypt a .agv file")
    dec.add_argument("file", help="Path to .agv encrypted file")
    dec.add_argument("--password", help="Decryption password")
    dec.add_argument("--output", help="Output directory (default: same as input)", default=None)

    inf = sub.add_parser("info", help="Show metadata from an encrypted file")
    inf.add_argument("file", help="Path to .agv encrypted file")

    args = parser.parse_args()

    if args.command == "encrypt":
        cmd_encrypt(args)
    elif args.command == "decrypt":
        cmd_decrypt(args)
    elif args.command == "info":
        cmd_info(args)


if __name__ == "__main__":
    main()
