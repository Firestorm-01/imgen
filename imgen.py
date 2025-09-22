#!/usr/bin/env python3
import argparse
import struct
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

# --- Config ---
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


# --- Crypto Helpers ---
def derive_key(password: bytes, salt: bytes) -> bytes:
    return scrypt(password, salt, KEY_LEN, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)


def encrypt_image(secret_path: str, password: str) -> bytes:
    data = open(secret_path, "rb").read()
    salt = get_random_bytes(SALT_LEN)
    nonce = get_random_bytes(NONCE_LEN)
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext = cipher.encrypt(data)
    tag = cipher.digest()
    encrypted = salt + nonce + ciphertext + tag
    return struct.pack(">I", len(encrypted)) + encrypted  # prepend length


def decrypt_image(encrypted_bytes: bytes, password: str) -> bytes:
    if len(encrypted_bytes) < 4 + SALT_LEN + NONCE_LEN + TAG_LEN:
        raise ValueError("Encrypted data is too short.")
    encrypted_bytes = encrypted_bytes[4:]  # skip 4-byte header
    salt = encrypted_bytes[:SALT_LEN]
    nonce = encrypted_bytes[SALT_LEN:SALT_LEN+NONCE_LEN]
    tag = encrypted_bytes[-TAG_LEN:]
    ciphertext = encrypted_bytes[SALT_LEN+NONCE_LEN:-TAG_LEN]
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    cipher.verify(tag)  # Raises if tampered
    return plaintext


# --- Steganography ---
def hide_bytes_in_image(cover_path: str, secret_bytes: bytes, output_path: str):
    img = Image.open(cover_path).convert("RGB")
    width, height = img.size
    pixels = img.load()

    # Prepend 4-byte length
    length = len(secret_bytes)
    header = length.to_bytes(4, "big")
    data = header + secret_bytes

    data_bits = ''.join(f'{b:08b}' for b in data)
    max_bits = width * height * 3
    if len(data_bits) > max_bits:
        raise ValueError("Cover image too small for secret data!")

    idx = 0
    for y in range(height):
        for x in range(width):
            if idx >= len(data_bits):
                break
            r, g, b = pixels[x, y]
            if idx < len(data_bits):
                r = (r & ~1) | int(data_bits[idx]); idx += 1
            if idx < len(data_bits):
                g = (g & ~1) | int(data_bits[idx]); idx += 1
            if idx < len(data_bits):
                b = (b & ~1) | int(data_bits[idx]); idx += 1
            pixels[x, y] = (r, g, b)
        if idx >= len(data_bits):
            break

    img.save(output_path)
    print(f"[+] Secret hidden inside '{output_path}'")


def extract_bytes_from_image(stego_path: str) -> bytes:
    img = Image.open(stego_path).convert("RGB")
    width, height = img.size
    pixels = img.load()

    bits = []
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            bits.extend([r & 1, g & 1, b & 1])

    # First 32 bits = length
    length_bits = bits[:32]
    length = int("".join(str(b) for b in length_bits), 2)

    data_bits = bits[32:32 + (length * 8)]
    secret_bytes = bytearray()
    for i in range(0, len(data_bits), 8):
        byte = int("".join(str(b) for b in data_bits[i:i+8]), 2)
        secret_bytes.append(byte)

    return bytes(secret_bytes)


# --- CLI ---
def main():
    parser = argparse.ArgumentParser(description="Image Encryption + Steganography Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Hide
    hide_p = subparsers.add_parser("hide", help="Hide an image inside a cover image")
    hide_p.add_argument("secret", help="Path to secret image")
    hide_p.add_argument("cover", help="Path to cover image")
    hide_p.add_argument("output", help="Path to output stego image")
    hide_p.add_argument("password", help="Password for encryption")

    # Extract
    extract_p = subparsers.add_parser("extract", help="Extract a hidden image")
    extract_p.add_argument("stego", help="Path to stego image")
    extract_p.add_argument("password", help="Password used during hiding")
    extract_p.add_argument("output", help="Path to save decrypted secret image")

    args = parser.parse_args()

    if args.command == "hide":
        encrypted_bytes = encrypt_image(args.secret, args.password)
        hide_bytes_in_image(args.cover, encrypted_bytes, args.output)

    elif args.command == "extract":
        encrypted_bytes = extract_bytes_from_image(args.stego)
        plaintext = decrypt_image(encrypted_bytes, args.password)
        with open(args.output, "wb") as f:
            f.write(plaintext)
        print(f"[+] Secret extracted to '{args.output}'")


if __name__ == "__main__":
    main()