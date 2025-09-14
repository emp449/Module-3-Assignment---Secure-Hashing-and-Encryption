#!/usr/bin/env python3
"""
crypto_app.py
A Python app that demonstrates:
 1. SHA-256 hashing for strings and files
 2. Caesar cipher encryption/decryption
 3. RSA digital signatures (sign/verify)

Dependencies:
  pip install cryptography
"""

import argparse
import hashlib
from pathlib import Path
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend


# ---------------- SHA-256 ----------------
def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------- Caesar Cipher ----------------
def shift_char(ch: str, shift: int) -> str:
    if "a" <= ch <= "z":
        return chr((ord(ch) - ord("a") + shift) % 26 + ord("a"))
    if "A" <= ch <= "Z":
        return chr((ord(ch) - ord("A") + shift) % 26 + ord("A"))
    return ch

def caesar_encrypt(text: str, shift: int) -> str:
    return "".join(shift_char(c, shift) for c in text)

def caesar_decrypt(text: str, shift: int) -> str:
    return "".join(shift_char(c, -shift) for c in text)


# ---------------- RSA Sign/Verify ----------------
def generate_keys(priv_file="private.pem", pub_file="public.pem", bits=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    # Save private key
    with open(priv_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Save public key
    with open(pub_file, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"Keys saved: {priv_file}, {pub_file}")

def sign_data(priv_file: str, data: bytes, sig_file="signature.bin"):
    private_key = serialization.load_pem_private_key(
        Path(priv_file).read_bytes(), password=None, backend=default_backend()
    )
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    Path(sig_file).write_bytes(signature)
    print(f"Signature saved to {sig_file}")

def verify_signature(pub_file: str, data: bytes, sig_file: str):
    public_key = serialization.load_pem_public_key(
        Path(pub_file).read_bytes(), backend=default_backend()
    )
    signature = Path(sig_file).read_bytes()
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("✅ Signature is VALID")
    except Exception:
        print("❌ Signature is INVALID")


# ---------------- CLI ----------------
def main():
    parser = argparse.ArgumentParser(description="Crypto App: SHA-256 | Caesar | Sign/Verify")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Hash
    ph = sub.add_parser("hash", help="Compute SHA-256")
    g = ph.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", "-t", help="Text input")
    g.add_argument("--file", "-f", help="File input")

    # Caesar
    pc = sub.add_parser("caesar", help="Caesar cipher")
    pc.add_argument("mode", choices=["encrypt", "decrypt"])
    pc.add_argument("--text", "-t", required=True)
    pc.add_argument("--shift", "-s", type=int, default=3)

    # Keygen
    pk = sub.add_parser("keygen", help="Generate RSA keypair")
    pk.add_argument("--priv", default="private.pem")
    pk.add_argument("--pub", default="public.pem")
    pk.add_argument("--bits", type=int, default=2048)

    # Sign
    ps = sub.add_parser("sign", help="Sign text or file")
    sgrp = ps.add_mutually_exclusive_group(required=True)
    sgrp.add_argument("--text", "-t")
    sgrp.add_argument("--file", "-f")
    ps.add_argument("--priv", required=True)
    ps.add_argument("--out", "-o", default="signature.bin")

    # Verify
    pv = sub.add_parser("verify", help="Verify signature")
    vgrp = pv.add_mutually_exclusive_group(required=True)
    vgrp.add_argument("--text", "-t")
    vgrp.add_argument("--file", "-f")
    pv.add_argument("--pub", required=True)
    pv.add_argument("--signature", "-s", required=True)

    args = parser.parse_args()

    if args.cmd == "hash":
        if args.text:
            print(sha256_text(args.text))
        else:
            print(sha256_file(Path(args.file)))

    elif args.cmd == "caesar":
        if args.mode == "encrypt":
            print(caesar_encrypt(args.text, args.shift))
        else:
            print(caesar_decrypt(args.text, args.shift))

    elif args.cmd == "keygen":
        generate_keys(args.priv, args.pub, args.bits)

    elif args.cmd == "sign":
        data = args.text.encode() if args.text else Path(args.file).read_bytes()
        sign_data(args.priv, data, args.out)

    elif args.cmd == "verify":
        data = args.text.encode() if args.text else Path(args.file).read_bytes()
        verify_signature(args.pub, data, args.signature)


if __name__ == "__main__":
    main()
