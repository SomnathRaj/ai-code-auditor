"""Encryption at rest (PRD §44, §52) with Fernet (AES-128-CBC + HMAC-SHA256).

MultiFernet: the first key in ENCRYPTION_KEYS encrypts, every key decrypts, so
keys can be rotated by prepending a new one.
"""
from typing import BinaryIO, Iterator

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from flask import Flask, current_app

STREAM_CHUNK = 4 * 1024 * 1024


def init_crypto(app: Flask) -> None:
    keys = app.config["ENCRYPTION_KEYS"]
    if not keys:
        raise RuntimeError("ENCRYPTION_KEYS is not set. Generate one (see .env.example).")
    try:
        app.extensions["fernet"] = MultiFernet([Fernet(k) for k in keys])
    except ValueError:
        raise RuntimeError("ENCRYPTION_KEYS contains an invalid Fernet key (must be 32 url-safe base64 bytes).")


def _fernet() -> MultiFernet:
    return current_app.extensions["fernet"]


def encrypt_text(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt_text(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


def rotate_text(token: str) -> str:
    """Re-encrypt with the primary (first) key; readable by any configured key."""
    return _fernet().rotate(token.encode()).decode()


def encrypt_stream(src: BinaryIO, write) -> None:
    """Encrypt src in chunks; each chunk is one Fernet token followed by a newline.

    Fernet tokens are url-safe base64, so newlines never occur inside one.
    Callers verify a SHA-256 of the plaintext on read to detect reordered or
    dropped chunks.
    """
    f = _fernet()
    while chunk := src.read(STREAM_CHUNK):
        write(f.encrypt(chunk) + b"\n")


def decrypt_stream(readline) -> Iterator[bytes]:
    f = _fernet()
    while line := readline():
        line = line.rstrip(b"\n")
        if line:
            try:
                yield f.decrypt(line)
            except InvalidToken:
                raise ValueError("Stored archive could not be decrypted (wrong key or corrupted data)")
