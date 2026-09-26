"""
video_stego.py - MP4 Steganography Module
==========================================
Embeds encrypted secret messages into MP4 files using metadata atoms.
Uses the mutagen library to write ciphertext into a custom freeform atom
(under the '----' iTunes-style tag namespace), and the cryptography
library (Fernet) for password-based encryption.

Strategy:
- Derive a Fernet key from the user's password via PBKDF2 (SHA256, 480000 iterations).
- Encrypt the message (with "#####" sentinel appended) using Fernet.
- Base64-encode the ciphertext and store it in a custom MP4 freeform atom.
- The MP4 audio/video streams are completely untouched, so the file stays valid and playable.
"""

import base64
import hashlib
import os
import shutil

from cryptography.fernet import Fernet, InvalidToken
from mutagen.mp4 import MP4

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SENTINEL = "#####"                       # End-of-message marker
# Custom freeform atom key:  ----:com.stego:data
ATOM_KEY = "----:com.stego:data"
PBKDF2_ITERATIONS = 480_000
SALT_LENGTH = 16


# ---------------------------------------------------------------------------
# Key derivation  (same scheme as audio_stego for consistency)
# ---------------------------------------------------------------------------
def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet key from a password + salt using PBKDF2."""
    raw = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(raw)


# ---------------------------------------------------------------------------
# Encode (embed message into MP4)
# ---------------------------------------------------------------------------
def encode_mp4(input_path: str, output_path: str, message: str, password: str = "") -> None:
    """
    Embed a secret message into an MP4 file via metadata atoms.
    If password is provided, the message is encrypted with Fernet.
    If password is empty, the message is stored as plaintext (base64-encoded).

    Parameters
    ----------
    input_path  : path to the original .mp4 file
    output_path : path where the stego .mp4 will be saved
    message     : plaintext secret message
    password    : password for encryption (optional – empty = no encryption)

    Raises
    ------
    FileNotFoundError  – input file doesn't exist
    ValueError         – empty message
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if not message.strip():
        raise ValueError("Message cannot be empty.")

    plaintext = (message + SENTINEL).encode("utf-8")

    if password:
        # --- Encrypted mode: flag byte 0x01 + salt + ciphertext ---------
        salt = os.urandom(SALT_LENGTH)
        key = _derive_key(password, salt)
        fernet = Fernet(key)
        ciphertext = fernet.encrypt(plaintext)
        raw_payload = b"\x01" + salt + ciphertext
    else:
        # --- Plaintext mode: flag byte 0x00 + raw message ---------------
        raw_payload = b"\x00" + plaintext

    payload = base64.b64encode(raw_payload)

    # --- Copy original so we don't mutate the source --------------------
    shutil.copy2(input_path, output_path)

    # --- Write MP4 atom -------------------------------------------------
    mp4 = MP4(output_path)
    # mutagen stores freeform atoms as list of bytes
    mp4[ATOM_KEY] = [payload]
    mp4.save()


# ---------------------------------------------------------------------------
# Decode (extract message from MP4)
# ---------------------------------------------------------------------------
def decode_mp4(stego_path: str, password: str = "") -> str:
    """
    Extract and decrypt the secret message from a stego MP4 file.

    Parameters
    ----------
    stego_path : path to the stego .mp4 file
    password   : password used during encoding (empty if not encrypted)

    Returns
    -------
    str – the original plaintext message (without sentinel)

    Raises
    ------
    FileNotFoundError – file doesn't exist
    ValueError        – no hidden data found, wrong password, or corrupted data
    """
    if not os.path.isfile(stego_path):
        raise FileNotFoundError(f"File not found: {stego_path}")

    # --- Read MP4 atom --------------------------------------------------
    mp4 = MP4(stego_path)

    if ATOM_KEY not in mp4:
        raise ValueError("No hidden data found in this MP4 file.")

    payload_bytes = mp4[ATOM_KEY][0]
    # mutagen may return bytes or MP4FreeForm; ensure bytes
    if hasattr(payload_bytes, "decode"):
        payload = payload_bytes
    else:
        payload = bytes(payload_bytes)

    try:
        raw = base64.b64decode(payload)
    except Exception:
        raise ValueError("Corrupted stego data – base64 decode failed.")

    # --- Check flag byte ------------------------------------------------
    flag = raw[0]
    data = raw[1:]

    if flag == 0x01:
        # Encrypted mode
        if not password:
            raise ValueError("This file is password-protected. Please enter the password.")
        salt = data[:SALT_LENGTH]
        ciphertext = data[SALT_LENGTH:]
        key = _derive_key(password, salt)
        fernet = Fernet(key)
        try:
            plaintext = fernet.decrypt(ciphertext).decode("utf-8")
        except InvalidToken:
            raise ValueError("Decryption failed – wrong password or corrupted data.")
    else:
        # Plaintext mode (no encryption)
        plaintext = data.decode("utf-8")

    # Strip sentinel
    if plaintext.endswith(SENTINEL):
        plaintext = plaintext[: -len(SENTINEL)]

    return plaintext
