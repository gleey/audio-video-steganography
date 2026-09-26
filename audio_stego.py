"""
audio_stego.py - MP3 Steganography Module
==========================================
Embeds encrypted secret messages into MP3 files using ID3 metadata tags.
Uses the mutagen library to write ciphertext into a custom TXXX frame,
and the cryptography library (Fernet) for password-based encryption.

Strategy:
- Derive a Fernet key from the user's password via PBKDF2 (SHA256, 480000 iterations).
- Encrypt the message (with "#####" sentinel appended) using Fernet.
- Base64-encode the ciphertext and store it in a custom ID3 TXXX tag.
- The MP3 audio data is completely untouched, so the file stays valid and playable.
"""

import base64
import hashlib
import os
import shutil

from cryptography.fernet import Fernet, InvalidToken
from mutagen.id3 import ID3, TXXX, ID3NoHeaderError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SENTINEL = "#####"                       # End-of-message marker
TAG_DESC = "STEGO_DATA"                  # TXXX frame description (custom tag key)
PBKDF2_ITERATIONS = 480_000             # OWASP-recommended minimum for PBKDF2-SHA256
SALT_LENGTH = 16                         # 128-bit random salt


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------
def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet key from a password + salt using PBKDF2."""
    raw = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    # Fernet requires a url-safe base64-encoded 32-byte key
    return base64.urlsafe_b64encode(raw)


# ---------------------------------------------------------------------------
# Encode (embed message into MP3)
# ---------------------------------------------------------------------------
def encode_mp3(input_path: str, output_path: str, message: str, password: str = "") -> None:
    """
    Embed a secret message into an MP3 file via ID3 metadata.
    If password is provided, the message is encrypted with Fernet.
    If password is empty, the message is stored as plaintext (base64-encoded).

    Parameters
    ----------
    input_path  : path to the original .mp3 file
    output_path : path where the stego .mp3 will be saved
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

    payload = base64.b64encode(raw_payload).decode("ascii")

    # --- Copy original file so we don't mutate the source ---------------
    shutil.copy2(input_path, output_path)

    # --- Write ID3 tag --------------------------------------------------
    try:
        tags = ID3(output_path)
    except ID3NoHeaderError:
        # MP3 has no ID3 header yet – create one
        tags = ID3()

    # Remove old stego tag if present, then add the new one
    tags.delall(f"TXXX:{TAG_DESC}")
    tags.add(TXXX(encoding=3, desc=TAG_DESC, text=[payload]))
    tags.save(output_path, v2_version=3)


# ---------------------------------------------------------------------------
# Decode (extract message from MP3)
# ---------------------------------------------------------------------------
def decode_mp3(stego_path: str, password: str = "") -> str:
    """
    Extract and decrypt the secret message from a stego MP3 file.

    Parameters
    ----------
    stego_path : path to the stego .mp3 file
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

    # --- Read ID3 tag ---------------------------------------------------
    try:
        tags = ID3(stego_path)
    except ID3NoHeaderError:
        raise ValueError("No ID3 tags found – file contains no hidden data.")

    frame_key = f"TXXX:{TAG_DESC}"
    if frame_key not in tags:
        raise ValueError("No hidden data found in this MP3 file.")

    payload = tags[frame_key].text[0]

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
