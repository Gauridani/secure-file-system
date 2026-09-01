import os
import struct
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


MAGIC = b"SFILE01"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 600_000


def derive_key(password, salt):
    """
    Derive a 256-bit AES key from a password.
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS
    )

    return kdf.derive(password.encode("utf-8"))


def encrypt_file(input_path, output_path, password):

    with open(input_path, "rb") as f:
        data = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)

    aes = AESGCM(key)

    encrypted_data = aes.encrypt(
        nonce,
        data,
        None
    )

    original_hash = hashlib.sha256(data).digest()

    with open(output_path, "wb") as f:

        f.write(MAGIC)
        f.write(salt)
        f.write(nonce)
        f.write(original_hash)
        f.write(encrypted_data)


def decrypt_file(input_path, output_path, password):

    with open(input_path, "rb") as f:
        content = f.read()

    minimum_size = (
        len(MAGIC)
        + SALT_SIZE
        + NONCE_SIZE
        + 32
    )

    if len(content) < minimum_size:
        raise ValueError("Invalid encrypted file.")

    position = 0

    magic = content[position:position + len(MAGIC)]
    position += len(MAGIC)

    if magic != MAGIC:
        raise ValueError("Invalid SecureFile format.")

    salt = content[position:position + SALT_SIZE]
    position += SALT_SIZE

    nonce = content[position:position + NONCE_SIZE]
    position += NONCE_SIZE

    stored_hash = content[position:position + 32]
    position += 32

    encrypted_data = content[position:]

    key = derive_key(password, salt)

    aes = AESGCM(key)

    try:
        decrypted_data = aes.decrypt(
            nonce,
            encrypted_data,
            None
        )
    except Exception:
        raise ValueError(
            "Decryption failed. Wrong password or modified file."
        )

    calculated_hash = hashlib.sha256(
        decrypted_data
    ).digest()

    if calculated_hash != stored_hash:
        raise ValueError(
            "File integrity verification failed."
        )

    with open(output_path, "wb") as f:
        f.write(decrypted_data)