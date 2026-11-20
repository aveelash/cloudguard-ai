
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


def get_encryption_fernet():
    key = settings.AZURE_CREDENTIAL_ENCRYPTION_KEY

    if not key:
        raise RuntimeError(
            "Azure credential encryption key is not configured."
        )

    return Fernet(key.encode())


def encrypt_secret(secret: str) -> str:
    fernet = get_encryption_fernet()

    encrypted_secret = fernet.encrypt(secret.encode())

    return encrypted_secret.decode()


def decrypt_secret(encrypted_secret: str) -> str:
    fernet = get_encryption_fernet()

    try:
        decrypted_secret = fernet.decrypt(
            encrypted_secret.encode()
        )
        return decrypted_secret.decode()

    except InvalidToken:
        raise ValueError(
            "Unable to decrypt Azure credentials. "
            "Check the encryption key."
        )
