import base64
import os
import markdown
import bleach
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from notes_keeping_site.utils import get_encryption_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.fernet import Fernet, InvalidToken
import re
from django.core.exceptions import ValidationError

def sanitize_markdown(content):
    rendered_html = markdown.markdown(content)

    allowed_tags = [
        'b','p','img','a','i','h1','h2','h3','h4','h5'
    ]
    allowed_attrs = {
        'img': ['src', 'alt'],  
        'a': ['href', 'title'],  
    }

    safe_html = bleach.clean(
        rendered_html,
        tags=allowed_tags,
        attributes=allowed_attrs,
    )

    return safe_html


def encrypt(content: str, password: str) -> str:
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=salt,
        iterations=100000, 
    )
    aes_key = kdf.derive(password.encode())
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    pad_length = 16 - (len(content) % 16)
    padded_content = content + chr(pad_length) * pad_length

    encrypted_content = encryptor.update(padded_content.encode()) + encryptor.finalize()

    cipher_server = get_encryption_key()
    encrypted_with_server_key = cipher_server.encrypt(encrypted_content)

    return base64.b64encode(salt + iv + encrypted_with_server_key).decode()

def decrypt(encrypted_data_str: str, password: str) -> str:
    try:
        encrypted_data = base64.b64decode(encrypted_data_str)

        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        encrypted_with_server_key = encrypted_data[32:]

        cipher_server = get_encryption_key()

        if not isinstance(cipher_server, Fernet):
            return "❌ Błąd w procesie - prosimy spróbowac ponownie później"

        try:
            decrypted_intermediate = cipher_server.decrypt(encrypted_with_server_key)
        except InvalidToken:
            return "❌ Błąd w procesie - prosimy spróbowac ponownie później"

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        aes_key = kdf.derive(password.encode())

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        decrypted_padded_content = decryptor.update(decrypted_intermediate) + decryptor.finalize()

        pad_length = decrypted_padded_content[-1]

        if pad_length > 16:
            return "❌ Niepoprawne hasło"

        decrypted_content = decrypted_padded_content[:-pad_length]

        return decrypted_content.decode("utf-8")

    except Exception as e:
        return "❌ Błąd w procesie - prosimy spróbowac ponownie później"

def encrypt_content(content, public_key):
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_content = cipher.encrypt(content.encode())

        return base64.b64encode(encrypted_content).decode()

def decrypt_content(content, private_key):
    try:

        encryptet_content = base64.b64decode(content)
        print("Encrypted Content:", encryptet_content)

        rsa_key = RSA.import_key(private_key)
        print("Private Key Loaded:", rsa_key)

        cipher = PKCS1_OAEP.new(rsa_key)
        decrypted_content = cipher.decrypt(encryptet_content)
        return decrypted_content.decode()
    except ValueError as e:
        print("Error Loading Key or Decrypting Content:", str(e))
    except Exception as e:
        print("Unexpected Error:", str(e))

def validate_usernames(value):
    if not re.match(r'^[a-zA-Z0-9, ]+$', value):
        raise ValidationError("Usernames must only contain letters, numbers, and commas.")
    return value

