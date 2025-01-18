import base64
import markdown
import bleach
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from notes_keeping_site.utils import get_encryption_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

def sanitize_markdown(content):
    rendered_html = markdown.markdown(content)

    allowed_tags = [
        'b','img','a','i','h1','h2','h3','h4','h5','h6'
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


def encrypt(content: str, public_key_pem: str) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted_with_public_key = public_key.encrypt(
        content.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

    cipher = get_encryption_key()
    encrypted_with_server_key = cipher.encrypt(encrypted_with_public_key)

    return base64.b64encode(encrypted_with_server_key).decode()

def decrypt(encrypted_data_str: str, private_key_pem: str) -> str:
    encrypted_with_server_key = base64.b64decode(encrypted_data_str)

    cipher = get_encryption_key()
    decrypted_intermediate = cipher.decrypt(encrypted_with_server_key)

    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    decrypted_final = private_key.decrypt(
        decrypted_intermediate,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

    return decrypted_final.decode()

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