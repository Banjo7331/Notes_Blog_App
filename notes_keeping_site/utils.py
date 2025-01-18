import os
from django.conf import settings
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import json


def get_private_key(user_id):
    private_key_dir = os.path.join(settings.BASE_DIR, "private_keys")
    key_file_path = os.path.join(private_key_dir, f"{user_id}_private_key.pem")

    if not os.path.exists(key_file_path):
        return None 

    with open(key_file_path, 'r') as key_file:
        return key_file.read()


def sign_note(user, note_content: str) -> str:
    try:
        private_key_pem = get_private_key(user.id)  

        data_to_sign = json.dumps({
            "author_id": user.id,
            "content": note_content,
        }, separators=(",", ":"), sort_keys=True)

        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)

        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key = RSA.import_key(private_key_bytes) 

        hash_obj = SHA256.new(data_to_sign.encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(hash_obj)

        return signature.hex()

    except Exception as e:
        raise ValueError(f"Błąd podpisywania notatki: {e}")  

def verify_signature(author, note_content: str, signature_hex: str) -> bool:
    try:
        public_key_pem = author.public_key 
        author_id = author.id 

        data_to_verify = json.dumps({
            "author_id": author_id,
            "content": note_content,
        }, separators=(",", ":"), sort_keys=True)

        public_key = RSA.import_key(public_key_pem)
        hash_obj = SHA256.new(data_to_verify.encode('utf-8'))
        signature = bytes.fromhex(signature_hex)

        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True  

    except (ValueError, TypeError):
        return False  

def get_encryption_key():
    key = os.getenv("OTP_ENCRYPTION_KEY")
    print(f"Using OTP_ENCRYPTION_KEY: {key}")
    if not key:
        raise ValueError("OTP_ENCRYPTION_KEY not set in environment variables")
    try:
        decoded_key = Fernet(key.encode())
        return decoded_key
    except Exception as e:
        raise ValueError(f"Invalid OTP_ENCRYPTION_KEY: {e}")

def encrypt_otp_secret(otp_secret: str) -> bytes:
    cipher = get_encryption_key()
    encrypted = cipher.encrypt(otp_secret.encode()) 
    return encrypted

def decrypt_otp_secret(encrypted_secret: bytes) -> str:
    cipher = get_encryption_key()
    decrypted = cipher.decrypt(encrypted_secret).decode()  
    return decrypted

def generate_rsa_key_pair_for_user(user):
    private_key_dir = os.path.join(settings.BASE_DIR, "private_keys")
    
    if not os.path.exists(private_key_dir):
        os.makedirs(private_key_dir, exist_ok=True)
        os.chmod(private_key_dir, 0o700)  
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    public_key = private_key.public_key()
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  
    )
    
    private_key_file_path = os.path.join(private_key_dir, f"{user.id}_private_key.pem")
    
    with open(private_key_file_path, 'wb') as private_file:
        private_file.write(private_key_pem)
    
    user.public_key = public_key_pem.decode("utf-8")
    user.save()
    