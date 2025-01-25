import os
from django.conf import settings
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from password_strength import PasswordPolicy
from password_strength import PasswordStats
from password_strength.tests import Length, Uppercase, Numbers, Special, NonLetters
import json
import hmac
import hashlib
import json
import base64

def get_encryption_key():
    key = os.getenv("SECRET_KEY")
    if not key:
        raise ValueError("SECRET_KEY not set in environment variables")
    try:
        decoded_key = Fernet(key.encode())
        return decoded_key
    except Exception as e:
        raise ValueError(f"Invalid SECRET_KEY: {e}")

def sign_note(user, note_content: str) -> str:
    try:
        secret_key = get_encryption_key()  

        if isinstance(secret_key, Fernet):  
            secret_key = secret_key._signing_key

        data_to_sign = json.dumps({
            "author_id": str(user.id),
            "content": note_content,
        }, separators=(",", ":"), sort_keys=True).encode()

        signature = hmac.new(secret_key, data_to_sign, hashlib.sha256).digest()

        return base64.b64encode(signature).decode() 

    except Exception as e:
        raise ValueError(f"Błąd podpisywania notatki: {e}")

def verify_signature(author, note_content: str, signature_b64: str) -> bool:
    try:
        secret_key = get_encryption_key()  

        if isinstance(secret_key, Fernet):  
            secret_key = secret_key._signing_key

        data_to_verify = json.dumps({
            "author_id": str(author.id),
            "content": note_content,
        }, separators=(",", ":"), sort_keys=True).encode()

        expected_signature = hmac.new(secret_key, data_to_verify, hashlib.sha256).digest()

        provided_signature = base64.b64decode(signature_b64)

        return hmac.compare_digest(expected_signature, provided_signature)

    except Exception:
        print("Błąd weryfikacji podpisu")
        return False


def encrypt_otp_secret(otp_secret: str) -> bytes:
    cipher = get_encryption_key()
    encrypted = cipher.encrypt(otp_secret.encode()) 
    return encrypted

def decrypt_otp_secret(encrypted_secret: bytes) -> str:
    cipher = get_encryption_key()
    decrypted = cipher.decrypt(encrypted_secret).decode()  
    return decrypted


policy = PasswordPolicy.from_names(
    length=10,  
    uppercase=1,  
    numbers=1,  
    special=1,  
    nonletters=1,  
)

def check_password_requirements(password):
    violations = policy.test(password)
    if violations:
        violation_messages = []
        for violation in violations:
            if isinstance(violation, Length):
                violation_messages.append(f"Minimum length of {violation.length} characters required.")
            if isinstance(violation, Uppercase):
                violation_messages.append(f"At least {violation.count} uppercase letter(s) required.")
            if isinstance(violation, Numbers):
                violation_messages.append(f"At least {violation.count} number(s) required.")
            if isinstance(violation, Special):
                violation_messages.append(f"At least {violation.count} special character(s) required.")
            if isinstance(violation, NonLetters):
                violation_messages.append(f"At least {violation.count} non-letter character(s) required.")

        return violation_messages  
    return []

def evaluate_password_strength(password):
    stats = PasswordStats(password)
    entropy = stats.strength()

    if entropy < 0.3:
        return "very_weak", "Very Weak"
    elif entropy < 0.5:
        return "weak", "Weak"
    elif entropy < 0.7:
        return "moderate", "Moderate"
    elif entropy < 0.9:
        return "strong", "Strong"
    else:
        return "very_strong", "Very Strong"
    