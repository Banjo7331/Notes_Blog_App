import base64
import io
import os
import pyotp
from datetime import datetime, timedelta
from password_strength import PasswordPolicy
from password_strength import PasswordStats
from password_strength.tests import Length, Uppercase, Numbers, Special, NonLetters
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from account.tokens import account_activation_token
from cryptography.fernet import Fernet
import qrcode


def email_verification(request, user, to_email):
    mail_subject = 'Activate your account'
    message = render_to_string('registration/activate_account.html', {
        'user': user,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user),
        'protocol': 'https' if request.is_secure() else 'http',
    })
    email = EmailMessage(mail_subject, message, to=[to_email])
    if email.send():
        return True

def generate_qr_code(user_data):
    encrypted_otp_secret = user_data['otp_secret']
    decrypted_otp_secret = decrypt_otp_secret(encrypted_otp_secret)
    otp_uri = pyotp.totp.TOTP(decrypted_otp_secret).provisioning_uri(
        name=user_data['email'],
        issuer_name="NOTES_APP"
    )

    qr = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    qr_code = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{qr_code}"

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
    """
    Szyfruje tajny klucz OTP jako dane binarne.
    """
    cipher = get_encryption_key()
    encrypted = cipher.encrypt(otp_secret.encode())  # `otp_secret.encode()` konwertuje `str` na `bytes`
    return encrypted

def decrypt_otp_secret(encrypted_secret: bytes) -> str:
    """
    Odszyfrowuje tajny klucz OTP przechowywany jako dane binarne.
    """
    cipher = get_encryption_key()
    decrypted = cipher.decrypt(encrypted_secret).decode()  # Wynik `decrypt` jest `bytes`, które konwertujemy na `str`
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
