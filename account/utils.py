import base64
import io
import pyotp
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from account.tokens import account_activation_token
from  notes_keeping_site.utils import get_encryption_key
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


def encrypt_otp_secret(otp_secret: str) -> bytes:
    cipher = get_encryption_key()
    encrypted = cipher.encrypt(otp_secret.encode())  
    return encrypted

def decrypt_otp_secret(encrypted_secret: bytes) -> str:
    cipher = get_encryption_key()
    decrypted = cipher.decrypt(encrypted_secret).decode()  
    return decrypted


