import base64
import markdown
import bleach
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

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